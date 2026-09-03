//! Common functionality for Rugix's various CLIs.

use std::fmt;
use std::io;
use std::ops::Deref;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::Weak;
use std::time::Duration;
use std::time::Instant;

use console::Term;
use rugix_tasks::is_canceled_payload;
use rugix_tasks::spawn_blocking;
use style::Style;
use style::Styled;
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

use crate::rate_limiter::RateLimiter;

pub mod json;
pub mod progress;
pub mod style;
pub mod widgets;

mod rate_limiter;

/// Helper for initializing the CLI.
#[derive(Debug)]
pub struct CliBuilder {
    /// Init [`tracing`] by registering a subscriber.
    init_tracing: bool,
    /// Maximum verbosity accepted by the tracing subscriber.
    max_log_level: Option<LevelFilter>,
    /// Start a background thread redrawing the status area periodically.
    start_drawing_thread: bool,
    /// Period for redrawing the status area.
    drawing_period: Duration,
}

impl CliBuilder {
    /// Create a new [`Initializer`] with default settings.
    pub fn new() -> Self {
        Self {
            init_tracing: true,
            max_log_level: None,
            start_drawing_thread: true,
            drawing_period: Duration::from_millis(100),
        }
    }

    /// Limit the maximum verbosity accepted by the tracing subscriber.
    pub fn with_max_log_level(&mut self, level: LevelFilter) -> &mut Self {
        self.max_log_level = Some(level);
        self
    }

    /// Initialize the CLI.
    pub fn init(self) {
        if self.init_tracing {
            let format = tracing_subscriber::fmt::format()
                .without_time()
                .with_target(false)
                .compact();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(StderrWriter::new())
                .with_ansi(Term::stderr().is_term())
                .event_format(format)
                .with_env_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .with_env_var("RUGIX_LOG")
                        .from_env_lossy(),
                );
            if let Some(level) = self.max_log_level {
                subscriber.with_max_level(level).init();
            } else {
                subscriber.init();
            }
        }
        if self.start_drawing_thread {
            std::thread::spawn(move || loop {
                std::thread::sleep(self.drawing_period);
                redraw();
            });
        }
    }

    pub fn run<F, E>(self, closure: F) -> !
    where
        F: 'static + Send + FnOnce() -> Result<(), E>,
        E: Send + fmt::Debug,
    {
        self.init();

        #[derive(Debug)]
        enum TerminationReason {
            Success,
            Failed,
            Panicked,
            Cancelled,
        }

        let (main_tx, main_rx) = flume::bounded(5);

        let mut main_task = Some(spawn_blocking(move || {
            match std::panic::catch_unwind(AssertUnwindSafe(closure)) {
                Ok(Ok(_)) => {
                    main_tx.send(TerminationReason::Success).ok();
                }
                Ok(Err(error)) => {
                    cli_msg!("Error: {error:?}");
                    main_tx.send(TerminationReason::Failed).ok();
                }
                Err(payload) => {
                    if is_canceled_payload(&payload) {
                        main_tx.send(TerminationReason::Cancelled).ok();
                        return;
                    }
                    if let Some(msg) = payload.downcast_ref::<&str>() {
                        cli_msg!("Panic: {msg}");
                    } else if let Some(msg) = payload.downcast_ref::<String>() {
                        cli_msg!("Panic: {msg}");
                    } else {
                        cli_msg!("Panic!");
                    }
                    main_tx.send(TerminationReason::Panicked).ok();
                }
            }
        }));

        ctrlc::set_handler(move || {
            // Will abort the task by dropping it.
            if main_task.take().is_some() {
                info!("Shutting down...");
            }
        })
        .unwrap();

        let Ok(reason) = main_rx.recv() else {
            panic!("main task terminated without sending a termination reason");
        };
        rugix_tasks::shutdown_blocking();
        hide_status();
        force_redraw();
        if matches!(reason, TerminationReason::Success) {
            std::process::exit(0)
        } else {
            std::process::exit(1)
        }
    }
}

/// Global terminal reference.
static TERMINAL: LazyLock<TerminalRef> = LazyLock::new(|| TerminalRef {
    shared: Arc::new(TerminalShared {
        term: Term::stderr(),
        reference_instant: Instant::now(),
        state: Mutex::default(),
        status_segments: Mutex::default(),
        rate_limiter: RateLimiter::new(Duration::from_millis(20)),
    }),
});

/// Add a status segment.
pub fn add_status<S: 'static + StatusSegment + Send + Sync>(segment: S) -> StatusSegmentRef<S> {
    TERMINAL.add_status(segment)
}

/// Redraw the terminal screen.
pub fn redraw() {
    TERMINAL.redraw();
}

/// Force redraw the terminal screen.
///
/// This function bypasses the builtin rate limiter.
pub fn force_redraw() {
    TERMINAL.force_redraw();
}

/// Check whether the terminal is attended by a user.
pub fn is_attended() -> bool {
    TERMINAL.is_attended()
}

/// Check whether `stdout` is piped into another program.
pub fn stdout_is_piped() -> bool {
    !Term::stdout().features().is_attended()
}

/// Check whether the terminal supports unicode.
pub fn supports_unicode() -> bool {
    TERMINAL.supports_unicode()
}

/// Check whether the terminal supports colors.
pub fn supports_colors() -> bool {
    TERMINAL.supports_colors()
}

/// Hide the status area.
pub fn hide_status() {
    TERMINAL.hide_status();
}

/// Show the status area.
pub fn show_status() {
    TERMINAL.show_status();
}

/// Temporarily hide the status area and any interactive elements.
pub fn suspend<F: FnOnce() -> T, T>(closure: F) -> T {
    TERMINAL.suspend_status(closure)
}

/// Same as [`eprintln`] but suspends the status area and any interactive elements.
#[macro_export]
macro_rules! cli_msg {
    ($($args:tt)*) => {
        $crate::suspend(|| {
            eprintln!($($args)*);
        })
    };
}

/// Same as [`dbg`] but suspends the status area and any interactive elements.
#[macro_export]
macro_rules! cli_dbg {
    ($($args:tt)*) => {
        $crate::suspend(|| {
            dbg!($($args)*)
        })
    };
}

/// Shared terminal reference.
#[derive(Debug, Clone)]
struct TerminalRef {
    shared: Arc<TerminalShared>,
}

/// Shared terminal data.
#[derive(Debug)]
struct TerminalShared {
    term: Term,
    state: Mutex<TerminalState>,
    reference_instant: Instant,
    status_segments: Mutex<Vec<StatusSegmentData>>,
    rate_limiter: RateLimiter,
}

/// Shared terminal state.
#[derive(Debug, Default)]
struct TerminalState {
    status_hidden: bool,
    buffer: String,
    buffer_lines: VisualHeight,
    visible_lines: VisualHeight,
}

impl TerminalRef {
    /// Check whether the terminal is attended by a user.
    pub fn is_attended(&self) -> bool {
        self.shared.term.features().is_attended()
    }

    /// Check whether the terminal supports unicode.
    pub fn supports_unicode(&self) -> bool {
        true
    }

    /// Check whether the terminal supports colors.
    pub fn supports_colors(&self) -> bool {
        self.shared.term.features().colors_supported()
    }

    /// Add a status segment to the terminal output.
    pub fn add_status<S: 'static + StatusSegment + Send + Sync>(
        &self,
        segment: S,
    ) -> StatusSegmentRef<S> {
        let segment = StatusSegmentRef::new(segment);
        let data = StatusSegmentData {
            buffer: String::new(),
            segment: StatusSegmentRef::weak_ref(&segment),
        };
        self.shared.status_segments.lock().unwrap().push(data);
        self.redraw();
        segment
    }

    /// Redraw everything.
    pub fn redraw(&self) {
        let _ = self.shared.rate_limiter.rate_limited(|| {
            self.force_redraw();
        });
    }

    /// Force-redraw everything.
    pub fn force_redraw(&self) {
        self.redraw_with_state(&mut self.shared.state.lock().unwrap());
    }

    /// Hide the status area.
    pub fn hide_status(&self) {
        let mut state = self.shared.state.lock().unwrap();
        self.clear_with_state(&mut state);
        state.status_hidden = true;
    }

    /// Show the status area.
    pub fn show_status(&self) {
        let mut state = self.shared.state.lock().unwrap();
        state.status_hidden = false;
        self.show_with_state(&mut state);
    }

    /// Clear status area and any interactive elements.
    fn clear_with_state(&self, state: &mut TerminalState) {
        let _ = self.shared.term.clear_line();
        if state.visible_lines > 1 {
            let lines = state.visible_lines - 1;
            let _ = self.shared.term.clear_last_lines(lines.into_u64() as usize);
        }
        state.visible_lines = VisualHeight::ZERO;
    }

    /// Redraw status area and any interactive elements.
    fn redraw_with_state(&self, state: &mut TerminalState) {
        if !self.is_attended() {
            // Only draw the status segments if the terminal is attended.
            return;
        }

        let (available_height, available_width) = self.shared.term.size();
        let mut available_height = VisualHeight(u64::from(available_height));
        let available_width = VisualWidth(u64::from(available_width));

        let time = self.shared.reference_instant.elapsed();

        state.buffer.clear();
        state.buffer_lines = VisualHeight::ZERO;

        let mut global_ctx = DrawCtx {
            buffer: &mut state.buffer,
            time,
            available_width,
            available_height,
            _wie: self.supports_unicode(),
            supports_colors: self.supports_colors(),
            current_style: Style::new(),
        };

        self.shared
            .status_segments
            .lock()
            .unwrap()
            .retain_mut(|data| {
                let Some(segment) = data.segment.upgrade() else {
                    return false;
                };
                data.buffer.clear();
                let mut ctx = DrawCtx {
                    buffer: &mut data.buffer,
                    time,
                    available_width,
                    available_height,
                    _wie: global_ctx._wie,
                    supports_colors: global_ctx.supports_colors,
                    current_style: Style::new(),
                };
                segment.draw(&mut ctx);
                let used_height = ctx.measure_used_height();
                if used_height <= available_height {
                    global_ctx.start_line();
                    global_ctx.write_str(&data.buffer);
                    if global_ctx.supports_colors {
                        global_ctx.reset_style();
                    }
                    available_height -= used_height;
                }
                true
            });
        state.buffer_lines = global_ctx.measure_used_height();
        self.show_with_state(state);
    }

    /// Show the status area.
    pub fn show_with_state(&self, state: &mut TerminalState) {
        if !state.status_hidden {
            self.clear_with_state(state);
            let _ = self.shared.term.write_str(&state.buffer);
            let _ = self.shared.term.flush();
            state.visible_lines = state.buffer_lines;
        }
    }

    /// Temporarily hide the status area and any interactive elements.
    pub fn suspend_status<F: FnOnce() -> U, U>(&self, closure: F) -> U {
        let mut state = self.shared.state.lock().unwrap();
        self.clear_with_state(&mut state);
        let output = closure();
        self.show_with_state(&mut state);
        output
    }
}

#[derive(Debug)]
struct StatusSegmentData {
    buffer: String,
    segment: Weak<dyn StatusSegment + Send + Sync>,
}

/// Smart pointer to a status segment.
///
/// Dropping this reference will remove the segment from the status.
pub struct StatusSegmentRef<S> {
    shared: Arc<S>,
}

impl<S> StatusSegmentRef<S> {
    /// Create a new segment reference.
    fn new(segment: S) -> Self {
        Self {
            shared: Arc::new(segment),
        }
    }
}

impl<S: 'static + StatusSegment + Send + Sync> StatusSegmentRef<S> {
    /// Create a weak reference to the status segment.
    fn weak_ref(this: &Self) -> Weak<dyn StatusSegment + Send + Sync> {
        Arc::downgrade(&this.shared) as Weak<_>
    }
}

impl<S> Clone for StatusSegmentRef<S> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<S> Deref for StatusSegmentRef<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.shared
    }
}

impl<S: fmt::Debug> fmt::Debug for StatusSegmentRef<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StatusSegmentRef")
            .field(&self.shared)
            .finish()
    }
}

/// Segment that can be drawn to the status area.
pub trait StatusSegment: 'static {
    /// Draw the status segment into the provided drawing context.
    fn draw(&self, ctx: &mut DrawCtx);
}

impl fmt::Debug for dyn StatusSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Drawable").finish_non_exhaustive()
    }
}

impl StatusSegment for &'static str {
    fn draw(&self, ctx: &mut DrawCtx) {
        ctx.write_str(self);
    }
}

impl StatusSegment for String {
    fn draw(&self, ctx: &mut DrawCtx) {
        ctx.write_str(self)
    }
}

impl<S: StatusSegment> StatusSegment for Styled<S> {
    fn draw(&self, ctx: &mut DrawCtx) {
        ctx.with_style(self.style, |ctx| self.value.draw(ctx))
    }
}

macro_rules! impl_dimension_traits {
    ($type:ty) => {
        impl From<u64> for $type {
            fn from(value: u64) -> Self {
                Self(value)
            }
        }

        impl From<$type> for u64 {
            fn from(value: $type) -> Self {
                value.0
            }
        }

        impl std::ops::Add for $type {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                Self(self.0.saturating_add(rhs.0))
            }
        }

        impl std::ops::AddAssign for $type {
            fn add_assign(&mut self, rhs: Self) {
                self.0 = self.0.saturating_add(rhs.0)
            }
        }

        impl std::ops::Sub for $type {
            type Output = Self;

            fn sub(self, rhs: Self) -> Self::Output {
                Self(self.0.saturating_sub(rhs.0))
            }
        }

        impl std::ops::SubAssign for $type {
            fn sub_assign(&mut self, rhs: Self) {
                self.0 = self.0.saturating_sub(rhs.0);
            }
        }

        impl std::ops::Rem for $type {
            type Output = $type;

            fn rem(self, rhs: Self) -> Self::Output {
                Self(self.0 % rhs.0)
            }
        }

        impl std::ops::RemAssign for $type {
            fn rem_assign(&mut self, rhs: Self) {
                self.0 %= rhs.0;
            }
        }

        impl std::ops::Div for $type {
            type Output = $type;

            fn div(self, rhs: Self) -> Self::Output {
                Self(self.0 / rhs.0)
            }
        }

        impl std::ops::DivAssign for $type {
            fn div_assign(&mut self, rhs: Self) {
                self.0 /= rhs.0;
            }
        }

        impl std::ops::Div<u64> for $type {
            type Output = $type;

            fn div(self, rhs: u64) -> Self::Output {
                Self(self.0 / rhs)
            }
        }

        impl std::ops::DivAssign<u64> for $type {
            fn div_assign(&mut self, rhs: u64) {
                self.0 /= rhs;
            }
        }

        impl std::ops::Mul<u64> for $type {
            type Output = $type;

            fn mul(self, rhs: u64) -> Self::Output {
                Self(self.0 * rhs)
            }
        }

        impl std::ops::MulAssign<u64> for $type {
            fn mul_assign(&mut self, rhs: u64) {
                self.0 *= rhs;
            }
        }

        impl std::ops::Sub<u64> for $type {
            type Output = $type;

            fn sub(self, rhs: u64) -> Self::Output {
                Self(self.0.saturating_sub(rhs))
            }
        }

        impl std::ops::SubAssign<u64> for $type {
            fn sub_assign(&mut self, rhs: u64) {
                self.0 = self.0.saturating_sub(rhs);
            }
        }

        impl std::ops::Add<u64> for $type {
            type Output = $type;

            fn add(self, rhs: u64) -> Self::Output {
                Self(self.0 + rhs)
            }
        }

        impl std::ops::AddAssign<u64> for $type {
            fn add_assign(&mut self, rhs: u64) {
                self.0 += rhs;
            }
        }

        impl PartialEq<u64> for $type {
            fn eq(&self, other: &u64) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<$type> for u64 {
            fn eq(&self, other: &$type) -> bool {
                *self == other.0
            }
        }

        impl PartialOrd<u64> for $type {
            fn partial_cmp(&self, other: &u64) -> Option<std::cmp::Ordering> {
                self.0.partial_cmp(other)
            }
        }

        impl PartialOrd<$type> for u64 {
            fn partial_cmp(&self, other: &$type) -> Option<std::cmp::Ordering> {
                self.partial_cmp(&other.0)
            }
        }
    };
}

/// _Visual height_, i.e., number of lines on a terminal screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VisualHeight(pub u64);

impl VisualHeight {
    /// Visual height of zero.
    pub const ZERO: Self = Self(0);
    /// Visual height of one.
    pub const ONE: Self = Self(1);

    /// Converts the height into [`u64`].
    pub fn into_u64(self) -> u64 {
        self.0
    }

    /// Converts a [`usize`] hight into [`VisualHeight`].
    ///
    /// Panics if the height does not fit into [`u64`].
    pub fn from_usize(height: usize) -> Self {
        Self(u64::try_from(height).expect("visual height must fit into `u64`"))
    }

    /// Check whether the height is zero.
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Measure the height of a string when displayed on a terminal with the given width.
    ///
    /// This function takes line wrapping into account.
    pub fn measure(s: &str, width: VisualWidth) -> Self {
        let mut height = 0;
        for line in s.split('\n') {
            height += ((VisualWidth::measure(line) - 1) / width).into_u64();
            height += 1;
        }
        Self(height)
    }
}

impl_dimension_traits!(VisualHeight);

/// _Visual width_, i.e., number of characters on a terminal screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VisualWidth(pub u64);

impl VisualWidth {
    /// Visual width of zero.
    pub const ZERO: Self = Self(0);
    /// Visual width of one.
    pub const ONE: Self = Self(1);

    /// Converts the width into [`u64`].
    pub fn into_u64(self) -> u64 {
        self.0
    }

    /// Converts a [`usize`] hight into [`VisualWidth`].
    ///
    /// Panics if the width does not fit into [`u64`].
    pub fn from_usize(width: usize) -> Self {
        Self(u64::try_from(width).expect("visual width must fit into `u64`"))
    }

    /// Check whether the width is zero.
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Iterator over the columns.
    pub fn iter(self) -> impl Iterator<Item = VisualWidth> {
        (0..self.0).map(VisualWidth)
    }

    /// Measure the width of a string when displayed on a terminal screen.
    pub fn measure(s: &str) -> Self {
        Self(
            u64::try_from(console::measure_text_width(s))
                .expect("visual width must not overflow `u64`"),
        )
    }

    /// Measure the width of the last line of a string when displayed on a terminal
    /// screen.
    pub fn measure_last_line(s: &str, line_width: VisualWidth) -> VisualWidth {
        if let Some(last_line) = s.split('\n').next_back() {
            VisualWidth::measure(last_line) % line_width
        } else {
            VisualWidth::ZERO
        }
    }
}

impl_dimension_traits!(VisualWidth);

/// Writer for writing to the standard error output.
pub struct StderrWriter(());

impl StderrWriter {
    /// Create a new writer for stderr.
    pub fn new() -> Self {
        Self(())
    }
}

impl io::Write for StderrWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        TERMINAL.suspend_status(|| io::stderr().write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

impl<'writer> MakeWriter<'writer> for StderrWriter {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        StderrWriter::new()
    }
}

/// Context for drawing on the terminal screen.
#[derive(Debug)]
pub struct DrawCtx<'ctx> {
    buffer: &'ctx mut String,
    time: Duration,
    available_width: VisualWidth,
    available_height: VisualHeight,
    _wie: bool,
    supports_colors: bool,
    current_style: Style,
}

impl DrawCtx<'_> {
    /// Current content of the buffer.
    #[inline(always)]
    pub fn buffer(&self) -> &str {
        self.buffer
    }

    /// [`Duration`] for consistent rendering of animations.
    #[inline(always)]
    pub fn time(&self) -> Duration {
        self.time
    }

    /// Lines of the buffer.
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.buffer().split('\n')
    }

    /// Check whether the terminal supports unicode.
    #[inline(always)]
    pub fn supports_unicode(&self) -> bool {
        self._wie
    }

    /// Check whether the terminal supports colors.
    #[inline(always)]
    pub fn supports_colors(&self) -> bool {
        self.supports_colors
    }

    /// Available terminal width to draw to.
    #[inline(always)]
    pub fn available_width(&self) -> VisualWidth {
        self.available_width
    }

    /// Available terminal height to draw to.
    #[inline(always)]
    pub fn available_height(&self) -> VisualHeight {
        self.available_height
    }

    /// Current style.
    #[inline(always)]
    pub fn current_style(&self) -> Style {
        self.current_style
    }

    /// Measure the used height.
    pub fn measure_used_height(&self) -> VisualHeight {
        VisualHeight::measure(self.buffer(), self.available_width)
    }

    /// Measure the used width.
    pub fn measure_used_width(&self) -> VisualWidth {
        self.lines()
            .map(VisualWidth::measure)
            .max()
            .unwrap_or_default()
    }

    /// Measure the width used by the current line.
    pub fn measure_current_line_width(&self) -> VisualWidth {
        if self.buffer.is_empty() {
            VisualWidth::ZERO
        } else {
            VisualWidth::measure_last_line(self.buffer, self.available_width)
        }
    }

    /// Measure the remaining width on the current line.
    pub fn measure_remaining_width(&self) -> VisualWidth {
        self.available_width - self.measure_current_line_width()
    }

    /// Measure the remaining height.
    pub fn measure_remaining_height(&self) -> VisualHeight {
        self.available_height - self.measure_used_height()
    }

    /// Start a new line.
    pub fn start_line(&mut self) {
        if self.measure_remaining_width() != self.available_width {
            self.write_char('\n');
        }
    }

    /// Fill the current line with spaces.
    #[inline(always)]
    pub fn fill_line(&mut self) {
        self.write_spaces(self.measure_remaining_width());
    }

    /// Write a character.
    #[inline(always)]
    pub fn write_char(&mut self, c: char) {
        self.buffer.push(c);
    }

    /// Write a character repeatedly for the given width.
    #[inline(always)]
    pub fn write_repeated(&mut self, c: char, width: VisualWidth) {
        for _ in width.iter() {
            self.write_char(c);
        }
    }

    /// Write a given number of spaces
    #[inline(always)]
    pub fn write_spaces(&mut self, width: VisualWidth) {
        self.write_repeated(' ', width);
    }

    /// Write a string.
    #[inline(always)]
    pub fn write_str(&mut self, s: &str) {
        for c in s.chars() {
            self.write_char(c);
        }
    }

    /// Write format arguments to the context.
    pub fn write_fmt(&mut self, args: fmt::Arguments<'_>) {
        // We ignore the result as writing cannot fail.
        let _ = fmt::Write::write_fmt(self, args);
    }

    /// Apply the style to everything written inside of the closure.
    pub fn with_style<F, R>(&mut self, style: Style, closure: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        let previous_style = self.current_style;
        self.apply_style(style);
        let return_value = closure(self);
        self.set_style(previous_style);
        return_value
    }

    /// Apply an optional style to everything written inside the closure.
    pub fn with_optional_style<F, R>(&mut self, style: Option<Style>, closure: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        if let Some(style) = style {
            self.with_style(style, closure)
        } else {
            closure(self)
        }
    }

    /// Apply the given style.
    pub fn apply_style(&mut self, style: Style) {
        if self.supports_colors {
            let _ = style.write_to(&mut self.buffer);
        }
        self.current_style = self.current_style.combine(style);
    }

    /// Set the given style.
    pub fn set_style(&mut self, style: Style) {
        if self.supports_colors {
            self.buffer.push_str(style::RESET_ALL);
            let _ = style.write_to(&mut self.buffer);
        }
        self.current_style = style;
    }

    /// Reset the current style.
    pub fn reset_style(&mut self) {
        if self.supports_colors {
            self.buffer.push_str(style::RESET_ALL);
        }
        self.current_style = Style::new();
    }
}

impl fmt::Write for DrawCtx<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        DrawCtx::write_str(self, s);
        Ok(())
    }

    fn write_char(&mut self, c: char) -> fmt::Result {
        DrawCtx::write_char(self, c);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::VisualHeight;
    use crate::VisualWidth;

    #[test]
    fn test_measure_visual_height() {
        assert_eq!(VisualHeight::measure("", VisualWidth(5)), VisualHeight(1));
        assert_eq!(
            VisualHeight::measure("xxxxx", VisualWidth(5)),
            VisualHeight(1)
        );
        assert_eq!(
            VisualHeight::measure("xxxxxx", VisualWidth(5)),
            VisualHeight(2)
        );
        assert_eq!(
            VisualHeight::measure("\n\n", VisualWidth(5)),
            VisualHeight(3)
        );
        assert_eq!(
            VisualHeight::measure("\nxxxxxx\nxxxxx\n", VisualWidth(5)),
            VisualHeight(5)
        );
    }
}
