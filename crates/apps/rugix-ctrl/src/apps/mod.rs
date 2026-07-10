pub mod config;
pub mod manager;
pub mod orchestrators;
pub mod systemd;

use reportify::Report;

reportify::new_whatever_type! {
    pub AppsError
}

pub type AppsResult<T> = Result<T, Report<AppsError>>;
