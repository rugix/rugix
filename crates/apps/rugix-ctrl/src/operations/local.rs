//! Local execution dependencies and dispatch.

use reportify::ResultExt;

use super::EventSink;
use super::Executor;
use super::Operation;
use crate::apps::config::load_apps_config;
use crate::apps::manager::AppManager;
use crate::config::config::Config;
use crate::system::SystemResult;

/// Dependencies available to host-side operation implementations.
pub struct ExecutionContext<'a> {
    config: &'a Config,
    app_manager: Option<&'a AppManager>,
}

impl ExecutionContext<'_> {
    /// Access the loaded Rugix Ctrl configuration.
    pub(crate) fn config(&self) -> &Config {
        self.config
    }

    /// Execute a function with the supplied or lazily loaded application manager.
    pub(crate) fn with_app_manager<T>(
        &self,
        operation: impl FnOnce(&AppManager) -> SystemResult<T>,
    ) -> SystemResult<T> {
        match self.app_manager {
            Some(app_manager) => operation(app_manager),
            None => {
                let app_manager = load_app_manager()?;
                operation(&app_manager)
            }
        }
    }
}

/// Executes operations directly on the host.
///
/// This executor assumes that its caller has already authorized the request. A daemon
/// must enforce its admission policy, including restrictions on insecure install options,
/// before invoking it. The privileged CLI intentionally executes requests without that
/// daemon policy.
pub struct LocalExecutor<'a> {
    context: ExecutionContext<'a>,
}

impl<'a> LocalExecutor<'a> {
    /// Create a local executor using the loaded Rugix Ctrl configuration.
    pub fn new(config: &'a Config) -> Self {
        Self {
            context: ExecutionContext {
                config,
                app_manager: None,
            },
        }
    }

    /// Reuse an application manager whose lifecycle is scoped by the caller.
    pub fn with_app_manager(mut self, app_manager: &'a AppManager) -> Self {
        self.context.app_manager = Some(app_manager);
        self
    }
}

impl Executor for LocalExecutor<'_> {
    fn execute<O: Operation>(
        &self,
        operation: O,
        input: O::Input,
        events: &mut dyn EventSink<O::Event>,
    ) -> SystemResult<O::Output> {
        operation.execute(&self.context, input, events)
    }
}

fn load_app_manager() -> SystemResult<AppManager> {
    let config = load_apps_config().whatever("unable to load apps config")?;
    Ok(AppManager::new(
        crate::apps::config::apps_dir().to_owned(),
        config,
    ))
}
