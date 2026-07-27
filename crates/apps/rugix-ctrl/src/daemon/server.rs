//! Unix socket server for privileged operation execution.

use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;

use reportify::bail;
use reportify::Report;
use reportify::ResultExt;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::config::DaemonSettings;
use super::policy::AdmissionPolicy;
use super::protocol::read_request;
use super::protocol::write_error;
use super::protocol::write_event;
use super::protocol::write_output;
use super::protocol::ErrorKind;
use super::protocol::Request;
use crate::config::config::Config;
use crate::config::load_ctrl_config;
use crate::operations::install::BundleInput;
use crate::operations::install::InstallSource;
use crate::operations::local::LocalExecutor;
use crate::operations::EventSink;
use crate::operations::Executor;
use crate::operations::Operation;
use crate::system::SystemError;
use crate::system::SystemResult;

pub(crate) fn serve(settings: DaemonSettings) -> SystemResult<()> {
    prepare_socket(&settings.socket_path)?;
    let listener = UnixListener::bind(&settings.socket_path)
        .whatever("unable to bind daemon socket")
        .field("socket", settings.socket_path.clone())?;
    fs::set_permissions(&settings.socket_path, fs::Permissions::from_mode(0o660))
        .whatever("unable to set daemon socket permissions")
        .field("socket", settings.socket_path.clone())?;
    let _socket_guard = SocketGuard::new(settings.socket_path.clone());
    let config = Arc::new(load_ctrl_config()?);
    let policy = AdmissionPolicy::new(&settings);
    info!(socket = %settings.socket_path.display(), "Rugix Ctrl daemon listening");

    loop {
        let (socket, _) = listener
            .accept()
            .whatever("unable to accept daemon connection")?;
        let config = config.clone();
        let policy = policy.clone();
        let max_control_frame_size = settings.max_control_frame_size;
        rugix_tasks::spawn_blocking(move || {
            if let Err(error) = handle_connection(socket, &config, &policy, max_control_frame_size)
            {
                warn!(error = ?error, "daemon connection failed");
            }
        })
        .detach();
    }
}

fn handle_connection(
    mut socket: UnixStream,
    config: &Config,
    policy: &AdmissionPolicy,
    max_control_frame_size: usize,
) -> SystemResult<()> {
    let request = match read_request(&mut socket, max_control_frame_size) {
        Ok(request) => request,
        Err(error) => {
            let message = format!("{error:?}");
            if let Err(write_error) = write_error(&mut socket, ErrorKind::Protocol, message) {
                warn!(error = ?write_error, "unable to report daemon protocol error");
            }
            return Err(error);
        }
    };
    if let Err(error) = policy.authorize(&request) {
        write_error(&mut socket, ErrorKind::Operation, format!("{error:?}"))?;
        return Ok(());
    }
    dispatch(request, socket, config)
}

fn dispatch(request: Request, mut socket: UnixStream, config: &Config) -> SystemResult<()> {
    let executor = LocalExecutor::new(config);
    match request {
        Request::InstallBundle(operation) => {
            let input = match &operation.source {
                InstallSource::Stream => BundleInput::Stream(Box::new(
                    socket
                        .try_clone()
                        .whatever("unable to prepare daemon bundle input")?,
                )),
                InstallSource::Http { .. } => BundleInput::None,
            };
            execute_operation(&executor, operation, input, &mut socket)
        }
        Request::QuerySystem(operation) => execute_operation(&executor, operation, (), &mut socket),
        Request::CheckComponents(operation) => {
            execute_operation(&executor, operation, (), &mut socket)
        }
        Request::ListApps(operation) => execute_operation(&executor, operation, (), &mut socket),
        Request::QueryApp(operation) => execute_operation(&executor, operation, (), &mut socket),
        Request::FactoryReset(operation) => {
            execute_operation(&executor, operation, (), &mut socket)
        }
        Request::CommitSystem(operation) => {
            execute_operation(&executor, operation, (), &mut socket)
        }
        Request::RebootSystem(operation) => {
            execute_operation(&executor, operation, (), &mut socket)
        }
        Request::ActivateApp(operation) => execute_operation(&executor, operation, (), &mut socket),
        Request::DeactivateApp(operation) => {
            execute_operation(&executor, operation, (), &mut socket)
        }
        Request::StartApp(operation) => execute_operation(&executor, operation, (), &mut socket),
        Request::StopApp(operation) => execute_operation(&executor, operation, (), &mut socket),
        Request::RollbackApp(operation) => execute_operation(&executor, operation, (), &mut socket),
        Request::RemoveApp(operation) => execute_operation(&executor, operation, (), &mut socket),
        Request::GarbageCollectApps(operation) => {
            execute_operation(&executor, operation, (), &mut socket)
        }
    }
}

fn execute_operation<O: Operation>(
    executor: &LocalExecutor<'_>,
    operation: O,
    input: O::Input,
    socket: &mut UnixStream,
) -> SystemResult<()> {
    let mut events = SocketEventSink::new(socket);
    let result = executor.execute(operation, input, &mut events);
    events.finish()?;
    match result {
        Ok(output) => write_output(socket, &output),
        Err(error) => {
            error!(error = ?error, "daemon operation failed");
            write_error(socket, ErrorKind::Operation, format!("{error:?}"))
        }
    }
}

fn prepare_socket(socket_path: &Path) -> SystemResult<()> {
    let parent = socket_path
        .parent()
        .ok_or_else(|| reportify::whatever!("daemon socket path has no parent directory"))?;
    fs::create_dir_all(parent)
        .whatever("unable to create daemon socket directory")
        .field("path", parent.to_owned())?;
    let metadata = match fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .whatever("unable to inspect daemon socket path")
                .field("socket", socket_path.to_owned());
        }
    };
    if !metadata.file_type().is_socket() {
        bail!(
            "refusing to replace non-socket daemon path {}",
            socket_path.display()
        );
    }
    match UnixStream::connect(socket_path) {
        Ok(_) => bail!("daemon socket {} is already in use", socket_path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            fs::remove_file(socket_path)
                .whatever("unable to remove stale daemon socket")
                .field("socket", socket_path.to_owned())
        }
        Err(error) => Err(error)
            .whatever("unable to check existing daemon socket")
            .field("socket", socket_path.to_owned()),
    }
}

struct SocketEventSink<'a> {
    socket: &'a mut UnixStream,
    error: Option<Report<SystemError>>,
}

impl<'a> SocketEventSink<'a> {
    fn new(socket: &'a mut UnixStream) -> Self {
        Self {
            socket,
            error: None,
        }
    }

    fn finish(self) -> SystemResult<()> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl<E: serde::Serialize> EventSink<E> for SocketEventSink<'_> {
    fn emit(&mut self, event: E) {
        if self.error.is_none() {
            self.error = write_event(self.socket, &event).err();
        }
    }
}

struct SocketGuard {
    path: std::path::PathBuf,
}

impl SocketGuard {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                warn!(path = %self.path.display(), %error, "unable to remove daemon socket");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    use indexmap::IndexMap;

    use super::handle_connection;
    use crate::config::config::Config;
    use crate::config::output::AppListEntryOutput;
    use crate::daemon::config::DaemonFeatureSettings;
    use crate::daemon::config::DaemonSettings;
    use crate::daemon::policy::AdmissionPolicy;
    use crate::daemon::protocol::decode_response;
    use crate::daemon::protocol::read_response;
    use crate::daemon::protocol::write_request;
    use crate::daemon::protocol::Request;
    use crate::daemon::protocol::Response;
    use crate::operations::apps::ListApps;

    #[test]
    fn typed_query_round_trips_through_daemon_dispatch_and_local_execution() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let settings = DaemonSettings {
            socket_path: PathBuf::from("/tmp/rugix-test.sock"),
            max_control_frame_size: 1024 * 1024,
            dangerously_insecure: false,
            features: DaemonFeatureSettings::default(),
        };
        let policy = AdmissionPolicy::new(&settings);
        let config = Config::default();

        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                handle_connection(server, &config, &policy, settings.max_control_frame_size)
                    .unwrap();
            });
            write_request(&mut client, Request::ListApps(ListApps)).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let Response::Output(payload) =
                read_response(&mut client, settings.max_control_frame_size).unwrap()
            else {
                panic!("expected daemon output");
            };
            let _: IndexMap<String, AppListEntryOutput> =
                decode_response(&payload, "unable to decode app list").unwrap();
            server.join().unwrap();
        });
    }
}
