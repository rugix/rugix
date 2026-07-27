//! Typed client for the privileged operation daemon.

use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use reportify::bail;
use reportify::ResultExt;

use super::config::DaemonSettings;
use super::protocol::decode_response;
use super::protocol::finish_input;
use super::protocol::read_response;
use super::protocol::write_request;
use super::protocol::DaemonOperation;
use super::protocol::Request;
use super::protocol::Response;
use crate::config::daemon::DaemonInfo;
use crate::operations::EventSink;
use crate::operations::Operation;
use crate::system::SystemResult;

/// Executes typed operations through the privileged daemon.
pub(crate) struct DaemonClient {
    settings: DaemonSettings,
}

impl DaemonClient {
    pub(crate) fn new(settings: DaemonSettings) -> Self {
        Self { settings }
    }

    pub(crate) fn execute<O: Operation + DaemonOperation>(
        &self,
        operation: O,
        input: O::Input,
        events: &mut dyn EventSink<O::Event>,
    ) -> SystemResult<O::Output>
    where
        O::Input: Send,
    {
        let mut socket = self.connect()?;
        write_request(&mut socket, operation.into_request())?;
        let mut input_socket = socket
            .try_clone()
            .whatever("unable to prepare daemon input stream")?;
        std::thread::scope(|scope| {
            let input_task = scope.spawn(move || {
                let result = O::send_input(input, &mut input_socket);
                let shutdown_result = finish_input(&input_socket);
                result.and(shutdown_result)
            });
            let response =
                receive_response::<O>(&mut socket, self.settings.max_control_frame_size, events);
            if response.is_err() {
                let _ = socket.shutdown(Shutdown::Both);
            }
            let input_result = input_task
                .join()
                .map_err(|_| reportify::whatever!("daemon input task panicked"))?;
            match response {
                Ok(output) => {
                    input_result.whatever("unable to send daemon operation input")?;
                    Ok(output)
                }
                Err(error) => Err(error),
            }
        })
    }

    pub(crate) fn query_info(&self) -> SystemResult<DaemonInfo> {
        let mut socket = self.connect()?;
        write_request(&mut socket, Request::QueryInfo)?;
        finish_input(&socket).whatever("unable to finish daemon information request")?;
        match read_response(&mut socket, self.settings.max_control_frame_size)? {
            Response::Event(_) => {
                bail!("privileged Rugix Ctrl daemon sent an unexpected information event")
            }
            Response::Output(payload) => {
                decode_response(&payload, "unable to decode privileged daemon information")
            }
            Response::OperationError(message) => bail!("{message}"),
            Response::ProtocolError(message) => {
                bail!("privileged Rugix Ctrl daemon protocol error: {message}")
            }
        }
    }

    fn connect(&self) -> SystemResult<UnixStream> {
        UnixStream::connect(&self.settings.socket_path)
            .whatever("unable to connect to the privileged Rugix Ctrl daemon")
            .field("socket", self.settings.socket_path.clone())
    }
}

fn receive_response<O: Operation>(
    socket: &mut UnixStream,
    max_control_frame_size: usize,
    events: &mut dyn EventSink<O::Event>,
) -> SystemResult<O::Output> {
    loop {
        match read_response(socket, max_control_frame_size)? {
            Response::Event(payload) => {
                events.emit(decode_response(&payload, "unable to decode daemon event")?);
            }
            Response::Output(payload) => {
                return decode_response(&payload, "unable to decode daemon operation output");
            }
            Response::OperationError(message) => bail!("{message}"),
            Response::ProtocolError(message) => {
                bail!("privileged Rugix Ctrl daemon protocol error: {message}")
            }
        }
    }
}
