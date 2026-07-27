//! Private wire protocol for typed Rugix Ctrl operations.

use std::io;
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use reportify::bail;
use reportify::ResultExt;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;

use crate::operations::apps::ActivateApp;
use crate::operations::apps::DeactivateApp;
use crate::operations::apps::GarbageCollectApps;
use crate::operations::apps::ListApps;
use crate::operations::apps::QueryApp;
use crate::operations::apps::RemoveApp;
use crate::operations::apps::RollbackApp;
use crate::operations::apps::StartApp;
use crate::operations::apps::StopApp;
use crate::operations::install::BundleInput;
use crate::operations::install::InstallBundle;
use crate::operations::state::FactoryReset;
use crate::operations::system::CheckComponents;
use crate::operations::system::CommitSystem;
use crate::operations::system::QuerySystem;
use crate::operations::system::RebootSystem;
use crate::operations::Operation;
use crate::system::SystemResult;

const MAGIC: [u8; 4] = *b"RGXD";
const VERSION: u16 = 1;

/// An operation supported by the private daemon protocol.
pub(crate) trait DaemonOperation: Operation {
    /// Convert the operation into its tagged wire representation.
    fn into_request(self) -> Request;

    /// Send the operation input after the serialized request.
    fn send_input(input: Self::Input, socket: &mut UnixStream) -> io::Result<()>;
}

/// Operations understood by this daemon protocol version.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", content = "parameters", rename_all = "kebab-case")]
pub(crate) enum Request {
    QueryInfo,
    InstallBundle(InstallBundle),
    QuerySystem(QuerySystem),
    CheckComponents(CheckComponents),
    ListApps(ListApps),
    QueryApp(QueryApp),
    FactoryReset(FactoryReset),
    CommitSystem(CommitSystem),
    RebootSystem(RebootSystem),
    ActivateApp(ActivateApp),
    DeactivateApp(DeactivateApp),
    StartApp(StartApp),
    StopApp(StopApp),
    RollbackApp(RollbackApp),
    RemoveApp(RemoveApp),
    GarbageCollectApps(GarbageCollectApps),
}

pub(crate) enum Response {
    Event(Vec<u8>),
    Output(Vec<u8>),
    OperationError(String),
    ProtocolError(String),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ErrorKind {
    Operation,
    Protocol,
}

pub(crate) fn write_request(socket: &mut UnixStream, request: Request) -> SystemResult<()> {
    let payload = serde_json::to_vec(&request).whatever("unable to encode daemon request")?;
    let payload_len =
        u32::try_from(payload.len()).whatever("daemon request exceeds the protocol size limit")?;
    socket
        .write_all(&MAGIC)
        .whatever("unable to write daemon protocol magic")?;
    socket
        .write_all(&VERSION.to_be_bytes())
        .whatever("unable to write daemon protocol version")?;
    socket
        .write_all(&payload_len.to_be_bytes())
        .whatever("unable to write daemon request size")?;
    socket
        .write_all(&payload)
        .whatever("unable to write daemon request")
}

pub(crate) fn read_request(
    socket: &mut UnixStream,
    max_control_frame_size: usize,
) -> SystemResult<Request> {
    let mut magic = [0; 4];
    socket
        .read_exact(&mut magic)
        .whatever("unable to read daemon protocol magic")?;
    if magic != MAGIC {
        bail!("invalid daemon protocol magic");
    }
    let mut version = [0; 2];
    socket
        .read_exact(&mut version)
        .whatever("unable to read daemon protocol version")?;
    let version = u16::from_be_bytes(version);
    if version != VERSION {
        bail!("unsupported daemon protocol version {version}");
    }
    let payload = read_sized_payload(socket, max_control_frame_size, "request")?;
    serde_json::from_slice(&payload).whatever("unable to decode daemon request")
}

pub(crate) fn write_event<E: Serialize>(socket: &mut UnixStream, event: &E) -> SystemResult<()> {
    write_json_frame(socket, FrameKind::Event, event)
}

pub(crate) fn write_output<O: Serialize>(socket: &mut UnixStream, output: &O) -> SystemResult<()> {
    write_json_frame(socket, FrameKind::Output, output)
}

pub(crate) fn write_error(
    socket: &mut UnixStream,
    kind: ErrorKind,
    message: String,
) -> SystemResult<()> {
    let kind = match kind {
        ErrorKind::Operation => FrameKind::OperationError,
        ErrorKind::Protocol => FrameKind::ProtocolError,
    };
    write_json_frame(socket, kind, &WireError { message })
}

pub(crate) fn read_response(
    socket: &mut UnixStream,
    max_control_frame_size: usize,
) -> SystemResult<Response> {
    let mut kind = [0];
    socket
        .read_exact(&mut kind)
        .whatever("unable to read daemon response kind")?;
    let kind = FrameKind::try_from(kind[0])?;
    let payload = read_sized_payload(socket, max_control_frame_size, "response")?;
    match kind {
        FrameKind::Event => Ok(Response::Event(payload)),
        FrameKind::Output => Ok(Response::Output(payload)),
        FrameKind::OperationError | FrameKind::ProtocolError => {
            let error: WireError =
                serde_json::from_slice(&payload).whatever("unable to decode daemon error")?;
            Ok(match kind {
                FrameKind::OperationError => Response::OperationError(error.message),
                FrameKind::ProtocolError => Response::ProtocolError(error.message),
                _ => unreachable!(),
            })
        }
    }
}

pub(crate) fn decode_response<T: DeserializeOwned>(
    payload: &[u8],
    description: &str,
) -> SystemResult<T> {
    serde_json::from_slice(payload).whatever(description.to_owned())
}

fn write_json_frame<T: Serialize>(
    socket: &mut UnixStream,
    kind: FrameKind,
    value: &T,
) -> SystemResult<()> {
    let payload = serde_json::to_vec(value).whatever("unable to encode daemon response")?;
    let payload_len =
        u32::try_from(payload.len()).whatever("daemon response exceeds the protocol size limit")?;
    socket
        .write_all(&[kind as u8])
        .whatever("unable to write daemon response kind")?;
    socket
        .write_all(&payload_len.to_be_bytes())
        .whatever("unable to write daemon response size")?;
    socket
        .write_all(&payload)
        .whatever("unable to write daemon response")
}

fn read_sized_payload(
    socket: &mut UnixStream,
    max_control_frame_size: usize,
    frame_description: &str,
) -> SystemResult<Vec<u8>> {
    let mut payload_len = [0; 4];
    socket
        .read_exact(&mut payload_len)
        .whatever(format!("unable to read daemon {frame_description} size"))?;
    let payload_len = u32::from_be_bytes(payload_len) as usize;
    if payload_len > max_control_frame_size {
        bail!(
            "daemon {frame_description} exceeds the configured control frame size ({payload_len} > {max_control_frame_size})"
        );
    }
    let mut payload = vec![0; payload_len];
    socket
        .read_exact(&mut payload)
        .whatever(format!("unable to read daemon {frame_description}"))?;
    Ok(payload)
}

#[derive(Debug, Serialize, Deserialize)]
struct WireError {
    message: String,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum FrameKind {
    Event = 1,
    Output = 2,
    OperationError = 3,
    ProtocolError = 4,
}

impl TryFrom<u8> for FrameKind {
    type Error = reportify::Report<crate::system::SystemError>;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Event),
            2 => Ok(Self::Output),
            3 => Ok(Self::OperationError),
            4 => Ok(Self::ProtocolError),
            _ => bail!("unknown daemon response kind {value}"),
        }
    }
}

fn send_no_input(_input: (), _socket: &mut UnixStream) -> io::Result<()> {
    Ok(())
}

macro_rules! impl_no_input_daemon_operation {
    ($operation:ty, $variant:ident) => {
        impl DaemonOperation for $operation {
            fn into_request(self) -> Request {
                Request::$variant(self)
            }

            fn send_input(input: Self::Input, socket: &mut UnixStream) -> io::Result<()> {
                send_no_input(input, socket)
            }
        }
    };
}

impl DaemonOperation for InstallBundle {
    fn into_request(self) -> Request {
        Request::InstallBundle(self)
    }

    fn send_input(input: Self::Input, socket: &mut UnixStream) -> io::Result<()> {
        match input {
            BundleInput::None => Ok(()),
            BundleInput::Stream(mut input) => io::copy(&mut input, socket).map(|_| ()),
            BundleInput::Seekable(mut input) => io::copy(&mut input, socket).map(|_| ()),
        }
    }
}

impl_no_input_daemon_operation!(QuerySystem, QuerySystem);
impl_no_input_daemon_operation!(CheckComponents, CheckComponents);
impl_no_input_daemon_operation!(ListApps, ListApps);
impl_no_input_daemon_operation!(QueryApp, QueryApp);
impl_no_input_daemon_operation!(FactoryReset, FactoryReset);
impl_no_input_daemon_operation!(CommitSystem, CommitSystem);
impl_no_input_daemon_operation!(RebootSystem, RebootSystem);
impl_no_input_daemon_operation!(ActivateApp, ActivateApp);
impl_no_input_daemon_operation!(DeactivateApp, DeactivateApp);
impl_no_input_daemon_operation!(StartApp, StartApp);
impl_no_input_daemon_operation!(StopApp, StopApp);
impl_no_input_daemon_operation!(RollbackApp, RollbackApp);
impl_no_input_daemon_operation!(RemoveApp, RemoveApp);
impl_no_input_daemon_operation!(GarbageCollectApps, GarbageCollectApps);

pub(crate) fn finish_input(socket: &UnixStream) -> io::Result<()> {
    socket.shutdown(Shutdown::Write)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    use super::read_request;
    use super::write_request;
    use super::Request;
    use crate::operations::system::QuerySystem;

    #[test]
    fn request_reader_rejects_payloads_before_allocating_beyond_the_limit() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(b"RGXD").unwrap();
        client.write_all(&1u16.to_be_bytes()).unwrap();
        client.write_all(&4096u32.to_be_bytes()).unwrap();

        let error = read_request(&mut server, 1024).unwrap_err();

        assert!(format!("{error:?}").contains("4096 > 1024"));
    }

    #[test]
    fn typed_requests_round_trip_through_the_protocol_header() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        write_request(&mut client, Request::QuerySystem(QuerySystem)).unwrap();

        assert!(matches!(
            read_request(&mut server, 1024).unwrap(),
            Request::QuerySystem(QuerySystem)
        ));
    }
}
