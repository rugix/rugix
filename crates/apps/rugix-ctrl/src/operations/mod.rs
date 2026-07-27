//! Typed Rugix Ctrl operations and their executors.
//!
//! Concrete operations define their input, event, and output types through the
//! abstract interface. A wire layer can serialize those values while remaining
//! responsible for operation selection, framing, and streamed input.

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;

use self::local::ExecutionContext;
use crate::system::SystemResult;

pub mod apps;
pub mod install;
pub mod local;
pub mod state;
pub mod system;

/// A Rugix Ctrl operation with statically known input, event, and output types.
pub trait Operation: Serialize + DeserializeOwned {
    /// Data supplied to the executor outside the serialized operation value.
    type Input;
    /// Event emitted while the operation executes.
    type Event: Serialize + DeserializeOwned;
    /// Value returned after successful execution.
    type Output: Serialize + DeserializeOwned;

    /// Execute the operation directly on the host.
    fn execute(
        self,
        context: &ExecutionContext<'_>,
        input: Self::Input,
        events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output>;
}

/// Executes typed operations.
pub trait Executor {
    /// Execute an operation.
    fn execute<O: Operation>(
        &self,
        operation: O,
        input: O::Input,
        events: &mut dyn EventSink<O::Event>,
    ) -> SystemResult<O::Output>;
}

/// Receives events of a specific type.
pub trait EventSink<E> {
    /// Emit an event.
    fn emit(&mut self, event: E);
}

/// The event type for operations that cannot emit events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NoEvent {}
