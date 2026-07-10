use std::io;
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl;
use nix::libc::c_char;
use nix::libc::c_int;
use nix::sys::stat;
use reportify::Report;
use reportify::ResultExt;

const RPI_FIRMWARE_GET_REBOOT_FLAGS: u32 = 0x00030064_u32;
const RPI_FIRMWARE_SET_REBOOT_FLAGS: u32 = 0x00038064_u32;

/// Sets the tryboot flag by directly interacting with Raspberry Pi's firmware.
pub fn main() -> Result<(), Report<io::Error>> {
    let vcio = Vcio::open().report()?;
    let mut buffer = encode_request(RPI_FIRMWARE_GET_REBOOT_FLAGS, 0);
    unsafe { vcio.ioctl_property(&mut buffer).report()? };
    println!("{buffer:?}");
    buffer = encode_request(RPI_FIRMWARE_SET_REBOOT_FLAGS, 1);
    unsafe { vcio.ioctl_property(&mut buffer).report()? };
    buffer = encode_request(RPI_FIRMWARE_GET_REBOOT_FLAGS, 0);
    unsafe { vcio.ioctl_property(&mut buffer).report()? };
    println!("{buffer:?}");
    Ok(())
}

fn encode_request(tag: u32, flags: u32) -> [u32; 7] {
    [
        7 * 4, // Size of the buffer in bytes.
        0,     // Request code (process request).
        tag,   // The request tag.
        4,     // Size of the value buffer in bytes.
        0,     // Tag request code.
        flags, // Reboot flags (values).
        0,     // Tag end.
    ]
}

/// The path to the VCIO device.
pub const VCIO_PATH: &str = "/dev/vcio";

/// A handle to the VCIO device.
#[derive(Debug)]
pub struct Vcio {
    /// The underlying file descriptor.
    fd: c_int,
}

impl Vcio {
    /// Checks whether the VCIO device exists.
    pub fn exists() -> bool {
        Path::new(VCIO_PATH).exists()
    }

    /// Opens a handle to the VCIO device.
    pub fn open() -> Result<Self, io::Error> {
        let flags = fcntl::OFlag::O_NONBLOCK;
        let mode = stat::Mode::empty();
        fcntl::open(VCIO_PATH, flags, mode)
            .map_err(to_io_error)
            .map(|fd| Self { fd })
    }

    /// Performs an `ioctl` call to the VCIO property interface using the provided buffer.
    ///
    /// # Safety
    ///
    /// The provided `buffer` must be valid as required by the property interface.
    pub unsafe fn ioctl_property(&self, buffer: &mut [u32]) -> Result<c_int, io::Error> {
        // Violating this safety precondition will most likely cause UB.
        assert!(
            buffer[0] <= (buffer.len() * 4) as u32,
            "Invalid buffer size. Buffer is smaller than indicated."
        );

        /// The `ioctl` identifier of the property interface.
        const IOCTL_IDENTIFIER: u8 = 100;
        /// The `ioctl` sequence number of the property interface.
        const IOCTL_SEQ_PROPERTY: u8 = 0;

        // We have to cast to `c_int` to make this work on 32-bit and 64-bit.
        const IOCTL_REQUEST_CODE: c_int = nix::request_code_readwrite!(
            IOCTL_IDENTIFIER,
            IOCTL_SEQ_PROPERTY,
            std::mem::size_of::<*mut c_char>()
        ) as c_int;

        // We have to use `ioctl_readwrite_bad` here because the code is computed with
        // `*mut c_char` but the actual type needs to be `c_char`.
        nix::ioctl_readwrite_bad! {
            /// Raw `ioctl` call.
            ioctl_property,
            IOCTL_REQUEST_CODE,
            c_char
        };

        ioctl_property(self.fd, buffer.as_mut_ptr() as *mut c_char).map_err(to_io_error)
    }
}

/// Converts an [`Errno`] into a proper [`io::Error`].
fn to_io_error(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}
