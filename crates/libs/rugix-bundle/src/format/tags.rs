/* cspell:ignore randint, clike, unportable */
//! STLV tags of the bundle format.
//!
//! The first bit of a tag indicates whether a value or segment with the tag may be
//! skipped by an older reader not supporting the tag. We call such tags *optional*. This
//! allows future versions to extend the format in a forward compatible way. Instead of
//! skipping *all* tags which are not supported by the reader, encoding this information
//! explicitly has the advantage that we can also make tags *required* in cases where an
//! extension must be processed by a reader. For instance, when extending a hash with a
//! salt, the reader must take the salt into account; otherwise, it may compute an
//! incorrect hash which can lead to hard to diagnose bugs down the line. In this case, if
//! the reader does not take the salt into account, the result would be indistinguishable
//! from an incorrect hash leading to confusing error messages. We want to fail early and
//! tell the user that the format is newer, not that the hash does not match.
//!
//! We use globally unique tags such that we can identify segments and values without any
//! context.
//!
//!
//! # Tag Generation
//!
//! The tags defined here have been randomly generated with the following Python snippets.
//!
//! To generate a random required tag:
//!
//! ```python
//! f"0x{random.randint(0, 2**31 - 1):08x}"
//! ```
//!
//! To generate a random optional tag:
//!
//! ```python
//! f"0x{random.randint(2**31, 2**32 - 1):08x}"
//! ```

use super::stlv::Tag;
use super::stlv::{self};

/// Bit mask to determine whether the handling of a tag is optional or required.
const IS_OPTIONAL_MASK: u8 = 0b1000_0000;

/// Returns whether handling of the tag is optional.
pub const fn is_optional(tag: Tag) -> bool {
    (tag.as_bytes()[0] & IS_OPTIONAL_MASK) != 0
}

/// Returns whether handling of the tag is required.
pub const fn is_required(tag: Tag) -> bool {
    !is_optional(tag)
}

/// Auxiliary macro for defining tags.
macro_rules! define_tags {
    (@define { }) => {};
    (@define {
        $(#[$meta:meta])*
        $name:ident = $tag:literal
        $($tail:tt)*
    }) => {
        $(#[$meta])*
        pub const $name: Tag = Tag::from_bytes(($tag as u32).to_be_bytes());
        define_tags! { @define $name { $($tail)* }}
    };
    (@define $name:ident { , $($tail:tt)* }) => {
        // Compile time check that the tag is indeed required.
        const _: () = {
            if is_optional($name) {
                panic!(stringify!($name));
                // panic!("tag is required but marked as optional");
            }
        };
        define_tags! { @define { $($tail)* }}
    };
    (@define $name:ident { ?, $($tail:tt)* }) => {
        // Compile time check that the tag is indeed optional.
        const _: () = {
            if is_required($name) {
                panic!(stringify!($name));
                // panic!("tag is optional but marked as required");
            }
        };
        define_tags! { @define { $($tail)* }}
    };
    (@impl {
        $(
            $(#[$meta:meta])*
            $name:ident = $tag:literal$(?)?,
        )*
    }) => {
        // Compile time check that all tags are unique.
        #[cfg(target_pointer_width = "64")]
        const _: () = {
            #[doc(hidden)]
            #[allow(non_camel_case_types)]
            #[allow(clippy::enum_clike_unportable_variant)]
            #[allow(clippy::upper_case_acronyms)]
            #[allow(dead_code)]
            enum Tags {
                $(
                    $name = $tag,
                )*
            }
        };

        /// Tag name resolver for pretty printing.
        #[derive(Debug, Clone, Copy)]
        pub struct TagNameResolver;

        impl stlv::TagNameResolver for TagNameResolver {
            fn resolve(&self, tag: Tag) -> Option<&str> {
                match tag {
                    $(
                        $name => Some(stringify!($name)),
                    )*
                    _ => None,
                }
            }
        }

        /// Returns whether the tag is known.
        pub const fn is_know(tag: Tag) -> bool {
            match tag {
                $(
                    $name => true,
                )*
                _ => false,
            }
        }
    };
    ($($tail:tt)*) => {
        define_tags! { @define { $($tail)* }}
        define_tags! { @impl { $($tail)* }}
    };
}

define_tags! {
    /// Bundle root segment.
    BUNDLE = 0x6b50741c,

    /// Bundle header segment.
    BUNDLE_HEADER = 0x49af6433,
    BUNDLE_HEADER_MANIFEST = 0x161aa242,
    /// Bundle manifest.
    BUNDLE_HEADER_HASH_ALGORITHM = 0x5cb80dd6,
    /// Entry in the payload index.
    BUNDLE_HEADER_PAYLOAD_INDEX = 0x13737992,

    /// Slot where the payload should be installed to.
    PAYLOAD_ENTRY_TYPE_SLOT = 0x45ca7e7e,
    PAYLOAD_ENTRY_TYPE_EXECUTE = 0x3adf32f5,
    /// Hash of the payload's header.
    PAYLOAD_ENTRY_HEADER_HASH = 0x5f6a60b1,
    /// Hash of the payload's file.
    PAYLOAD_ENTRY_FILE_HASH = 0x0c8d1fd0,
    /// Payload entry delta encoding.
    PAYLOAD_ENTRY_DELTA_ENCODING = 0x272cdf9f,

    PAYLOAD_TYPE_SLOT_SLOT = 0x1b231de7,

    PAYLOAD_TYPE_EXECUTE_HANDLER = 0x4b3836a2,

    /// App file payload: a single file written to a generation directory.
    PAYLOAD_ENTRY_TYPE_APP_FILE = 0x214c6e2b,
    PAYLOAD_TYPE_APP_FILE_APP = 0x6b42b4a2,
    PAYLOAD_TYPE_APP_FILE_PATH = 0x2c4e33b4,
    /// Unix file mode for an app file payload.
    PAYLOAD_TYPE_APP_FILE_MODE = 0x83dd01fb?,
    /// Whether to keep an app file payload in the content-addressed store.
    PAYLOAD_TYPE_APP_FILE_STORE = 0x9e95013e?,

    /// App archive payload: a tar archive extracted into a generation directory.
    PAYLOAD_ENTRY_TYPE_APP_ARCHIVE = 0x40a88630,
    PAYLOAD_TYPE_APP_ARCHIVE_APP = 0x3fa221ce,

    BLOCK_INDEX = 0x1ae50c8e,

    BUNDLE_HEADER_IS_INCREMENTAL = 0x20f3d16b,
    /// Optional component metadata declared by the bundle.
    BUNDLE_HEADER_COMPONENTS = 0x8d25bba7?,
    /// Component metadata file declared by the bundle.
    BUNDLE_COMPONENTS_FILE = 0x1c47f0a2,
    /// Component metadata file path.
    BUNDLE_COMPONENT_FILE_PATH = 0x0e6c9a41,
    /// Component metadata file data.
    BUNDLE_COMPONENT_FILE_DATA = 0x35b2f928,

    BLOCK_INDEX_CHUNKER = 0x5cdf21b0,
    BLOCK_INDEX_HASH_ALGORITHM = 0x1d92a080,
    BLOCK_INDEX_BLOCK_HASHES = 0x55e547d8,
    BLOCK_INDEX_BLOCK_SIZES = 0x4668c5ba,

    /// Signatures segment of the bundle.
    SIGNATURES = 0xa83936f1?,

    /// CMS signature.
    SIGNATURES_CMS_SIGNATURE = 0x9795498f?,

    /// Payloads segment of the bundle.
    PAYLOADS = 0x1f38fba,

    /// Payload segment.
    PAYLOAD = 0x490cafaf,
    /// Payload header segment.
    PAYLOAD_HEADER = 0x0959ca75,
    /// Data of the payload.
    PAYLOAD_DATA = 0x42fd641a,

    /// Payload block encoding.
    PAYLOAD_HEADER_BLOCK_ENCODING = 0x40ed9314,

    COMPRESSION_XZ = 0x747df11b,

    BLOCK_ENCODING_HASH_ALGORITHM = 0x7f1f994b,
    BLOCK_ENCODING_DEDUPLICATED = 0x05902926,
    BLOCK_ENCODING_CHUNKER = 0x55872cf8,
    BLOCK_ENCODING_COMPRESSION = 0x783217c6,

    /// Block index.
    BLOCK_ENCODING_BLOCK_HASHES = 0x76b3d7a0,
    /// Block sizes.
    BLOCK_ENCODING_BLOCK_SIZES = 0x27e5d3f2,

    /// Delta encoding format.
    DELTA_ENCODING_FORMAT = 0x3b8aeb9a,
    /// Delta encoding input.
    DELTA_ENCODING_INPUT = 0x4e08b9f1,
    /// Delta encoding original hash.
    DELTA_ENCODING_ORIGINAL_HASH = 0x64760e1c,

    /// Hash to identify a delta encoding input.
    DELTA_ENCODING_INPUT_HASH = 0x3a0d1307,

    /// Signed metadata.
    SIGNED_METADATA = 0x61d0871e,
    /// Signed metadata header hash.
    SIGNED_METADATA_HEADER_HASH = 0x1f992dfc,
}
