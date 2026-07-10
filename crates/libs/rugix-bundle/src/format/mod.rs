//! Low-level implementation of the bundle format and its structures.
//!
//! The bundle format is based on the *STLV encoding* specified and implemented in
//! [`stlv`].

use std::io::Write;
use std::io::{self};

use reportify::ResultExt;
use reportify::bail;

use rugix_chunker::ChunkerAlgorithm;
use rugix_compression::CompressionFormat;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;

use crate::BundleResult;
use crate::manifest::DeltaEncodingFormat;
use crate::source::BundleSource;

use self::decode::Decode;
use self::decode::Decoder;
use self::encode::Encode;
use self::macros::define_struct;
use self::stlv::AtomHead;
use self::stlv::Tag;
use self::stlv::write_atom_head;
use self::stlv::write_value;

mod macros;

pub mod decode;
pub mod encode;
pub mod stlv;
pub mod tags;

define_struct! {
    /// Bundle header.
    pub struct BundleHeader {
        /// Optional bundle manifest (JSON-encoded).
        pub manifest[BUNDLE_HEADER_MANIFEST]: Option<String>,
        /// Indicates whether the update is incremental.
        pub is_incremental[BUNDLE_HEADER_IS_INCREMENTAL]: bool,
        /// Hash algorithm to secure the bundle.
        pub hash_algorithm[BUNDLE_HEADER_HASH_ALGORITHM]: HashAlgorithm,
        /// Optional component metadata declared by the bundle.
        pub components[BUNDLE_HEADER_COMPONENTS]: Option<BundleComponents>,
        /// Payload index.
        pub payload_index[BUNDLE_HEADER_PAYLOAD_INDEX]: Vec<PayloadEntry>,
    }
}

define_struct! {
    /// Component metadata declared by a bundle.
    pub struct BundleComponents {
        /// Component metadata files.
        pub files[BUNDLE_COMPONENTS_FILE]: Vec<BundleComponentFile>,
    }
}

impl BundleComponents {
    /// Create bundle-declared component metadata.
    pub fn new(files: Vec<BundleComponentFile>) -> Self {
        Self { files }
    }
}

define_struct! {
    /// Component metadata file declared by a bundle.
    pub struct BundleComponentFile {
        /// Path relative to the bundle's `components` directory.
        pub path[BUNDLE_COMPONENT_FILE_PATH]: String,
        /// Raw file data.
        pub data[BUNDLE_COMPONENT_FILE_DATA]: Bytes,
    }
}

impl BundleComponentFile {
    /// Create a bundle-declared component metadata file.
    pub fn new(path: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            data: Bytes { raw: data.into() },
        }
    }
}

define_struct! {
    /// Entry in the payload index of a bundle.
    pub struct PayloadEntry {
        /// Slot where the payload should be installed to.
        pub type_slot[PAYLOAD_ENTRY_TYPE_SLOT]: Option<SlotPayloadType>,
        pub type_execute[PAYLOAD_ENTRY_TYPE_EXECUTE]: Option<ExecutePayloadType>,
        /// App file payload.
        pub type_app_file[PAYLOAD_ENTRY_TYPE_APP_FILE]: Option<AppFilePayloadType>,
        /// App archive payload.
        pub type_app_archive[PAYLOAD_ENTRY_TYPE_APP_ARCHIVE]: Option<AppArchivePayloadType>,
        /// Hash of the payload header.
        pub header_hash[PAYLOAD_ENTRY_HEADER_HASH]: Bytes,
        /// Hash of the payload file.
        pub file_hash[PAYLOAD_ENTRY_FILE_HASH]: Bytes,
        /// Delta encoding.
        pub delta_encoding[PAYLOAD_ENTRY_DELTA_ENCODING]: Option<DeltaEncoding>,
    }
}

define_struct! {
    pub struct DeltaEncoding {
        pub format[DELTA_ENCODING_FORMAT]: DeltaEncodingFormat,
        pub inputs[DELTA_ENCODING_INPUT]: Vec<DeltaEncodingInput>,
        pub original_hash[DELTA_ENCODING_ORIGINAL_HASH]: HashDigest,
    }
}

define_struct! {
    pub struct DeltaEncodingInput {
        pub hashes[DELTA_ENCODING_INPUT_HASH]: Vec<HashDigest>,
    }
}

impl Decode for HashDigest {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, atom: AtomHead) -> BundleResult<Self> {
        String::decode(decoder, atom)?
            .parse::<Self>()
            .whatever("invalid hash digest")
    }
}

impl Encode for HashDigest {
    fn encode(&self, writer: &mut dyn Write, tag: Tag) -> io::Result<()> {
        write_value(writer, tag, self.to_string().as_bytes())
    }
}

define_struct! {
    /// Header of a payload.
    pub struct SlotPayloadType {
        pub slot[PAYLOAD_TYPE_SLOT_SLOT]: String,
    }
}

define_struct! {
    /// Header of a payload.
    pub struct ExecutePayloadType {
        pub handler[PAYLOAD_TYPE_EXECUTE_HANDLER]: Vec<String>,
    }
}

define_struct! {
    /// App file payload type: a single file written to a generation directory.
    pub struct AppFilePayloadType {
        /// App name.
        pub app[PAYLOAD_TYPE_APP_FILE_APP]: String,
        /// Relative path within the generation directory.
        pub path[PAYLOAD_TYPE_APP_FILE_PATH]: String,
        /// Unix file mode (e.g., 0o755 for executables).
        pub mode[PAYLOAD_TYPE_APP_FILE_MODE]: Option<u32>,
    }
}

define_struct! {
    /// App archive payload type: a tar archive extracted into a generation directory.
    pub struct AppArchivePayloadType {
        /// App name.
        pub app[PAYLOAD_TYPE_APP_ARCHIVE_APP]: String,
    }
}

define_struct! {
    /// Header of a payload.
    pub struct PayloadHeader {
        /// Block encoding.
        pub block_encoding[PAYLOAD_HEADER_BLOCK_ENCODING]: Option<BlockEncoding>,
    }
}

define_struct! {
    /// Signatures.
    #[derive(Default)]
    pub struct Signatures {
        /// Embedded CMS signatures.
        pub cms_signatures[SIGNATURES_CMS_SIGNATURE]: Vec<Bytes>,
    }
}

define_struct! {
    /// Payload block encoding.
    pub struct BlockEncoding {
        /// Chunker used for the encoding.
        pub chunker[BLOCK_ENCODING_CHUNKER]: ChunkerAlgorithm,
        /// Hash algorithm.
        pub hash_algorithm[BLOCK_ENCODING_HASH_ALGORITHM]: HashAlgorithm,
        /// Whether blocks have been deduplicated.
        pub deduplicated[BLOCK_ENCODING_DEDUPLICATED]: bool,
        pub compression[BLOCK_ENCODING_COMPRESSION]: Option<CompressionFormat>,
        /// Block index.
        pub block_hashes[BLOCK_ENCODING_BLOCK_HASHES]: Bytes,
        /// Block sizes.
        pub block_sizes[BLOCK_ENCODING_BLOCK_SIZES]: Option<Bytes>,
    }
}

define_struct! {
    pub struct BlockIndex {
        pub chunker[BLOCK_INDEX_CHUNKER]: ChunkerAlgorithm,
        pub hash_algorithm[BLOCK_INDEX_HASH_ALGORITHM]: HashAlgorithm,
        pub block_hashes[BLOCK_INDEX_BLOCK_HASHES]: Bytes,
        pub block_sizes[BLOCK_INDEX_BLOCK_SIZES]: Bytes,
    }
}

define_struct! {
    pub struct XzCompression {}
}

define_struct! {
    pub struct SignedMetadata {
        pub header_hash[SIGNED_METADATA_HEADER_HASH]: HashDigest,
    }
}

/// Encodable and decodable bytes.
#[derive(Debug, Clone)]
pub struct Bytes {
    /// Raw byte vector.
    pub raw: Vec<u8>,
}

impl Encode for Bytes {
    fn encode(&self, writer: &mut dyn Write, tag: Tag) -> io::Result<()> {
        write_value(writer, tag, &self.raw)
    }
}

impl Decode for Bytes {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, atom: AtomHead) -> BundleResult<Self> {
        if !atom.is_value() {
            bail!("cannot decode `Bytes` from segment");
        }
        Ok(Self {
            raw: decoder.read_value()?,
        })
    }
}

impl Encode for HashAlgorithm {
    fn encode(&self, writer: &mut dyn Write, tag: Tag) -> io::Result<()> {
        write_value(
            writer,
            tag,
            match self {
                HashAlgorithm::Sha512_256 => "sha512-256".as_bytes(),
                _ => self.name().as_bytes(),
            },
        )
    }
}

impl Decode for HashAlgorithm {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, atom: AtomHead) -> BundleResult<Self> {
        String::decode(decoder, atom)?
            .parse::<Self>()
            .whatever("unknown hash algorithm")
    }
}

impl Encode for DeltaEncodingFormat {
    fn encode(&self, writer: &mut dyn Write, tag: Tag) -> io::Result<()> {
        write_value(
            writer,
            tag,
            match self {
                DeltaEncodingFormat::Xdelta => b"xdelta",
            },
        )
    }
}

impl Decode for DeltaEncodingFormat {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, atom: AtomHead) -> BundleResult<Self> {
        match String::decode(decoder, atom)?.as_str() {
            "xdelta" => Ok(Self::Xdelta),
            format => bail!("unknown delta encoding format '{format}'"),
        }
    }
}

impl Encode for ChunkerAlgorithm {
    fn encode(&self, writer: &mut dyn Write, tag: Tag) -> io::Result<()> {
        write_value(writer, tag, self.to_string().as_bytes())
    }
}

impl Decode for ChunkerAlgorithm {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, atom: AtomHead) -> BundleResult<Self> {
        String::decode(decoder, atom)?
            .parse::<Self>()
            .whatever("unknown chunker algorithm")
    }
}

impl Encode for CompressionFormat {
    fn encode(&self, writer: &mut dyn Write, tag: Tag) -> io::Result<()> {
        write_value(writer, tag, self.as_str().as_bytes())
    }
}

impl Decode for CompressionFormat {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, atom: AtomHead) -> BundleResult<Self> {
        String::decode(decoder, atom)?
            .parse::<Self>()
            .whatever("unknown compression format")
    }
}
