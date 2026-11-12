//! Resource limits for decoding untrusted CMS update metadata.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::db::rfc5911::ID_SIGNED_DATA;
use der::Decode;
use der::Tagged;

use crate::PkiError;
use crate::PkiResult;

/// Bound quadratic SET OF sorting in der 0.7 before it sees untrusted input.
/// Encapsulated content is excluded because its octets require no SET OF sorting.
const MAX_CMS_METADATA_SIZE: usize = 32 * 1024;
const MAX_SIGNERS: usize = 16;

/// Decode CMS update metadata with bounded parsing and signer verification work.
pub(crate) fn decode_cms(cms_der: &[u8]) -> PkiResult<SignedData> {
    let content_info = ContentInfo::from_der(cms_der)
        .map_err(|error| PkiError::InvalidCms(format!("failed to parse ContentInfo: {error}")))?;
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(PkiError::InvalidCms(format!(
            "unexpected content type: {}, expected SignedData",
            content_info.content_type
        )));
    }
    // Decode only framing and opaque fields before bounding metadata. This avoids
    // SET OF sorting while preserving support for large encapsulated content.
    let raw = content_info
        .content
        .decode_as::<RawSignedData>()
        .map_err(|error| {
            PkiError::InvalidCms(format!("failed to parse SignedData framing: {error}"))
        })?;
    let content_len = raw
        .encap_content_info
        .econtent
        .as_ref()
        .filter(|content| content.tag() == der::Tag::OctetString)
        .map_or(0, |content| content.value().len());
    if cms_der.len().saturating_sub(content_len) > MAX_CMS_METADATA_SIZE {
        return Err(PkiError::InvalidCms(format!(
            "CMS metadata exceeds the {} byte size limit",
            MAX_CMS_METADATA_SIZE
        )));
    }
    let signed_data: SignedData = content_info
        .content
        .decode_as()
        .map_err(|error| PkiError::InvalidCms(format!("failed to parse SignedData: {error}")))?;
    if signed_data.signer_infos.0.len() > MAX_SIGNERS {
        return Err(PkiError::InvalidCms(format!(
            "CMS exceeds the {} signer limit",
            MAX_SIGNERS
        )));
    }
    Ok(signed_data)
}

/// Opaque collections defer all SET OF decoding until the metadata budget is checked.
#[derive(der::Sequence)]
struct RawSignedData<'a> {
    version: u8,
    digest_algorithms: der::asn1::AnyRef<'a>,
    encap_content_info: RawEncapsulatedContent<'a>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    certificates: Option<der::asn1::AnyRef<'a>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    crls: Option<der::asn1::AnyRef<'a>>,
    signer_infos: der::asn1::AnyRef<'a>,
}

/// Borrow the content rather than copying potentially large primitive octets.
#[derive(der::Sequence)]
struct RawEncapsulatedContent<'a> {
    content_type: const_oid::ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    econtent: Option<der::asn1::AnyRef<'a>>,
}
