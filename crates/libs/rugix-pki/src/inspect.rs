//! Read CMS content and claimed signer identities without validating signatures.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::db::rfc5911::ID_SIGNED_DATA;
use der::Decode;
use der::asn1::OctetString;

use crate::PkiError;
use crate::PkiResult;
use crate::verify::extract_certificates;
use crate::verify::find_signer_certificate;

/// Unverified content and claimed signer identities from a CMS signature.
#[derive(Debug)]
pub struct CmsInspection {
    /// Encapsulated content, when it could be decoded.
    pub content: Option<Vec<u8>>,
    /// Subjects of certificates referenced by signer entries, excluding intermediates.
    pub signer_subjects: Vec<String>,
    /// Problems resolving content or signer certificates.
    pub errors: Vec<String>,
}

/// Parse CMS metadata without cryptographic or certificate-chain verification.
///
/// Malformed CMS framing returns an error. Problems with encapsulated content or
/// missing signer certificates are reported alongside the metadata that could be read.
pub fn inspect_cms(cms_der: &[u8]) -> PkiResult<CmsInspection> {
    let content_info = ContentInfo::from_der(cms_der)
        .map_err(|error| PkiError::InvalidCms(format!("failed to parse ContentInfo: {error}")))?;
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(PkiError::InvalidCms(format!(
            "unexpected content type: {}, expected SignedData",
            content_info.content_type
        )));
    }
    let signed_data: SignedData = content_info
        .content
        .decode_as()
        .map_err(|error| PkiError::InvalidCms(format!("failed to parse SignedData: {error}")))?;
    let mut inspection = CmsInspection {
        content: None,
        signer_subjects: Vec::new(),
        errors: Vec::new(),
    };
    match signed_data.encap_content_info.econtent.as_ref() {
        Some(content) => match content.decode_as::<OctetString>() {
            Ok(content) => inspection.content = Some(content.as_bytes().to_vec()),
            Err(error) => inspection
                .errors
                .push(format!("failed to decode content: {error}")),
        },
        None => inspection
            .errors
            .push(PkiError::NoEncapsulatedContent.to_string()),
    }
    if signed_data.signer_infos.0.is_empty() {
        inspection.errors.push(PkiError::NoSignerInfo.to_string());
    }
    match extract_certificates(&signed_data) {
        Ok(certificates) => {
            for signer in signed_data.signer_infos.0.iter() {
                match find_signer_certificate(&certificates, &signer.sid) {
                    Ok(certificate) => inspection
                        .signer_subjects
                        .push(certificate.tbs_certificate.subject.to_string()),
                    Err(error) => inspection.errors.push(error.to_string()),
                }
            }
        }
        Err(error) => inspection.errors.push(error.to_string()),
    }
    Ok(inspection)
}
