//! CMS signature verification with certificate chain validation.

use aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1;
use aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1;
use aws_lc_rs::signature::ED25519;
use aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256;
use aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA384;
use aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA512;
use aws_lc_rs::signature::RSA_PSS_2048_8192_SHA256;
use aws_lc_rs::signature::RSA_PSS_2048_8192_SHA384;
use aws_lc_rs::signature::RSA_PSS_2048_8192_SHA512;
use aws_lc_rs::signature::UnparsedPublicKey;
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use cms::signed_data::SignerIdentifier;
use const_oid::ObjectIdentifier;
use const_oid::db::rfc5911::ID_CONTENT_TYPE;
use const_oid::db::rfc5911::ID_DATA;
use const_oid::db::rfc5911::ID_MESSAGE_DIGEST;
use const_oid::db::rfc5911::ID_SIGNED_DATA;
use const_oid::db::rfc5912::ECDSA_WITH_SHA_256;
use const_oid::db::rfc5912::ECDSA_WITH_SHA_384;
use const_oid::db::rfc5912::ID_EC_PUBLIC_KEY;
use const_oid::db::rfc5912::ID_SHA_256;
use const_oid::db::rfc5912::ID_SHA_384;
use const_oid::db::rfc5912::ID_SHA_512;
use const_oid::db::rfc5912::RSA_ENCRYPTION;
use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;
use const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION;
use const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION;
use der::Decode;
use der::Encode;
use der::Tag;
use der::Tagged;
use der::asn1::GeneralizedTime;
use der::asn1::OctetString;
use der::asn1::UtcTime;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::UnixTime;
use webpki::EndEntityCert;
use webpki::anchor_from_trusted_cert;
use x509_cert::Certificate;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::ext::pkix::KeyUsage as X509KeyUsage;

use std::time::SystemTime;

use crate::PkiError;
use crate::PkiResult;
use crate::RsaPssParams;
use crate::compute_digest;
use crate::pem;

/// OID for RSA-PSS signature algorithm (1.2.840.113549.1.1.10)
const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// OID for Ed25519 (1.3.101.112) - RFC 8410
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// OID for signing-time attribute (1.2.840.113549.1.9.5) — RFC 5652 Section 11.3.
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

/// A CMS verifier that validates signatures against a trusted root certificate.
pub struct CmsVerifier {
    root_cert: Certificate,
}

impl CmsVerifier {
    /// Create a new CMS verifier with a PEM-encoded root certificate.
    pub fn new(root_cert_pem: &[u8]) -> PkiResult<Self> {
        let root_cert_der = pem::parse(root_cert_pem, "CERTIFICATE")?;
        let root_cert = Certificate::from_der(&root_cert_der)
            .map_err(|e| PkiError::CertificateParse(e.to_string()))?;

        Ok(Self { root_cert })
    }

    /// Create a new CMS verifier from a DER-encoded root certificate.
    pub fn from_der(root_cert_der: &[u8]) -> PkiResult<Self> {
        let root_cert = Certificate::from_der(root_cert_der)
            .map_err(|e| PkiError::CertificateParse(e.to_string()))?;

        Ok(Self { root_cert })
    }

    /// Verify a DER-encoded CMS signature.
    ///
    /// This method:
    ///
    /// 1. Parses the CMS structure
    /// 2. Extracts and validates the certificate chain
    /// 3. Verifies the signature
    /// 4. Returns the encapsulated content if verification succeeds
    pub fn verify(&self, cms_der: &[u8]) -> PkiResult<VerificationResult> {
        let content_info = ContentInfo::from_der(cms_der)
            .map_err(|e| PkiError::InvalidCms(format!("failed to parse ContentInfo: {}", e)))?;

        if content_info.content_type != ID_SIGNED_DATA {
            return Err(PkiError::InvalidCms(format!(
                "unexpected content type: {}, expected SignedData",
                content_info.content_type
            )));
        }

        let signed_data: SignedData = content_info
            .content
            .decode_as()
            .map_err(|e| PkiError::InvalidCms(format!("failed to parse SignedData: {}", e)))?;

        let econtent = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or(PkiError::NoEncapsulatedContent)?;

        let content_bytes: OctetString = econtent
            .decode_as()
            .map_err(|e| PkiError::InvalidCms(format!("failed to decode content: {}", e)))?;
        let content = content_bytes.as_bytes().to_vec();

        let embedded_certs = extract_certificates(&signed_data)?;
        if signed_data.signer_infos.0.is_empty() {
            return Err(PkiError::NoSignerInfo);
        }
        let mut signer_errors = Vec::new();
        for signer_info in signed_data.signer_infos.0.iter() {
            match verify_signer(
                &self.root_cert,
                &signed_data,
                &content,
                &embedded_certs,
                signer_info,
            ) {
                Ok(result) => return Ok(result),
                Err(error) => signer_errors.push(error.to_string()),
            }
        }
        Err(PkiError::SignatureVerification(format!(
            "none of {} signer infos verified: {}",
            signer_errors.len(),
            signer_errors.join("; ")
        )))
    }

    /// Verify a DER-encoded CMS signature and check that the content matches expected
    /// data.
    pub fn verify_content(&self, cms_der: &[u8], expected_content: &[u8]) -> PkiResult<()> {
        let result = self.verify(cms_der)?;
        if result.content != expected_content {
            return Err(PkiError::ContentMismatch);
        }
        Ok(())
    }
}

fn verify_signer(
    root_cert: &Certificate,
    signed_data: &SignedData,
    content: &[u8],
    embedded_certs: &[Certificate],
    signer_info: &cms::signed_data::SignerInfo,
) -> PkiResult<VerificationResult> {
    let signer_cert = find_signer_certificate(embedded_certs, &signer_info.sid)?;

    let signer_cert_der = signer_cert
        .to_der()
        .map_err(|e| PkiError::DerParse(e.to_string()))?;

    validate_end_entity_key_usage(signer_cert)?;
    let chain_der = validate_certificate_chain(&signer_cert_der, embedded_certs, root_cert)?;

    // RFC 5652 Section 5.3: The digest algorithm used by the signer should be
    // among those listed in the SignedData digestAlgorithms set.
    if !signed_data
        .digest_algorithms
        .iter()
        .any(|alg| alg.oid == signer_info.digest_alg.oid)
    {
        return Err(PkiError::InvalidCms(
            "signer digest algorithm not listed in SignedData digestAlgorithms".to_owned(),
        ));
    }

    if let Some(signed_attrs) = &signer_info.signed_attrs {
        // RFC 5652 Section 5.6: if signed attributes are present, the content-type
        // attribute value MUST match SignedData encapContentInfo eContentType.
        verify_content_type_attribute(signed_attrs, signed_data.encap_content_info.econtent_type)
            .map_err(PkiError::InvalidCms)?;
    } else {
        // RFC 5652 Section 5.3: signed attributes MUST be present if
        // eContentType is anything other than id-data.
        if signed_data.encap_content_info.econtent_type != ID_DATA {
            return Err(PkiError::InvalidCms(
                "signed attributes are required when eContentType is not id-data".to_owned(),
            ));
        }
    }

    verify_cms_signature(content, signer_info, signer_cert)?;

    let signing_time = signer_info
        .signed_attrs
        .as_ref()
        .and_then(extract_signing_time_attribute);

    Ok(VerificationResult {
        content: content.to_vec(),
        signer_certificate: signer_cert_der,
        certificate_chain: chain_der,
        signing_time,
    })
}

/// Result of successful CMS verification.
#[derive(Debug)]
pub struct VerificationResult {
    /// The extracted encapsulated content.
    pub content: Vec<u8>,
    /// The signer certificate (DER-encoded).
    pub signer_certificate: Vec<u8>,
    /// The certificate chain from signer to root (inclusive, DER-encoded).
    pub certificate_chain: Vec<Vec<u8>>,
    /// The claimed signing time from the signing-time attribute, if present.
    pub signing_time: Option<SystemTime>,
}

/// Extract all certificates from a SignedData structure.
fn extract_certificates(signed_data: &SignedData) -> PkiResult<Vec<Certificate>> {
    let certs_opt = signed_data.certificates.as_ref();
    let Some(certs) = certs_opt else {
        return Err(PkiError::NoCertificates);
    };

    let mut certificates = Vec::new();
    for cert_choice in certs.0.iter() {
        match cert_choice {
            CertificateChoices::Certificate(cert) => {
                let cert_der = cert
                    .to_der()
                    .map_err(|e| PkiError::CertificateParse(e.to_string()))?;
                let parsed_cert = Certificate::from_der(&cert_der)
                    .map_err(|e| PkiError::CertificateParse(e.to_string()))?;
                certificates.push(parsed_cert);
            }
            _ => continue,
        }
    }

    if certificates.is_empty() {
        return Err(PkiError::NoCertificates);
    }

    Ok(certificates)
}

/// Find the signer certificate from the embedded certificates.
fn find_signer_certificate<'a>(
    certificates: &'a [Certificate],
    signer_id: &SignerIdentifier,
) -> PkiResult<&'a Certificate> {
    match signer_id {
        SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial) => {
            for cert in certificates {
                if cert.tbs_certificate.issuer == issuer_and_serial.issuer
                    && cert.tbs_certificate.serial_number == issuer_and_serial.serial_number
                {
                    return Ok(cert);
                }
            }
            Err(PkiError::ChainValidation(
                "signer certificate not found in embedded certificates".into(),
            ))
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            for cert in certificates {
                let cert_ski = cert
                    .tbs_certificate
                    .get::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
                    .map_err(|error| PkiError::CertificateParse(error.to_string()))?;
                if cert_ski.is_some_and(|(_, cert_ski)| cert_ski.0 == ski.0) {
                    return Ok(cert);
                }
            }
            Err(PkiError::ChainValidation(
                "signer certificate matching SubjectKeyIdentifier not found".into(),
            ))
        }
    }
}

/// Build the certificate chain from signer to root.
fn validate_certificate_chain(
    signer_cert_der: &[u8],
    embedded_certs: &[Certificate],
    root_cert: &Certificate,
) -> PkiResult<Vec<Vec<u8>>> {
    let root_der = root_cert
        .to_der()
        .map_err(|e| PkiError::DerParse(e.to_string()))?;

    let root_cert_der = CertificateDer::from_slice(&root_der);
    let trust_anchor = anchor_from_trusted_cert(&root_cert_der)
        .map_err(|e| PkiError::ChainValidation(format!("invalid trust anchor: {e:?}")))?;

    let signer_cert_der = CertificateDer::from_slice(signer_cert_der);
    let end_entity = EndEntityCert::try_from(&signer_cert_der)
        .map_err(|e| PkiError::ChainValidation(format!("invalid signer certificate: {e:?}")))?;

    let intermediates_der = collect_intermediate_certs(embedded_certs, signer_cert_der.as_ref())?;
    let intermediate_refs: Vec<CertificateDer<'_>> = intermediates_der
        .iter()
        .map(|der| CertificateDer::from_slice(der))
        .collect();

    let time = UnixTime::now();

    let usage = webpki::KeyUsage::required_if_present(
        const_oid::db::rfc5280::ID_KP_CODE_SIGNING.as_bytes(),
    );

    let trust_anchors = [trust_anchor];
    let verified_path = end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &intermediate_refs,
            time,
            usage,
            None,
            None,
        )
        .map_err(|e| PkiError::ChainValidation(format!("chain validation failed: {e:?}")))?;

    let mut chain = Vec::new();
    chain.push(signer_cert_der.to_vec());

    for intermediate in verified_path.intermediate_certificates() {
        chain.push(intermediate.der().as_ref().to_vec());
    }

    chain.push(root_der);

    Ok(chain)
}

/// Collect intermediate certificates from the embedded certificates.
fn collect_intermediate_certs(
    embedded_certs: &[Certificate],
    signer_cert_der: &[u8],
) -> PkiResult<Vec<Vec<u8>>> {
    let mut intermediates = Vec::new();
    for cert in embedded_certs {
        let der = cert
            .to_der()
            .map_err(|e| PkiError::DerParse(e.to_string()))?;
        if der == signer_cert_der {
            continue;
        }
        if is_ca_certificate(cert)? {
            intermediates.push(der);
        }
    }
    Ok(intermediates)
}

/// Check if a certificate is a CA certificate.
fn is_ca_certificate(cert: &Certificate) -> PkiResult<bool> {
    match cert.tbs_certificate.get::<BasicConstraints>() {
        Ok(Some((_, constraints))) => Ok(constraints.ca),
        Ok(None) => Ok(false),
        Err(e) => Err(PkiError::ChainValidation(format!(
            "failed to decode basic constraints: {e}"
        ))),
    }
}

/// Validate that the end-entity certificate is valid for digital signatures.
fn validate_end_entity_key_usage(cert: &Certificate) -> PkiResult<()> {
    match cert.tbs_certificate.get::<X509KeyUsage>() {
        Ok(Some((_critical, usage))) => {
            if !usage.digital_signature() {
                return Err(PkiError::ChainValidation(
                    "end-entity certificate not valid for digital signatures".into(),
                ));
            }
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(e) => Err(PkiError::ChainValidation(format!(
            "failed to decode key usage: {e}"
        ))),
    }
}

/// Verify the CMS signature on the content.
///
/// This handles both cases:
///
/// - Without signed attributes: signature is over the content directly
/// - With signed attributes: signature is over the DER-encoded signed attributes
fn verify_cms_signature(
    content: &[u8],
    signer_info: &cms::signed_data::SignerInfo,
    signer_cert: &Certificate,
) -> PkiResult<()> {
    let signature_bytes = signer_info.signature.as_bytes();
    let sig_alg = &signer_info.signature_algorithm.oid;
    let digest_alg = &signer_info.digest_alg.oid;

    let signer_spki = &signer_cert.tbs_certificate.subject_public_key_info;
    let public_key_der = signer_spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| PkiError::SignatureVerification("public key has unused bits".into()))?;

    let data_to_verify = if let Some(signed_attrs) = &signer_info.signed_attrs {
        // When signed attributes are present, the signature is over the DER encoding
        // of the signed attributes as a SET (not the IMPLICIT [0] used in the CMS structure)
        let content_digest = compute_digest(content, digest_alg).ok_or_else(|| {
            PkiError::SignatureVerification(format!("unsupported digest algorithm: {}", digest_alg))
        })?;

        verify_message_digest_attribute(signed_attrs, &content_digest)
            .map_err(PkiError::SignatureVerification)?;

        encode_signed_attrs_as_set(signed_attrs).map_err(PkiError::SignatureVerification)?
    } else {
        content.to_vec()
    };

    verify_signature_with_algorithm_params(
        &data_to_verify,
        signature_bytes,
        public_key_der,
        sig_alg,
        signer_spki,
        signer_info.signature_algorithm.parameters.as_ref(),
    )
    .map_err(PkiError::SignatureVerification)
}

/// Verify the message-digest attribute matches the content digest.
fn verify_message_digest_attribute(
    signed_attrs: &cms::signed_data::SignedAttributes,
    expected_digest: &[u8],
) -> Result<(), String> {
    let mut found = false;
    for attr in signed_attrs.iter() {
        if attr.oid == ID_MESSAGE_DIGEST {
            if found {
                return Err("message-digest attribute appears multiple times".to_owned());
            }
            // RFC 5652 Section 11.2: there MUST be a single attribute value.
            if attr.values.len() != 1 {
                return Err(format!(
                    "message-digest attribute must have exactly one value, got {}",
                    attr.values.len()
                ));
            }
            let digest = attr
                .values
                .iter()
                .next()
                .unwrap()
                .decode_as::<OctetString>()
                .map_err(|_| "message-digest attribute has invalid format".to_owned())?;
            if digest.as_bytes() != expected_digest {
                return Err("message-digest attribute does not match content".to_owned());
            }
            found = true;
        }
    }
    if found {
        Ok(())
    } else {
        Err("message-digest attribute not found in signed attributes".to_owned())
    }
}

/// Verify the content-type attribute matches the expected content type.
fn verify_content_type_attribute(
    signed_attrs: &cms::signed_data::SignedAttributes,
    expected_content_type: ObjectIdentifier,
) -> Result<(), String> {
    let mut found = false;
    for attr in signed_attrs.iter() {
        if attr.oid == ID_CONTENT_TYPE {
            if found {
                return Err("content-type attribute appears multiple times".into());
            }
            // RFC 5652 Section 11.1: there MUST be a single attribute value.
            if attr.values.len() != 1 {
                return Err(format!(
                    "content-type attribute must have exactly one value, got {}",
                    attr.values.len()
                ));
            }
            let oid = attr
                .values
                .iter()
                .next()
                .unwrap()
                .decode_as::<ObjectIdentifier>()
                .map_err(|_| "content-type attribute has invalid format".to_owned())?;
            if oid != expected_content_type {
                return Err("content-type attribute does not match".into());
            }
            found = true;
        }
    }
    if found {
        Ok(())
    } else {
        Err("content-type attribute not found in signed attributes".into())
    }
}

/// Extract the signing-time attribute value from signed attributes, if present.
///
/// Handles both UTCTime and GeneralizedTime encodings per RFC 5652 Section 11.3.
fn extract_signing_time_attribute(
    signed_attrs: &cms::signed_data::SignedAttributes,
) -> Option<SystemTime> {
    for attr in signed_attrs.iter() {
        if attr.oid == ID_SIGNING_TIME {
            for value in attr.values.iter() {
                if let Ok(utc_time) = value.decode_as::<UtcTime>() {
                    return Some(utc_time.to_system_time());
                }
                if let Ok(gen_time) = value.decode_as::<GeneralizedTime>() {
                    return Some(gen_time.to_system_time());
                }
            }
        }
    }
    None
}

/// Re-encode signed attributes as a SET instead of IMPLICIT [0].
///
/// CMS encodes signed attributes with IMPLICIT [0] tag (0xA0), but signatures
/// are computed over the SET encoding (0x31 tag).
fn encode_signed_attrs_as_set(
    signed_attrs: &cms::signed_data::SignedAttributes,
) -> Result<Vec<u8>, String> {
    let original_der = signed_attrs
        .to_der()
        .map_err(|e| format!("failed to encode signed attrs: {}", e))?;

    let mut result = original_der;
    if !result.is_empty() && result[0] == 0xA0 {
        result[0] = Tag::Set.into();
    }

    Ok(result)
}

/// Verify a signature using the appropriate algorithm, with optional signature algorithm
/// parameters.
fn verify_signature_with_algorithm_params(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
    sig_alg_oid: &ObjectIdentifier,
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    sig_alg_params: Option<&der::Any>,
) -> Result<(), String> {
    let key_alg = &spki.algorithm.oid;

    if *key_alg == ID_EC_PUBLIC_KEY {
        let params = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or("missing EC parameters")?;

        let curve_oid = params
            .decode_as::<ObjectIdentifier>()
            .map_err(|e| format!("invalid EC parameters: {}", e))?;

        if curve_oid == const_oid::db::rfc5912::SECP_256_R_1 {
            if *sig_alg_oid != ECDSA_WITH_SHA_256 {
                return Err(format!(
                    "algorithm mismatch: P-256 key with {} signature",
                    sig_alg_oid
                ));
            }
            let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key);
            key.verify(data, signature)
                .map_err(|e| format!("ECDSA P-256 verification failed: {}", e))
        } else if curve_oid == const_oid::db::rfc5912::SECP_384_R_1 {
            if *sig_alg_oid != ECDSA_WITH_SHA_384 {
                return Err(format!(
                    "algorithm mismatch: P-384 key with {} signature",
                    sig_alg_oid
                ));
            }
            let key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, public_key);
            key.verify(data, signature)
                .map_err(|e| format!("ECDSA P-384 verification failed: {}", e))
        } else {
            Err(format!("unsupported EC curve: {}", curve_oid))
        }
    } else if *key_alg == RSA_ENCRYPTION {
        let algorithm: &dyn aws_lc_rs::signature::VerificationAlgorithm =
            if *sig_alg_oid == SHA_256_WITH_RSA_ENCRYPTION {
                &RSA_PKCS1_2048_8192_SHA256
            } else if *sig_alg_oid == SHA_384_WITH_RSA_ENCRYPTION {
                &RSA_PKCS1_2048_8192_SHA384
            } else if *sig_alg_oid == SHA_512_WITH_RSA_ENCRYPTION {
                &RSA_PKCS1_2048_8192_SHA512
            } else if *sig_alg_oid == ID_RSASSA_PSS {
                determine_rsa_pss_algorithm(sig_alg_params)?
            } else {
                return Err(format!(
                    "unsupported RSA signature algorithm: {}",
                    sig_alg_oid
                ));
            };

        // RSA verification requires the full SPKI DER, not just the key bytes.
        let spki_der = spki
            .to_der()
            .map_err(|e| format!("failed to encode SPKI: {}", e))?;
        let key = UnparsedPublicKey::new(algorithm, &spki_der);
        key.verify(data, signature)
            .map_err(|e| format!("RSA verification failed: {}", e))
    } else if *key_alg == ID_ED25519 {
        if *sig_alg_oid != ID_ED25519 {
            return Err(format!(
                "algorithm mismatch: Ed25519 key with {} signature",
                sig_alg_oid
            ));
        }
        let key = UnparsedPublicKey::new(&ED25519, public_key);
        key.verify(data, signature)
            .map_err(|e| format!("Ed25519 verification failed: {}", e))
    } else {
        Err(format!("unsupported key algorithm: {}", key_alg))
    }
}

/// Determine the RSA-PSS verification algorithm from signature algorithm parameters.
///
/// RSA-PSS parameters (RFC 4055) encode the hash algorithm. We use a simple heuristic
/// of searching for hash algorithm OIDs in the DER-encoded parameters, falling back
/// to SHA-256 if parameters are missing or unparseable.
fn determine_rsa_pss_algorithm(
    sig_alg_params: Option<&der::Any>,
) -> Result<&'static dyn aws_lc_rs::signature::VerificationAlgorithm, String> {
    let params = sig_alg_params.ok_or("missing RSA-PSS parameters")?;
    let pss_params = params
        .decode_as::<RsaPssParams>()
        .map_err(|e| format!("failed to decode RSA-PSS parameters: {e}"))?;

    let hash_oid = extract_pss_hash_oid(pss_params.hash_algorithm.as_ref())?;
    let mgf_oid = extract_pss_mgf_hash_oid(pss_params.mask_gen_algorithm.as_ref())?;

    if hash_oid != mgf_oid {
        return Err("RSA-PSS parameters require matching hash and MGF1 hash".into());
    }

    let salt_length = pss_params
        .salt_length
        .ok_or("RSA-PSS parameters missing salt length")?;

    let (expected_salt_len, algorithm) = if hash_oid == ID_SHA_256 {
        (32u8, &RSA_PSS_2048_8192_SHA256)
    } else if hash_oid == ID_SHA_384 {
        (48u8, &RSA_PSS_2048_8192_SHA384)
    } else if hash_oid == ID_SHA_512 {
        (64u8, &RSA_PSS_2048_8192_SHA512)
    } else {
        return Err(format!("unsupported RSA-PSS hash algorithm: {}", hash_oid));
    };

    if salt_length != expected_salt_len {
        return Err(format!("unsupported RSA-PSS salt length: {}", salt_length));
    }

    if let Some(trailer) = pss_params.trailer_field
        && trailer != 1
    {
        return Err(format!("unsupported RSA-PSS trailer field: {}", trailer));
    }

    Ok(algorithm)
}

/// Extract the hash OID from the hash algorithm in RSA-PSS.
fn extract_pss_hash_oid(
    hash_alg: Option<&spki::AlgorithmIdentifierOwned>,
) -> Result<ObjectIdentifier, String> {
    let alg = hash_alg.ok_or("RSA-PSS parameters missing hash algorithm")?;
    let params = alg
        .parameters
        .as_ref()
        .ok_or("RSA-PSS hash algorithm parameters missing")?;
    if params.tag() != Tag::Null {
        return Err("RSA-PSS hash algorithm parameters must be NULL".into());
    }
    Ok(alg.oid)
}

/// Extract the hash OID from the MGF1 parameters in RSA-PSS.
fn extract_pss_mgf_hash_oid(
    mgf_alg: Option<&spki::AlgorithmIdentifierOwned>,
) -> Result<ObjectIdentifier, String> {
    let mgf = mgf_alg.ok_or("RSA-PSS parameters missing MGF1")?;
    if mgf.oid != const_oid::db::rfc5912::ID_MGF_1 {
        return Err("RSA-PSS mask generation algorithm must be MGF1".into());
    }
    let params = mgf
        .parameters
        .as_ref()
        .ok_or("RSA-PSS MGF1 parameters missing")?;
    let hash_alg = params
        .decode_as::<spki::AlgorithmIdentifierOwned>()
        .map_err(|e| format!("failed to decode MGF1 hash: {e}"))?;
    extract_pss_hash_oid(Some(&hash_alg))
}
