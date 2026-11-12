//! Adversarial CMS decoding and signer-certificate policy regressions.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::Decode;
use der::Encode;
use der::asn1::Any;
use der::asn1::OctetString;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rugix_pki::CmsSigner;
use rugix_pki::CmsVerifier;
use rugix_pki::inspect_cms;
use rugix_pki::verify_cms_with_certificate;

/// Issue certificates with independently varied end-entity constraints.
fn pki(ca: bool, eku: Option<ExtendedKeyUsagePurpose>) -> (String, String, String) {
    pki_with_algorithm(ca, eku, &rcgen::PKCS_ECDSA_P256_SHA256)
}

/// Issue a signer using the requested supported key algorithm.
fn pki_with_algorithm(
    ca: bool,
    eku: Option<ExtendedKeyUsagePurpose>,
    algorithm: &'static rcgen::SignatureAlgorithm,
) -> (String, String, String) {
    let root_key = KeyPair::generate().unwrap();
    let mut root = CertificateParams::new(vec!["Root".into()]).unwrap();
    root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let root = root.self_signed(&root_key).unwrap();
    let key = KeyPair::generate_for(algorithm).unwrap();
    let mut signer = CertificateParams::new(vec!["Signer".into()]).unwrap();
    signer.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    if ca {
        signer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        signer.key_usages.push(KeyUsagePurpose::KeyCertSign);
    }
    signer.extended_key_usages = eku.into_iter().collect();
    let signer = signer.signed_by(&key, &root, &root_key).unwrap();
    (root.pem(), signer.pem(), key.serialize_pem())
}

/// Exact-certificate checks enforce end-entity and code-signing usage without chain
/// trust.
#[test]
fn signer_certificate_usage_matches_device() {
    for (ca, eku, accepted) in [
        (false, None, true),
        (false, Some(ExtendedKeyUsagePurpose::CodeSigning), true),
        (false, Some(ExtendedKeyUsagePurpose::ServerAuth), false),
        (true, Some(ExtendedKeyUsagePurpose::CodeSigning), false),
    ] {
        let (root, cert, key) = pki(ca, eku);
        let cms = CmsSigner::new(cert.as_bytes(), key.as_bytes())
            .unwrap()
            .sign(b"metadata")
            .unwrap();
        assert_eq!(
            verify_cms_with_certificate(&cms, cert.as_bytes()).is_ok(),
            accepted
        );
        assert_eq!(
            CmsVerifier::new(root.as_bytes())
                .unwrap()
                .verify(&cms)
                .is_ok(),
            accepted
        );
    }
}

/// ECDSA and Ed25519 parameters must be absent even if signature bytes still verify.
#[test]
fn reject_ecdsa_and_ed25519_signature_parameters() {
    for algorithm in [&rcgen::PKCS_ECDSA_P256_SHA256, &rcgen::PKCS_ED25519] {
        let (root, cert, key) = pki_with_algorithm(false, None, algorithm);
        let cms = CmsSigner::new(cert.as_bytes(), key.as_bytes())
            .unwrap()
            .sign(b"metadata")
            .unwrap();
        for params in [
            Any::null(),
            Any::encode_from(&OctetString::new(vec![1]).unwrap()).unwrap(),
        ] {
            let mut ci = ContentInfo::from_der(&cms).unwrap();
            let mut sd = ci.content.decode_as::<SignedData>().unwrap();
            let mut si = sd.signer_infos.0.iter().next().unwrap().clone();
            si.signature_algorithm.parameters = Some(params);
            sd.signer_infos.0 = [si].try_into().unwrap();
            ci.content = Any::encode_from(&sd).unwrap();
            let modified = ci.to_der().unwrap();
            assert!(
                CmsVerifier::new(root.as_bytes())
                    .unwrap()
                    .verify(&modified)
                    .is_err()
            );
            assert!(verify_cms_with_certificate(&modified, cert.as_bytes()).is_err());
        }
    }
}

/// Opaque collections allow constructing adversarial SET order without sorting it first.
#[derive(der::Sequence)]
struct RawSignedData {
    version: u8,
    digests: Any,
    content: cms::signed_data::EncapsulatedContentInfo,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    certificates: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    crls: Option<Any>,
    signers: Any,
}

/// Reverse-ordered digest sets are rejected before quadratic sorting, even with large
/// content.
#[test]
fn reject_oversized_metadata_before_set_sorting() {
    let (root, cert, _) = pki(false, None);
    let verifier = CmsVerifier::new(root.as_bytes()).unwrap();
    let mut algorithms = (0..3000u32)
        .map(|index| {
            spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ID_SHA_256,
                parameters: Some(
                    Any::encode_from(&OctetString::new(index.to_be_bytes().to_vec()).unwrap())
                        .unwrap(),
                ),
            }
            .to_der()
            .unwrap()
        })
        .collect::<Vec<_>>();
    algorithms.sort();
    algorithms.reverse();
    for content_size in [0, 1024 * 1024] {
        let raw = RawSignedData {
            version: 1,
            digests: Any::new(der::Tag::Set, algorithms.concat()).unwrap(),
            content: cms::signed_data::EncapsulatedContentInfo {
                econtent_type: const_oid::db::rfc5911::ID_DATA,
                econtent: Some(
                    Any::encode_from(&OctetString::new(vec![0; content_size]).unwrap()).unwrap(),
                ),
            },
            certificates: None,
            crls: None,
            signers: Any::new(der::Tag::Set, vec![]).unwrap(),
        };
        let cms = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::encode_from(&raw).unwrap(),
        }
        .to_der()
        .unwrap();
        for error in [
            verifier.verify(&cms).unwrap_err(),
            verify_cms_with_certificate(&cms, cert.as_bytes()).unwrap_err(),
            inspect_cms(&cms).unwrap_err(),
        ] {
            assert!(error.to_string().contains("metadata exceeds"), "{error}");
        }
    }
}

/// Excess signer entries are rejected before cryptographic attempts or error aggregation.
#[test]
fn reject_excess_signer_infos() {
    let (root, cert, key) = pki(false, None);
    let cms = CmsSigner::new(cert.as_bytes(), key.as_bytes())
        .unwrap()
        .sign(b"metadata")
        .unwrap();
    let mut ci = ContentInfo::from_der(&cms).unwrap();
    let mut sd = ci.content.decode_as::<SignedData>().unwrap();
    let original = sd.signer_infos.0.iter().next().unwrap().clone();
    let signers = (0..17)
        .map(|index| {
            let mut signer = original.clone();
            signer.signature = OctetString::new(vec![index; 64]).unwrap();
            signer
        })
        .collect::<Vec<_>>();
    sd.signer_infos.0 = signers.try_into().unwrap();
    ci.content = Any::encode_from(&sd).unwrap();
    let cms = ci.to_der().unwrap();
    assert!(
        CmsVerifier::new(root.as_bytes())
            .unwrap()
            .verify(&cms)
            .unwrap_err()
            .to_string()
            .contains("16 signer")
    );
    assert!(
        inspect_cms(&cms)
            .unwrap_err()
            .to_string()
            .contains("16 signer")
    );
}

/// Only primitive OCTET STRING content is exempt from the metadata budget.
#[test]
fn metadata_budget_exempts_only_primitive_octets() {
    let (root, cert, key) = pki(false, None);
    let content = vec![b'a'; 1024 * 1024];
    let cms = CmsSigner::new(cert.as_bytes(), key.as_bytes())
        .unwrap()
        .sign(&content)
        .unwrap();
    let verifier = CmsVerifier::new(root.as_bytes()).unwrap();
    assert_eq!(verifier.verify(&cms).unwrap().content, content);
    assert_eq!(
        verify_cms_with_certificate(&cms, cert.as_bytes()).unwrap(),
        content
    );
    assert_eq!(inspect_cms(&cms).unwrap().content.unwrap(), content);
    let mut ci = ContentInfo::from_der(&cms).unwrap();
    let mut sd = ci.content.decode_as::<SignedData>().unwrap();
    sd.encap_content_info.econtent = Some(Any::new(der::Tag::Utf8String, content).unwrap());
    ci.content = Any::encode_from(&sd).unwrap();
    let modified = ci.to_der().unwrap();
    assert!(
        verifier
            .verify(&modified)
            .unwrap_err()
            .to_string()
            .contains("metadata exceeds")
    );
    assert!(
        inspect_cms(&modified)
            .unwrap_err()
            .to_string()
            .contains("metadata exceeds")
    );
}
