//! CMS signature creation.

use aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
use aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING;
use aws_lc_rs::signature::EcdsaKeyPair;
use aws_lc_rs::signature::Ed25519KeyPair;
use aws_lc_rs::signature::KeyPair;
use aws_lc_rs::signature::RsaKeyPair;
use cms::cert::CertificateChoices;
use cms::content_info::CmsVersion;
use cms::content_info::ContentInfo;
use cms::signed_data::CertificateSet;
use cms::signed_data::EncapsulatedContentInfo;
use cms::signed_data::SignedData;
use cms::signed_data::SignerIdentifier;
use cms::signed_data::SignerInfo;
use cms::signed_data::SignerInfos;
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
use der::Any;
use der::Decode;
use der::Encode;
use der::Tag;
use der::asn1::OctetString;
use der::asn1::SetOfVec;
use der::asn1::UtcTime;
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_cert::attr::Attribute;

use std::time::SystemTime;
use zeroize::Zeroizing;

use crate::PkiError;
use crate::PkiResult;
use crate::RsaPssParams;
use crate::SignatureAlgorithm;
use crate::compute_digest;
use crate::pem;

/// A CMS signer that can create CMS `SignedData`` structures.
pub struct CmsSigner {
    signing_key: SigningKey,
    signer_cert: Certificate,
    signer_cert_der: Vec<u8>,
    intermediate_certs_der: Vec<Vec<u8>>,
    signing_time: Option<SystemTime>,
}

impl CmsSigner {
    /// Create a new CMS signer from PEM-encoded certificate and private key.
    ///
    /// For RSA keys, this defaults to RSA-PSS with SHA-256.
    ///
    /// Use [`CmsSignerBuilder`] to add intermediate certificates and customize the RSA
    /// signature mode.
    pub fn new(signer_cert_pem: &[u8], private_key_pem: &[u8]) -> PkiResult<Self> {
        CmsSignerBuilder::new(signer_cert_pem, private_key_pem)?.build()
    }

    /// Construct a [`CmsSigner`] from a [`CmsSignerBuilder`].
    fn from_builder(builder: CmsSignerBuilder) -> PkiResult<Self> {
        let signer_cert = Certificate::from_der(&builder.signer_cert_der)
            .map_err(|e| PkiError::CertificateParse(e.to_string()))?;

        let spki = &signer_cert.tbs_certificate.subject_public_key_info;
        let key_algorithm = &spki.algorithm.oid;

        let signing_key = if *key_algorithm == ID_EC_PUBLIC_KEY {
            let params = spki
                .algorithm
                .parameters
                .as_ref()
                .ok_or_else(|| PkiError::PrivateKeyParse("missing EC parameters".into()))?;

            let curve_oid = params
                .decode_as::<ObjectIdentifier>()
                .map_err(|e| PkiError::PrivateKeyParse(format!("invalid EC parameters: {}", e)))?;

            if curve_oid == const_oid::db::rfc5912::SECP_256_R_1 {
                let key =
                    try_parse_ec_key(&builder.private_key_der, &ECDSA_P256_SHA256_ASN1_SIGNING)?;
                SigningKey::EcdsaP256(key)
            } else if curve_oid == const_oid::db::rfc5912::SECP_384_R_1 {
                let key =
                    try_parse_ec_key(&builder.private_key_der, &ECDSA_P384_SHA384_ASN1_SIGNING)?;
                SigningKey::EcdsaP384(key)
            } else {
                return Err(PkiError::UnsupportedKeyAlgorithm(format!(
                    "unsupported EC curve: {}",
                    curve_oid
                )));
            }
        } else if *key_algorithm == RSA_ENCRYPTION {
            let key = RsaKeyPair::from_der(&builder.private_key_der)
                .or_else(|_| RsaKeyPair::from_pkcs8(&builder.private_key_der))
                .map_err(|e| PkiError::PrivateKeyParse(e.to_string()))?;
            SigningKey::Rsa(key, builder.rsa_mode, builder.rsa_hash)
        } else if *key_algorithm == ID_ED25519 {
            let key = Ed25519KeyPair::from_pkcs8(&builder.private_key_der)
                .map_err(|e| PkiError::PrivateKeyParse(e.to_string()))?;
            SigningKey::Ed25519(key)
        } else {
            return Err(PkiError::UnsupportedKeyAlgorithm(format!(
                "unsupported key algorithm: {}",
                key_algorithm
            )));
        };

        let cert_public_key = spki.subject_public_key.raw_bytes();
        let key_public_key = signing_key.public_key_bytes();
        if cert_public_key != key_public_key {
            return Err(PkiError::KeyMismatch);
        }

        Ok(Self {
            signing_key,
            signer_cert,
            signer_cert_der: builder.signer_cert_der,
            intermediate_certs_der: builder.intermediate_certs,
            signing_time: builder.signing_time,
        })
    }

    /// Get the signature algorithm used by this signer.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.signing_key.algorithm()
    }

    /// Sign data and create a CMS `SignedData` structure.
    ///
    /// The data is embedded in the CMS structure.
    ///
    /// Returns the DER-encoded CMS `ContentInfo` with the signed data.
    pub fn sign(&self, data: &[u8]) -> PkiResult<Vec<u8>> {
        let (digest_algorithm, signature_algorithm) = self.get_algorithm_identifiers()?;

        let econtent = OctetString::new(data)
            .map_err(|e| PkiError::SigningFailed(format!("failed to create OctetString: {}", e)))?;
        let econtent_any =
            Any::from_der(&econtent.to_der().map_err(|e| {
                PkiError::SigningFailed(format!("failed to encode content: {}", e))
            })?)
            .map_err(|e| PkiError::SigningFailed(format!("failed to create Any: {}", e)))?;

        let encap_content_info = EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: Some(econtent_any),
        };

        let signing_time = self.signing_time.unwrap_or_else(SystemTime::now);
        let signed_attrs = build_signed_attributes(data, digest_algorithm.oid, signing_time)?;
        let signed_attrs_der = encode_signed_attrs_for_signature(&signed_attrs)?;

        let signature = self.create_signature(&signed_attrs_der)?;

        let issuer_and_serial = cms::cert::IssuerAndSerialNumber {
            issuer: self.signer_cert.tbs_certificate.issuer.clone(),
            serial_number: self.signer_cert.tbs_certificate.serial_number.clone(),
        };

        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial),
            digest_alg: digest_algorithm.clone(),
            signed_attrs: Some(signed_attrs),
            signature_algorithm: signature_algorithm.clone(),
            signature: OctetString::new(signature).map_err(|e| {
                PkiError::SigningFailed(format!("failed to create signature OctetString: {}", e))
            })?,
            unsigned_attrs: None,
        };

        let mut certs = Vec::new();

        let signer_cert_any = Any::from_der(&self.signer_cert_der)
            .map_err(|e| PkiError::SigningFailed(format!("failed to parse signer cert: {}", e)))?;
        certs.push(CertificateChoices::Certificate(
            signer_cert_any
                .decode_as()
                .map_err(|e| PkiError::SigningFailed(format!("failed to decode cert: {}", e)))?,
        ));

        for cert_der in &self.intermediate_certs_der {
            let cert_any = Any::from_der(cert_der)
                .map_err(|e| PkiError::SigningFailed(format!("failed to parse cert: {}", e)))?;
            certs.push(CertificateChoices::Certificate(
                cert_any.decode_as().map_err(|e| {
                    PkiError::SigningFailed(format!("failed to decode cert: {}", e))
                })?,
            ));
        }

        let mut digest_algorithms = SetOfVec::new();
        digest_algorithms
            .insert(digest_algorithm)
            .map_err(|e| PkiError::SigningFailed(format!("failed to insert digest alg: {}", e)))?;

        let mut signer_infos_set = SetOfVec::new();
        signer_infos_set
            .insert(signer_info)
            .map_err(|e| PkiError::SigningFailed(format!("failed to insert signer info: {}", e)))?;

        let mut certs_set: SetOfVec<CertificateChoices> = SetOfVec::new();
        for cert in certs {
            certs_set
                .insert(cert)
                .map_err(|e| PkiError::SigningFailed(format!("failed to insert cert: {}", e)))?;
        }

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms,
            encap_content_info,
            certificates: Some(CertificateSet::from(certs_set)),
            crls: None,
            signer_infos: SignerInfos::from(signer_infos_set),
        };

        let signed_data_der = signed_data
            .to_der()
            .map_err(|e| PkiError::SigningFailed(format!("failed to encode SignedData: {}", e)))?;

        let content_info = ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::from_der(&signed_data_der)
                .map_err(|e| PkiError::SigningFailed(format!("failed to create Any: {}", e)))?,
        };

        content_info
            .to_der()
            .map_err(|e| PkiError::SigningFailed(format!("failed to encode ContentInfo: {}", e)))
    }

    fn get_algorithm_identifiers(
        &self,
    ) -> PkiResult<(AlgorithmIdentifierOwned, AlgorithmIdentifierOwned)> {
        match &self.signing_key {
            SigningKey::EcdsaP256(_) => Ok((
                AlgorithmIdentifierOwned {
                    oid: ID_SHA_256,
                    parameters: None,
                },
                AlgorithmIdentifierOwned {
                    oid: ECDSA_WITH_SHA_256,
                    parameters: None,
                },
            )),
            SigningKey::EcdsaP384(_) => Ok((
                AlgorithmIdentifierOwned {
                    oid: ID_SHA_384,
                    parameters: None,
                },
                AlgorithmIdentifierOwned {
                    oid: ECDSA_WITH_SHA_384,
                    parameters: None,
                },
            )),
            SigningKey::Rsa(_, mode, hash) => {
                let (digest_oid, hash_len) = match hash {
                    RsaHashAlgorithm::Sha256 => (ID_SHA_256, 32u8),
                    RsaHashAlgorithm::Sha384 => (ID_SHA_384, 48u8),
                    RsaHashAlgorithm::Sha512 => (ID_SHA_512, 64u8),
                };

                let digest_algorithm = AlgorithmIdentifierOwned {
                    oid: digest_oid,
                    parameters: None,
                };

                let signature_algorithm = match mode {
                    RsaSignatureMode::Pkcs1v15 => {
                        let sig_oid = match hash {
                            RsaHashAlgorithm::Sha256 => SHA_256_WITH_RSA_ENCRYPTION,
                            RsaHashAlgorithm::Sha384 => {
                                const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION
                            }
                            RsaHashAlgorithm::Sha512 => {
                                const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION
                            }
                        };
                        AlgorithmIdentifierOwned {
                            oid: sig_oid,
                            parameters: Some(Any::null()),
                        }
                    }
                    RsaSignatureMode::Pss => {
                        let pss_params = build_rsa_pss_params(digest_oid, hash_len)?;
                        AlgorithmIdentifierOwned {
                            oid: ID_RSASSA_PSS,
                            parameters: Some(pss_params),
                        }
                    }
                };

                Ok((digest_algorithm, signature_algorithm))
            }
            SigningKey::Ed25519(_) => {
                // Ed25519 uses SHA-512 internally but for CMS, we use a placeholder digest
                // algorithm since Ed25519 is a "pure" signature scheme that doesn't separate
                // hashing from signing. RFC 8419 specifies using id-sha512 as the digest
                // algorithm for EdDSA in CMS.
                Ok((
                    AlgorithmIdentifierOwned {
                        oid: ID_SHA_512,
                        parameters: None,
                    },
                    AlgorithmIdentifierOwned {
                        oid: ID_ED25519,
                        parameters: None,
                    },
                ))
            }
        }
    }

    fn create_signature(&self, data: &[u8]) -> PkiResult<Vec<u8>> {
        let rng = aws_lc_rs::rand::SystemRandom::new();

        match &self.signing_key {
            SigningKey::EcdsaP256(key) => {
                let sig = key
                    .sign(&rng, data)
                    .map_err(|e| PkiError::SigningFailed(e.to_string()))?;
                Ok(sig.as_ref().to_vec())
            }
            SigningKey::EcdsaP384(key) => {
                let sig = key
                    .sign(&rng, data)
                    .map_err(|e| PkiError::SigningFailed(e.to_string()))?;
                Ok(sig.as_ref().to_vec())
            }
            SigningKey::Rsa(key, mode, hash) => {
                let mut signature = vec![0u8; key.public_key().modulus_len()];
                let padding = match (mode, hash) {
                    (RsaSignatureMode::Pkcs1v15, RsaHashAlgorithm::Sha256) => {
                        &aws_lc_rs::signature::RSA_PKCS1_SHA256
                    }
                    (RsaSignatureMode::Pkcs1v15, RsaHashAlgorithm::Sha384) => {
                        &aws_lc_rs::signature::RSA_PKCS1_SHA384
                    }
                    (RsaSignatureMode::Pkcs1v15, RsaHashAlgorithm::Sha512) => {
                        &aws_lc_rs::signature::RSA_PKCS1_SHA512
                    }
                    (RsaSignatureMode::Pss, RsaHashAlgorithm::Sha256) => {
                        &aws_lc_rs::signature::RSA_PSS_SHA256
                    }
                    (RsaSignatureMode::Pss, RsaHashAlgorithm::Sha384) => {
                        &aws_lc_rs::signature::RSA_PSS_SHA384
                    }
                    (RsaSignatureMode::Pss, RsaHashAlgorithm::Sha512) => {
                        &aws_lc_rs::signature::RSA_PSS_SHA512
                    }
                };
                key.sign(padding, &rng, data, &mut signature)
                    .map_err(|e| PkiError::SigningFailed(e.to_string()))?;
                Ok(signature)
            }
            SigningKey::Ed25519(key) => {
                let sig = key.sign(data);
                Ok(sig.as_ref().to_vec())
            }
        }
    }
}

/// OID for RSA-PSS signature algorithm (1.2.840.113549.1.1.10).
const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// OID for MGF1 (1.2.840.113549.1.1.8).
const ID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");

/// OID for Ed25519 (1.3.101.112).
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// OID for signing-time attribute (1.2.840.113549.1.9.5) — RFC 5652 Section 11.3.
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

/// RSA signature mode for RSA keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RsaSignatureMode {
    /// PKCS#1 v1.5 padding.
    Pkcs1v15,
    /// PSS padding (default).
    #[default]
    Pss,
}

/// Hash algorithm for RSA signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RsaHashAlgorithm {
    /// SHA-256.
    #[default]
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// A builder for creating CMS signers.
pub struct CmsSignerBuilder {
    signer_cert_der: Vec<u8>,
    private_key_der: Zeroizing<Vec<u8>>,
    intermediate_certs: Vec<Vec<u8>>,
    rsa_mode: RsaSignatureMode,
    rsa_hash: RsaHashAlgorithm,
    signing_time: Option<SystemTime>,
}

impl CmsSignerBuilder {
    /// Create a new signer builder with the signer certificate and private key.
    ///
    /// Both the certificate and key must be PEM-encoded.
    pub fn new(signer_cert_pem: &[u8], private_key_pem: &[u8]) -> PkiResult<Self> {
        let signer_cert_der = pem::parse(signer_cert_pem, "CERTIFICATE")?;
        let (_, private_key_der) = pem::parse_any(
            private_key_pem,
            &["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"],
        )?;
        Ok(Self {
            signer_cert_der,
            private_key_der,
            intermediate_certs: Vec::new(),
            rsa_mode: RsaSignatureMode::default(),
            rsa_hash: RsaHashAlgorithm::default(),
            signing_time: None,
        })
    }

    /// Add an intermediate certificate to include in the signature.
    ///
    /// The certificate must be PEM-encoded.
    pub fn with_intermediate_cert(mut self, cert_pem: &[u8]) -> PkiResult<Self> {
        let cert_der = pem::parse(cert_pem, "CERTIFICATE")?;
        self.intermediate_certs.push(cert_der);
        Ok(self)
    }

    /// Set the RSA signature mode (PKCS#1 v1.5 or PSS).
    ///
    /// This only affects RSA keys; ECDSA keys ignore this setting.
    ///
    /// Default is PSS.
    pub fn with_rsa_mode(mut self, mode: RsaSignatureMode) -> Self {
        self.rsa_mode = mode;
        self
    }

    /// Set the hash algorithm for RSA signatures.
    ///
    /// This only affects RSA keys; ECDSA keys use the hash algorithm
    /// determined by the curve (SHA-256 for P-256, SHA-384 for P-384).
    ///
    /// Default is SHA-256.
    pub fn with_rsa_hash(mut self, hash: RsaHashAlgorithm) -> Self {
        self.rsa_hash = hash;
        self
    }

    /// Set a fixed signing time to include in the signed attributes.
    ///
    /// By default, each call to [`CmsSigner::sign`] uses the current system time.
    pub fn with_signing_time(mut self, time: SystemTime) -> Self {
        self.signing_time = Some(time);
        self
    }

    /// Build the CMS signer.
    pub fn build(self) -> PkiResult<CmsSigner> {
        CmsSigner::from_builder(self)
    }
}

/// Represents a signing key that can create signatures.
enum SigningKey {
    EcdsaP256(EcdsaKeyPair),
    EcdsaP384(EcdsaKeyPair),
    Rsa(RsaKeyPair, RsaSignatureMode, RsaHashAlgorithm),
    Ed25519(Ed25519KeyPair),
}

impl SigningKey {
    /// Get the public key bytes derived from the private key.
    fn public_key_bytes(&self) -> &[u8] {
        match self {
            SigningKey::EcdsaP256(key) => key.public_key().as_ref(),
            SigningKey::EcdsaP384(key) => key.public_key().as_ref(),
            SigningKey::Rsa(key, _, _) => key.public_key().as_ref(),
            SigningKey::Ed25519(key) => key.public_key().as_ref(),
        }
    }

    /// Get the signature algorithm for this key.
    fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            SigningKey::EcdsaP256(_) => SignatureAlgorithm::EcdsaP256Sha256,
            SigningKey::EcdsaP384(_) => SignatureAlgorithm::EcdsaP384Sha384,
            SigningKey::Rsa(_, mode, hash) => match (mode, hash) {
                (RsaSignatureMode::Pkcs1v15, RsaHashAlgorithm::Sha256) => {
                    SignatureAlgorithm::RsaPkcs1Sha256
                }
                (RsaSignatureMode::Pkcs1v15, RsaHashAlgorithm::Sha384) => {
                    SignatureAlgorithm::RsaPkcs1Sha384
                }
                (RsaSignatureMode::Pkcs1v15, RsaHashAlgorithm::Sha512) => {
                    SignatureAlgorithm::RsaPkcs1Sha512
                }
                (RsaSignatureMode::Pss, RsaHashAlgorithm::Sha256) => {
                    SignatureAlgorithm::RsaPssSha256
                }
                (RsaSignatureMode::Pss, RsaHashAlgorithm::Sha384) => {
                    SignatureAlgorithm::RsaPssSha384
                }
                (RsaSignatureMode::Pss, RsaHashAlgorithm::Sha512) => {
                    SignatureAlgorithm::RsaPssSha512
                }
            },
            SigningKey::Ed25519(_) => SignatureAlgorithm::Ed25519,
        }
    }
}

fn encode_signed_attrs_for_signature(
    signed_attrs: &cms::signed_data::SignedAttributes,
) -> PkiResult<Vec<u8>> {
    let mut der = signed_attrs
        .to_der()
        .map_err(|e| PkiError::SigningFailed(format!("failed to encode signed attrs: {}", e)))?;

    if !der.is_empty() {
        der[0] = Tag::Set.into();
    }

    Ok(der)
}

fn build_signed_attributes(
    content: &[u8],
    digest_oid: ObjectIdentifier,
    signing_time: SystemTime,
) -> PkiResult<cms::signed_data::SignedAttributes> {
    let digest = compute_digest(content, &digest_oid).ok_or_else(|| {
        PkiError::SigningFailed(format!("unsupported digest algorithm: {}", digest_oid))
    })?;

    let content_type_any = Any::from_der(&ID_DATA.to_der().map_err(|e| {
        PkiError::SigningFailed(format!("failed to encode content-type OID: {}", e))
    })?)
    .map_err(|e| PkiError::SigningFailed(format!("failed to create content-type Any: {}", e)))?;

    let mut content_type_values = SetOfVec::new();
    content_type_values.insert(content_type_any).map_err(|e| {
        PkiError::SigningFailed(format!("failed to insert content-type value: {}", e))
    })?;

    let content_type_attr = Attribute {
        oid: ID_CONTENT_TYPE,
        values: content_type_values,
    };

    let digest_octet = OctetString::new(digest.clone()).map_err(|e| {
        PkiError::SigningFailed(format!("failed to create digest OctetString: {}", e))
    })?;
    let digest_any = Any::from_der(
        &digest_octet
            .to_der()
            .map_err(|e| PkiError::SigningFailed(format!("failed to encode digest: {}", e)))?,
    )
    .map_err(|e| PkiError::SigningFailed(format!("failed to create digest Any: {}", e)))?;

    let mut digest_values = SetOfVec::new();
    digest_values
        .insert(digest_any)
        .map_err(|e| PkiError::SigningFailed(format!("failed to insert digest value: {}", e)))?;

    let digest_attr = Attribute {
        oid: ID_MESSAGE_DIGEST,
        values: digest_values,
    };

    // RFC 5652 Section 11.3: signing-time attribute.
    let utc_time = UtcTime::from_system_time(signing_time)
        .map_err(|e| PkiError::SigningFailed(format!("failed to convert signing time: {}", e)))?;
    let time_any =
        Any::from_der(&utc_time.to_der().map_err(|e| {
            PkiError::SigningFailed(format!("failed to encode signing time: {}", e))
        })?)
        .map_err(|e| {
            PkiError::SigningFailed(format!("failed to create signing-time Any: {}", e))
        })?;

    let mut time_values = SetOfVec::new();
    time_values.insert(time_any).map_err(|e| {
        PkiError::SigningFailed(format!("failed to insert signing-time value: {}", e))
    })?;

    let signing_time_attr = Attribute {
        oid: ID_SIGNING_TIME,
        values: time_values,
    };

    let mut attrs = SetOfVec::new();
    attrs.insert(content_type_attr).map_err(|e| {
        PkiError::SigningFailed(format!("failed to insert content-type attribute: {}", e))
    })?;
    attrs.insert(digest_attr).map_err(|e| {
        PkiError::SigningFailed(format!("failed to insert message-digest attribute: {}", e))
    })?;
    attrs.insert(signing_time_attr).map_err(|e| {
        PkiError::SigningFailed(format!("failed to insert signing-time attribute: {}", e))
    })?;

    Ok(attrs)
}

/// Build RSA-PSS algorithm parameters.
fn build_rsa_pss_params(hash_oid: ObjectIdentifier, salt_length: u8) -> PkiResult<Any> {
    let hash_alg = AlgorithmIdentifierOwned {
        oid: hash_oid,
        parameters: Some(Any::null()),
    };

    // MGF1 with the same hash algorithm
    let mgf1_params = hash_alg
        .to_der()
        .map_err(|e| PkiError::SigningFailed(format!("failed to encode MGF1 params: {}", e)))?;
    let mask_gen_alg =
        AlgorithmIdentifierOwned {
            oid: ID_MGF1,
            parameters: Some(Any::from_der(&mgf1_params).map_err(|e| {
                PkiError::SigningFailed(format!("failed to create MGF1 Any: {}", e))
            })?),
        };

    let pss_params = RsaPssParams {
        hash_algorithm: Some(hash_alg),
        mask_gen_algorithm: Some(mask_gen_alg),
        salt_length: Some(salt_length),
        trailer_field: None,
    };

    let params_der = pss_params
        .to_der()
        .map_err(|e| PkiError::SigningFailed(format!("failed to encode PSS params: {}", e)))?;

    Any::from_der(&params_der)
        .map_err(|e| PkiError::SigningFailed(format!("failed to create PSS params Any: {}", e)))
}

/// Try to parse an EC private key in various formats.
fn try_parse_ec_key(
    key_der: &[u8],
    algorithm: &'static aws_lc_rs::signature::EcdsaSigningAlgorithm,
) -> PkiResult<EcdsaKeyPair> {
    if let Ok(key) = EcdsaKeyPair::from_pkcs8(algorithm, key_der) {
        return Ok(key);
    }
    if let Ok(key) = EcdsaKeyPair::from_private_key_der(algorithm, key_der) {
        return Ok(key);
    }
    Err(PkiError::PrivateKeyParse(
        "failed to parse EC private key (tried PKCS#8 and SEC1 formats)".into(),
    ))
}
