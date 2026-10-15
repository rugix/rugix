//! Inspect bundle metadata from files, forward streams, or HTTP without installing it.

use reportify::bail;
use reportify::ResultExt;
use rugix_bundle::format;
use rugix_bundle::format::decode::decode_slice;
use rugix_bundle::reader::BundleReader;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;
use tracing::warn;

use crate::components::bundle_component_declarations;
use crate::components::component_output;
use crate::config::bundle::BundleAppArchiveDeliveryOutput;
use crate::config::bundle::BundleAppFileDeliveryOutput;
use crate::config::bundle::BundleComponentOutput;
use crate::config::bundle::BundleDeliveryOutput;
use crate::config::bundle::BundleDeltaInputOutput;
use crate::config::bundle::BundleDeltaOutput;
use crate::config::bundle::BundleExecuteDeliveryOutput;
use crate::config::bundle::BundleInspectOutput;
use crate::config::bundle::BundleManifestOutput;
use crate::config::bundle::BundlePayloadOutput;
use crate::config::bundle::BundleSignatureOutput;
use crate::config::bundle::BundleSlotDeliveryOutput;
use crate::config::bundle::BundleUpdateTypeOutput;
use crate::operations::install::with_bundle_source;
use crate::operations::install::BundleInput;
use crate::operations::install::InstallSource;
use crate::system::SystemResult;

/// Inspect metadata without consulting device configuration or verifying signatures.
#[tracing::instrument(level = "debug", skip_all)]
pub(crate) fn inspect(
    source: InstallSource,
    input: BundleInput,
) -> SystemResult<BundleInspectOutput> {
    with_bundle_source(source, input, |source, _, options| {
        let reader = BundleReader::start_with_options(source, None, options)
            .whatever("unable to read bundle")?;
        inspect_reader(&reader)
    })
    .map(|result| result.output)
}

/// Describe declared payloads using only the bundle header and signatures.
fn inspect_reader(reader: &BundleReader) -> SystemResult<BundleInspectOutput> {
    let manifest =
        reader
            .header()
            .manifest
            .as_deref()
            .and_then(|manifest| match manifest_output(manifest) {
                Ok(manifest) => Some(manifest),
                Err(error) => {
                    warn!(%error, "unable to inspect embedded bundle manifest");
                    None
                }
            });
    let algorithm = reader.header().hash_algorithm;
    let header_hash = reader.header_hash(algorithm);
    let update_type = if reader.header().is_incremental {
        BundleUpdateTypeOutput::Incremental
    } else {
        BundleUpdateTypeOutput::Full
    };
    let components = reader
        .header()
        .components
        .as_ref()
        .map(|components| {
            bundle_component_declarations(components).map(|components| {
                components
                    .into_iter()
                    .map(|(path, component)| {
                        BundleComponentOutput::new(path, component_output(&component))
                    })
                    .collect::<Vec<_>>()
            })
        })
        .transpose()?;
    let signatures = reader
        .signatures()
        .map(|signatures| {
            signatures
                .cms_signatures
                .iter()
                .map(|signature| signature_output(reader, &signature.raw))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let payloads = reader
        .header()
        .payload_index
        .iter()
        .map(|entry| {
            let delta = entry.delta_encoding.as_ref().map(|delta| {
                BundleDeltaOutput::new(
                    delta
                        .inputs
                        .iter()
                        .map(|input| {
                            BundleDeltaInputOutput::new(
                                input.hashes.iter().cloned().map(Into::into).collect(),
                            )
                        })
                        .collect(),
                    delta.original_hash.clone().into(),
                )
            });
            Ok(BundlePayloadOutput::new(
                delivery_output(entry)?,
                payload_digest(algorithm, &entry.header_hash.raw)?.into(),
                payload_digest(algorithm, &entry.file_hash.raw)?.into(),
            )
            .with_delta(delta))
        })
        .collect::<SystemResult<Vec<_>>>()?;
    Ok(BundleInspectOutput::new(
        header_hash.into(),
        algorithm.into(),
        update_type,
        payloads.into(),
        signatures.into(),
    )
    .with_components(components.map(Into::into))
    .with_manifest(manifest))
}

/// Decode the embedded object without interpreting manifest fields or encoding settings.
fn manifest_output(manifest: &str) -> SystemResult<BundleManifestOutput> {
    sidex::formats::json::from_str(manifest).whatever("invalid manifest JSON object")
}

/// Attach the bundle's hash algorithm to a declared payload digest.
fn payload_digest(algorithm: HashAlgorithm, bytes: &[u8]) -> SystemResult<HashDigest> {
    HashDigest::new(algorithm, bytes.into()).whatever("invalid payload digest")
}

/// Require one delivery mechanism and convert it to the public inspection format.
fn delivery_output(entry: &format::PayloadEntry) -> SystemResult<BundleDeliveryOutput> {
    match (
        &entry.type_slot,
        &entry.type_execute,
        &entry.type_app_file,
        &entry.type_app_archive,
    ) {
        (Some(slot), None, None, None) => Ok(BundleDeliveryOutput::Slot(
            BundleSlotDeliveryOutput::new(slot.slot.clone()),
        )),
        (None, Some(execute), None, None) => Ok(BundleDeliveryOutput::Execute(
            BundleExecuteDeliveryOutput::new(
                execute.handler.iter().cloned().map(Into::into).collect(),
            ),
        )),
        (None, None, Some(file), None) => Ok(BundleDeliveryOutput::AppFile(
            BundleAppFileDeliveryOutput::new(file.app.clone(), file.path.clone())
                .with_mode(file.mode)
                .with_store(file.store),
        )),
        (None, None, None, Some(archive)) => Ok(BundleDeliveryOutput::AppArchive(
            BundleAppArchiveDeliveryOutput::new(archive.app.clone()),
        )),
        _ => bail!("payload must declare exactly one delivery mechanism"),
    }
}

/// Preserve usable metadata and diagnostics even when a signature is malformed.
fn signature_output(reader: &BundleReader, bytes: &[u8]) -> BundleSignatureOutput {
    let inspection = match rugix_pki::inspect_cms(bytes) {
        Ok(inspection) => inspection,
        Err(error) => {
            return BundleSignatureOutput::new(Default::default())
                .with_error(Some(error.to_string().into()))
        }
    };
    let mut errors = inspection.errors;
    let header_matches = inspection.content.as_ref().and_then(|content| {
        match decode_slice::<format::SignedMetadata>(content) {
            Ok(metadata) => {
                Some(metadata.header_hash == reader.header_hash(metadata.header_hash.algorithm()))
            }
            Err(error) => {
                errors.push(format!("unable to read signed bundle metadata: {error}"));
                None
            }
        }
    });
    BundleSignatureOutput::new(
        inspection
            .signer_subjects
            .into_iter()
            .map(Into::into)
            .collect(),
    )
    .with_header_matches(header_matches)
    .with_error(if errors.is_empty() {
        None
    } else {
        Some(errors.join("; ").into())
    })
}
