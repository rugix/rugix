//! Exercise the public inspection command with each supported input capability.

use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use serde::Deserialize;
use si_crypto_hashes::HashAlgorithm;

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inspection {
    header_hash: String,
    hash_algorithm: String,
    update_type: String,
    payloads: Vec<Payload>,
    components: Option<Vec<ComponentFile>>,
    signatures: Vec<Signature>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Payload {
    delivery: Delivery,
    header_hash: String,
    file_hash: String,
    delta: Option<Delta>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum Delivery {
    Slot {
        slot: String,
    },
    Execute {
        handler: Vec<String>,
    },
    AppFile {
        app: String,
        path: String,
        mode: Option<u32>,
    },
    AppArchive {
        app: String,
    },
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Delta {
    inputs: Vec<DeltaInput>,
    output_hash: String,
}

#[derive(Debug, Deserialize, PartialEq)]
struct DeltaInput {
    hashes: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct ComponentFile {
    path: String,
    component: Component,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Component {
    id: String,
    provides: Vec<Capability>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Capability {
    id: String,
    version: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Signature {
    signer_subjects: Vec<String>,
    header_matches: Option<bool>,
    error: Option<String>,
}

/// Build one bundle containing every delivery kind and distinct hash algorithms.
struct Fixture {
    directory: tempfile::TempDir,
    path: PathBuf,
    header_hash: String,
    base_hash: String,
    output_hash: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("payloads")).unwrap();
        fs::create_dir(root.join("components")).unwrap();
        fs::write(root.join("payloads/system"), vec![42; 192 * 1024]).unwrap();
        fs::write(root.join("payloads/script"), b"exit 99\n").unwrap();
        fs::write(root.join("payloads/patch"), b"patch bytes").unwrap();
        fs::write(root.join("payloads/archive"), vec![17; 512 * 1024]).unwrap();
        fs::write(
            root.join("components/versions.toml"),
            "id = 'versions'\nprovides = [{ id = 'app', version = '4.1.7' }]\n",
        )
        .unwrap();
        let base_hash = HashAlgorithm::Sha256.hash::<Vec<u8>>(b"base").to_string();
        let output_hash = HashAlgorithm::Sha256.hash::<Vec<u8>>(b"result").to_string();
        fs::write(root.join("rugix-bundle.toml"), format!(r#"
update-type = "incremental"
hash-algorithm = "sha512-256"

[[payloads]]
filename = "system"
delivery = {{ type = "slot", slot = "system" }}
block-encoding = {{ chunker = "fixed-64", hash-algorithm = "sha256", deduplicate = true, compression = {{ type = "xz" }} }}

[[payloads]]
filename = "script"
delivery = {{ type = "execute", handler = ["sh", "-e"] }}

[[payloads]]
filename = "patch"
delivery = {{ type = "app-file", app = "demo", path = "bin/run", mode = 493 }}
delta-encoding = {{ format = "xdelta", inputs = [{{ hashes = ["{base_hash}"] }}], original-hash = "{output_hash}" }}
block-encoding = {{ chunker = "fixed-64" }}

[[payloads]]
filename = "archive"
delivery = {{ type = "app-archive", app = "demo" }}
"#)).unwrap();
        let path = root.join("bundle.rugixb");
        let header_hash = rugix_bundle::builder::pack(root, &path)
            .unwrap()
            .to_string();
        Self {
            directory,
            path,
            header_hash,
            base_hash,
            output_hash,
        }
    }
}

/// Keep only the metadata prefix, ending immediately after the payload section starts.
fn metadata_prefix(path: &Path) -> Vec<u8> {
    let mut bytes = fs::read(path).unwrap();
    let source =
        rugix_bundle::reader::BundleSource::from_seekable(std::io::Cursor::new(bytes.clone()))
            .unwrap();
    let reader = rugix_bundle::reader::BundleReader::start(source, None).unwrap();
    bytes.truncate(reader.progress().bytes_read.raw as usize);
    bytes
}

/// Execute inspection without initializing a Rugix device or privileged daemon.
fn inspect(input: &str, stream: Option<&[u8]>) -> Inspection {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rugix-ctrl"))
        .args([
            "bundle",
            "inspect",
            "--json",
            input,
            "--http-max-retries",
            "0",
        ])
        .stdin(if stream.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Keep stdin open: inspection must finish without waiting for payloads or EOF.
    let stdin = stream.map(|bytes| {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(bytes).unwrap();
        stdin
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "inspection did not finish: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    drop(stdin);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Verify output metadata and equivalence of seekable and forward-only inputs.
#[test]
fn file_and_open_stdin_report_declared_payloads_and_components() {
    let fixture = Fixture::new();
    let output = inspect(fixture.path.to_str().unwrap(), None);
    assert_eq!(output.header_hash, fixture.header_hash);
    assert_eq!(output.hash_algorithm, "sha512_256");
    assert_eq!(output.update_type, "incremental");
    assert_eq!(output.payloads.len(), 4);
    assert_eq!(
        output.payloads[0].delivery,
        Delivery::Slot {
            slot: "system".into()
        }
    );
    assert_eq!(
        output.payloads[1].delivery,
        Delivery::Execute {
            handler: vec!["sh".into(), "-e".into()]
        }
    );
    assert_eq!(
        output.payloads[2].delivery,
        Delivery::AppFile {
            app: "demo".into(),
            path: "bin/run".into(),
            mode: Some(493),
        }
    );
    let delta = output.payloads[2].delta.as_ref().unwrap();
    assert_eq!(delta.inputs[0].hashes, vec![fixture.base_hash]);
    assert_eq!(delta.output_hash, fixture.output_hash);
    assert_eq!(
        output.payloads[3].delivery,
        Delivery::AppArchive { app: "demo".into() }
    );
    let components = output.components.as_ref().unwrap();
    assert_eq!(components[0].path, "versions.toml");
    assert_eq!(components[0].component.id, "versions");
    assert_eq!(components[0].component.provides[0].id, "app");
    assert_eq!(
        components[0].component.provides[0].version.as_deref(),
        Some("4.1.7")
    );
    assert!(output.signatures.is_empty());
    for payload in &output.payloads {
        assert!(payload.header_hash.starts_with("sha512-256:"));
        assert!(payload.file_hash.starts_with("sha512-256:"));
    }
    let prefix = metadata_prefix(&fixture.path);
    assert_eq!(output, inspect("-", Some(&prefix)));
    let truncated = fixture.directory.path().join("header-only.rugixb");
    fs::write(&truncated, &prefix).unwrap();
    assert_eq!(output, inspect(truncated.to_str().unwrap(), None));
}

/// Generate an untrusted, self-signed signer without needing device trust roots.
fn signer(root: &Path) -> rugix_pki::CmsSigner {
    let key = root.join("signer.key");
    let cert = root.join("signer.crt");
    let output = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args(["-subj", "/CN=Inspection Signer", "-days", "1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    rugix_pki::CmsSigner::new(&fs::read(cert).unwrap(), &fs::read(key).unwrap()).unwrap()
}

/// Inspect matching, mismatching, and malformed signatures without rejecting the bundle.
#[test]
fn signature_diagnostics_do_not_require_valid_or_trusted_signatures() {
    let fixture = Fixture::new();
    let signer = signer(fixture.directory.path());
    let matching = signer
        .sign(&rugix_bundle::signed_metadata(&fixture.path).unwrap())
        .unwrap();
    let other_root = fixture.directory.path().join("other");
    fs::create_dir(&other_root).unwrap();
    fs::write(
        other_root.join("rugix-bundle.toml"),
        "update-type = 'full'\npayloads = []\n",
    )
    .unwrap();
    let other_path = other_root.join("empty.rugixb");
    rugix_bundle::builder::pack(&other_root, &other_path).unwrap();
    let empty = inspect(other_path.to_str().unwrap(), None);
    assert_eq!(empty.update_type, "full");
    assert!(empty.payloads.is_empty());
    assert!(empty.components.is_none());
    let mismatch = signer
        .sign(&rugix_bundle::signed_metadata(&other_path).unwrap())
        .unwrap();
    let mut input = fixture.path.clone();
    for (index, signature) in [matching, mismatch, b"malformed CMS".to_vec()]
        .into_iter()
        .enumerate()
    {
        let output = fixture
            .directory
            .path()
            .join(format!("signed-{index}.rugixb"));
        rugix_bundle::add_bundle_signature(&input, signature, &output).unwrap();
        input = output;
    }
    let output = inspect(input.to_str().unwrap(), None);
    assert_eq!(output.header_hash, fixture.header_hash);
    assert_eq!(output.signatures.len(), 3);
    for signature in &output.signatures[..2] {
        assert_eq!(signature.signer_subjects, vec!["CN=Inspection Signer"]);
        assert!(signature.error.is_none());
    }
    assert_eq!(output.signatures[0].header_matches, Some(true));
    assert_eq!(output.signatures[1].header_matches, Some(false));
    assert!(output.signatures[2].signer_subjects.is_empty());
    assert!(output.signatures[2].header_matches.is_none());
    assert!(output.signatures[2].error.is_some());
    assert_eq!(output, inspect("-", Some(&metadata_prefix(&input))));
}

/// A minimal HTTP fixture serving either byte ranges or a forward response.
struct Server {
    url: String,
    sent: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn new(bytes: Vec<u8>, ranges: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/bundle", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(AtomicUsize::new(0));
        let worker_stop = Arc::clone(&stop);
        let worker_sent = Arc::clone(&sent);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                let (mut socket, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = BufReader::new(socket.try_clone().unwrap());
                let mut requested_range = None;
                loop {
                    let mut line = String::new();
                    if request.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(range) = line.to_ascii_lowercase().strip_prefix("range: bytes=") {
                        let (start, end) = range.trim().split_once('-').unwrap();
                        requested_range = Some((
                            start.parse::<usize>().unwrap(),
                            end.parse::<usize>().unwrap() + 1,
                        ));
                    }
                }
                let (start, requested_end) = if ranges {
                    requested_range.unwrap_or((0, bytes.len()))
                } else {
                    (0, bytes.len())
                };
                let end = requested_end.min(bytes.len());
                let status = if ranges && requested_range.is_some() {
                    "206 Partial Content"
                } else {
                    "200 OK"
                };
                let content_range = if ranges && requested_range.is_some() {
                    format!(
                        "Content-Range: bytes {start}-{}/{total}\r\n",
                        end - 1,
                        total = bytes.len()
                    )
                } else {
                    String::new()
                };
                write!(socket, "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{content_range}Connection: close\r\n\r\n", end - start).unwrap();
                worker_sent.fetch_add(end - start, Ordering::Relaxed);
                if let Err(error) = socket.write_all(&bytes[start..end]) {
                    assert!(
                        matches!(
                            error.kind(),
                            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                        ),
                        "{error}"
                    );
                }
            }
        });
        Self {
            url,
            sent,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

/// Inspect full bundles and metadata prefixes with or without HTTP range support.
#[test]
fn http_ranges_and_streaming_fallback_match_local_inspection() {
    let fixture = Fixture::new();
    let bytes = fs::read(&fixture.path).unwrap();
    let expected = inspect(fixture.path.to_str().unwrap(), None);
    let ranged = Server::new(bytes.clone(), true);
    assert_eq!(inspect(&ranged.url, None), expected);
    assert!(ranged.sent.load(Ordering::Relaxed) < bytes.len() / 2);
    let streaming = Server::new(bytes, false);
    assert_eq!(inspect(&streaming.url, None), expected);
    for ranges in [true, false] {
        let prefix = Server::new(metadata_prefix(&fixture.path), ranges);
        assert_eq!(inspect(&prefix.url, None), expected);
    }
}
