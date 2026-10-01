# Detached Installation Grants

An installation grant authorizes a specific bundle for a device or provisioned group
during a limited time window. The grant is a separate CMS file. Issuing or renewing
it leaves the bundle unchanged, including its hash, streaming verification, and
delta delivery.

Rugix Ctrl verifies grants inside the installation executor. The CLI and privileged
daemon enforce the same grant policy. The signature covers the Rugix bundle hash,
device audience, validity window, authorization sequence, and installation options.

## Provision a Device

Configure `/etc/rugix/ctrl.toml`:

```toml
[grants]
roots = ["/etc/rugix/grant-root.pem"]
mode = { tag = "GrantOnly" }
namespace = "example-production"
device = "device-001"
groups = ["canary"]
trusted-system-clock = true
max-lifetime = 86400
```

The namespace, device ID, and groups are trusted provisioning data. Protect the
configuration and certificates from installation callers. Group names use exact
matching. Updating a group in an external inventory does not update this local
membership automatically.

Set `trusted-system-clock = true` only when the platform establishes trustworthy
current time across power cycles, for example through a protected clock or an
authenticated time service. The same time is used for grant and certificate
validity. Grant timestamps and CMS signing-time are not time sources. A stored
timestamp alone cannot account for time spent powered off. With this option false,
Rugix refuses granted installations.

Grant replay state uses `/run/rugix/mounts/data/.rugix/grants` when Rugix state
management is active, detected by the presence of `/run/rugix/state`. This location
survives a state-profile reset. Systems without state management use
`/var/lib/rugix/grants`. An optional `state-directory` setting overrides the path.

Initialize state after the device's storage and state management are set up. Keep
the selected directory on persistent, protected storage outside the A/B system
slots and resettable profiles. When changing the storage layout, migrate the
existing replay state. Rugix fails closed if the selected state file is missing,
invalid, or belongs to another provisioned identity; it does not search other
locations for a usable state file. Do not automatically initialize missing state
at boot. A full data-partition wipe removes grant history and requires explicit
reprovisioning.

Initialize state once during provisioning, as root:

```sh
rugix-ctrl initialize-grant-state
```

Initialization refuses to overwrite existing state. Restoring an old state backup
can restore old permissions; deployments defending against storage rollback need
hardware-backed protection for their security state and verifier.

With a `[grants]` section present, every system and app installation requires a
grant. Caller-supplied bundle hashes, root certificates, compatibility overrides,
and insecure verification options cannot bypass this requirement. The daemon's
`dangerously-insecure` switch does not override grant policy.

Grant roots authorize both system and app installation on the configured device.
Unconstrained grant issuers can authorize any bundle under `GrantOnly`.
Constrained authority certificates can narrow this permission as described below. Use independent publisher
verification when deployment authorities should only select publisher-approved
software:

```toml
[signatures]
roots = ["/etc/rugix/publisher-root.pem"]

[grants]
roots = ["/etc/rugix/grant-root.pem"]
mode = { tag = "EmbeddedAndGrant" }
namespace = "example-production"
device = "device-001"
trusted-system-clock = true
```

Both signatures are then mandatory. Adding several roots allows certificate
rotation within one authority; any accepted grant root may issue a grant. Restart
the daemon after changing its configuration.

## Issue and Install a Grant

Issue a grant on a trusted signing machine. Validity timestamps are Unix seconds,
with an inclusive start and exclusive end.

```sh
now=$(date +%s)
rugix-bundler grants sign \
  --bundle update.rugixb \
  --id rollout-42-device-001 \
  --namespace example-production \
  --device device-001 \
  --not-before "$now" \
  --expires-at "$((now + 3600))" \
  --sequence 42 \
  --target system \
  --reboot set \
  --cert grant-signer.pem \
  --key grant-signer.key \
  update.cms
```

Install with the same authorized options:

```sh
rugix-ctrl update install --grant update.cms --reboot set update.rugixb
```

Use `--group canary` instead of `--device device-001` for a provisioned group.
Use `--target apps` when signing for `rugix-ctrl apps install --grant app.cms app.rugixb`.

System grants bind `--boot-group`, `--keep-overlay`, and `--reboot` exactly.
Omitting a boot group authorizes local selection of an inactive group. Omitting
reboot behavior authorizes the bundle's default. System options cannot be used
with an app grant. The bundle hash binds its payload destinations, including app
names.

The default maximum grant size is 1 MiB, including certificates. The default
maximum validity window is one day; `max-lifetime` configures the device's limit.
The verifier also applies normal bundle integrity, destination, and compatibility
checks.

Inspect authenticated grant content and compare it with a trusted bundle:

```sh
rugix-bundler grants verify update.cms \
  --root-cert grant-root.pem \
  --namespace example-production \
  --device device-001 \
  --bundle update.rugixb
```

For group grants, also supply the independently established membership with
`--group`. This command uses the local clock and the library's default limits.
It does not inspect a device's replay state or authorize an installation.

## Use an External Signer

Prepare the exact bytes that must be signed, using the same grant options as above:

```sh
rugix-bundler grants prepare \
  --bundle update.rugixb --id rollout-42-device-001 \
  --namespace example-production --device device-001 \
  --not-before "$now" --expires-at "$((now + 3600))" \
  --sequence 42 --target system --reboot set grant.raw

openssl cms -sign -binary -nodetach \
  -in grant.raw -signer grant-signer.pem -inkey grant-signer.key \
  -outform DER -out update.cms
```

The CMS envelope must include the signed content. Its signing certificate and
intermediate chain must validate against a configured grant root. The existing
Rugix PKI certificate rules apply, including digital signature key usage.
Unconstrained chains use code-signing extended key usage when present; constrained
chains use the dedicated grant-authority purpose described below. The signing command also supports
repeated `--intermediate-cert` arguments.

## Constrained Grant Authorities

An authority certificate delegates permission to issue grants or subordinate
certificates. Its signed constraints bind the public key to a namespace, audience
selectors, service-operation permissions, maximum grant lifetime, and delegation
depth. Its X.509 validity period bounds when that authority is usable. Verification
requires no certificate server: the grant carries its signing certificate and
intermediates.

A child must preserve or narrow its parent's namespace, audience selectors,
permissions, and maximum grant lifetime. Its whole certificate validity period
must fit inside its parent's. An omitted `maxDelegationDepth` means zero: a CA may
issue grant-signing certificates but may not issue subordinate CAs. Each additional
CA level reduces the remaining allowance. A signing certificate must have depth
zero. A child that widens authority is rejected even if a particular grant would
fit its parent's permissions.

Audience selectors use exact matching. `"Any"` permits any selector within the
namespace. `{"Targets":[{"Group":"canary"}]}` permits grants addressed to that group;
it does not permit device-addressed grants, even for devices in the group.
Device membership still comes from trusted local provisioning.

Permissions pair a verifier identifier with an operation permission identifier:

| Verifier | Permission | Authorized Operation |
| --- | --- | --- |
| `rugix-ctrl` | `rugix.install.apps.v1` | Application installation |
| `rugix-ctrl` | `rugix.install.system.v1` | System installation |

Both use the `rugix.install.v1` grant payload. Permissions distinguish the
authenticated installation target. An empty permission or target list authorizes
nothing. Unknown identifiers grant no additional permission. Unknown constraint
fields, versions, duplicate fields, and malformed certificates are rejected.

The grant's entire validity window must fit inside its signing certificate's
window and its maximum grant lifetime. Device policy may impose a shorter limit.
The certificate chain is checked again at reservation and consumption. A claimed
signing time cannot extend authority beyond certificate expiry. Already authorized
activation, recovery, and running software follow the rules in
[Replay, Expiry, and Recovery](#replay-expiry-and-recovery).

Configured trust roots remain administrative authorities. Existing unconstrained
code-signing chains remain supported. Use separate keys for constrained authorities:
issuing an unconstrained certificate for the same key creates another authorization
path. A locally configured root's certificate expiry does not automatically expire
local trust. If the root itself carries authority constraints, Rugix also enforces
those constraints and its validity window.

Constraints limit accepted requests. They do not reverse installations or replay
state changes already authorized by a compromised key. In particular, issuers
sharing an installation scope still share its authorization sequence.

## Issue Constrained Certificates

Create `authority.json` on a trusted signing machine:

```json
{
  "version": 1,
  "namespace": "example-production",
  "audiences": {"Targets": [{"Group": "canary"}]},
  "permissions": [
    {"verifier": "rugix-ctrl", "operation": "rugix.install.apps.v1"}
  ],
  "maxGrantLifetime": 1800
}
```

Use an existing grant root to issue an intermediate with a 90-day validity period:

```sh
umask 077
rugix-bundler grants authority-extensions \
  authority.json authority.ext --intermediate

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -nodes -subj "/CN=Application Deployment Authority" \
  -keyout authority.key -out authority.csr

openssl x509 -req -in authority.csr \
  -CA grant-root.pem -CAkey grant-root.key -CAcreateserial \
  -days 90 -extfile authority.ext -out authority.pem
```

Issue a grant-signing certificate with a shorter validity period:

```sh
rugix-bundler grants authority-extensions authority.json signer.ext

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -nodes -subj "/CN=Application Grant Signer" \
  -keyout grant-signer.key -out grant-signer.csr

openssl x509 -req -in grant-signer.csr \
  -CA authority.pem -CAkey authority.key -CAcreateserial \
  -days 1 -extfile signer.ext -out grant-signer.pem

now=$(date +%s)
rugix-bundler grants sign \
  --bundle app.rugixb --id canary-app-42 \
  --namespace example-production --group canary \
  --not-before "$now" --expires-at "$((now + 600))" \
  --sequence 42 --target apps \
  --cert grant-signer.pem --key grant-signer.key \
  --intermediate-cert authority.pem app.cms

rugix-ctrl apps install --grant app.cms app.rugixb
```

Choose certificate and grant end times that fit inside their parent windows,
including when renewing close to an authority's expiry. OpenSSL can issue
certificates that exceed these limits; Rugix rejects them during verification.
Renewed certificates can travel with the next grant.

The extension generator validates the policy and emits the required certificate
purpose and basic constraints. Certificate issuance remains with your CA tooling.
It does not add a certificate service or maintain issuer state.

## Replay, Expiry, and Recovery

Rugix maintains separate authorization sequences for system installations and app
installations. All apps share one sequence stream. An issuer must coordinate
increasing sequences across its keys and device or group grants within each stream.
Sequence numbers describe authorizations, so an intentional downgrade uses a newer
sequence for an older bundle.

After preflight, Rugix durably reserves the grant before installation side effects.
An interrupted transfer can retry the exact same grant while it remains valid.
Changing its ID or content at the same sequence is rejected. A newer reserved
authorization supersedes older ones.

Before activating apps, selecting or deferring a system boot, or finalizing a staged
system update, Rugix rechecks grant and certificate validity and durably consumes
the grant. Once consumed, another installation requires a higher sequence, including
when activation fails or power is lost between consumption and activation.
This permits retries of incomplete transfers and prevents repeated activation
admission. It does not promise exactly-once execution of arbitrary payload handlers.

An update that expires while streaming cannot proceed to activation. Its inactive
data may remain and can be replaced by an installation with a new grant. Manual
app activation, manual app rollback, and `system reboot --spare` are disabled under
grant policy. To select stored software again, install its bundle with a new grant.
A staged system installation with `--reboot no` follows the same rule.

Once activation is durably authorized, boot retries, commit, and automatic recovery
may finish after expiry. Existing software continues running. Deferred reboot
authorization may execute on a later boot. The validity window limits authorization
of the operation, not the time at which software must stop running.

Short validity windows limit how long an offline grant remains usable. Immediate
revocation requires fresh information on the device. Protect the privileged
verifier, local policy, clock, and replay state as part of the device security boundary.

## Library and Wire Format

`crates/libs/rugix-grants` provides the reusable envelope, CMS signing, and
verification for typed operations. It has no installer, filesystem, transport, or
daemon dependency. `rugix-bundle` defines the `rugix.install.v1` operation and its
`rugix-ctrl` verifier audience. The executor owns resource policy, replay state, and
operation recovery.

The signed CMS content is the byte prefix `rugix.operation-grant.v1\0`, followed by
UTF-8 JSON. The signature covers the original bytes. Verification does not
reserialize JSON. Unsupported versions, operation types, unknown fields, duplicate
fields, and trailing content are rejected. A grant cannot be substituted for
ordinary embedded bundle metadata.

The Sidex source contracts are
[`grant.sidex`](../crates/libs/rugix-grants/schemas/grant.sidex),
[`authority.sidex`](../crates/libs/rugix-grants/schemas/authority.sidex), and
[`grants.sidex`](../crates/libs/rugix-bundle/schemas/grants.sidex).
The unsigned 64-bit fields `notBefore`, `expiresAt`, and `sequence` accept JSON
integers or decimal strings. Sidex emits decimal strings for values above
JavaScript's maximum safe integer, 9007199254740991.

Rugix's delegated object identifier (OID) namespace is `1.3.6.1.4.1.67013.100`.
The following assignments are permanent and must not be reused for other purposes:

| OID | Purpose |
| --- | --- |
| `1.3.6.1.4.1.67013.100.1` | Grant-authority extended key usage |
| `1.3.6.1.4.1.67013.100.2` | Authority constraints extension |

Authority constraints are UTF-8 Sidex JSON inside a DER UTF8String, carried in the
certificate's non-critical authority extension. Every non-root certificate in a
constrained path must carry this extension and a critical extended key usage
containing only the dedicated grant-authority purpose. The verifier requires the
constraints whenever that purpose is used. It evaluates only the path authenticated
by X.509 validation, never unrelated certificates supplied in the CMS envelope.

The dedicated purpose prevents existing code-signing verifiers from accepting
constrained keys while ignoring their policy. A constrained key also cannot serve
as an embedded bundle publisher. Unknown critical extensions on signing and
intermediate certificates remain rejected.
This profile uses the standard critical extended key usage extension because the
X.509 validation library does not support custom critical extension handlers.

## Verify Changes

Run the Rust checks and the CLI/daemon test:

```sh
mise run check
mise run test:grants
```

The end-to-end test needs Linux user and mount namespaces, Python, OpenSSL, and
`mount`. It replaces device paths in private namespaces and does not require host
root access. It exercises real bundle creation, CMS issuance, app activation,
system installation to file slots, boot selection through a test controller,
streaming expiry, interrupted transfer recovery, replay protection, daemon policy,
independent signing authorities, external OpenSSL signing, constrained certificate
issuance, delegation escalation rejection, and application-only authority rejection
for system installations.
