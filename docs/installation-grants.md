# Detached Installation Grants

An installation grant authorizes one specific bundle for one device or provisioned
group during a limited time window. This document specifies the wire format, the
certificate profile, and the permanent identifiers, for anyone implementing a grant
issuer or reviewing the implementation.

Operator documentation lives at
[Installation Grants](https://rugix.org/docs/ctrl/next/updates/installation-grants).

## Components

| Crate | Responsibility |
| --- | --- |
| `crates/libs/rugix-grants` | Grant envelope, CMS signing and verification, certificate scope |
| `crates/libs/rugix-install-grants` | The `rugix.install.v1` operation and its permissions |
| `crates/apps/rugix-ctrl` | Local policy, device identity, replay state, enforcement |
| `crates/apps/rugix-bundler` | Issuance, external signing, certificate extensions |

`rugix-grants` performs no I/O and executes no operations. It is reusable by other
services that need signed, constrained operations; an operation defines its payload
in Sidex and the key purpose that authorizes it.

## Trust Model

Every accepted grant satisfies two independent limits, and authorization is their
intersection:

- **Local policy** names the trusted roots, the operations each may authorize, and
  the longest validity window each may use. A signing key cannot change it.
- **Certificate scope** names the identity namespace and audiences one key may
  address, and the operations its extended key usage permits. An authority cannot
  delegate more than it holds.

A verifier is constructed for one root and one permission set, so an executor cannot
accidentally accept a grant that local policy does not cover.

Grants gate installation and nothing else. Activating an installed app generation,
rolling one back, and selecting the spare system are deliberately ungated: that
software reached the device under a grant, the boot flow has to roll back
automatically when a trial fails, and any caller privileged enough to reach those
operations can also rewrite the local policy. Gating them would forbid operations no
grant could authorize, since there is no activation operation to issue a grant for,
and it would disable rollback as a recovery path.

The boundary is between the installer and its callers, including every client of the
privileged daemon. It is not a defense against root on the device. Accordingly the
policy has an explicit way out, `insecure_skip_grant_verification`, which installs
without a grant and falls back to the ordinary verification rules. It is classified
as a security override, so the daemon refuses it without `dangerously-insecure`. An
explicit per-invocation option is preferable to the alternative an operator would
otherwise reach for, which is deleting `[grants]` and leaving the device unprotected
for every later installation.

A grant and a local override are mutually exclusive: `require_exclusive_grant`
refuses a request that supplies both, because a grant already decides verification.
It destructures the options so that a new one has to be classified before it can be
combined with a grant.

Recipient identity must come from the executor's trusted provider, never from the
request or the grant. The library takes it as an explicit input.

Verification needs trusted current time, supplied by the caller. Rugix Ctrl uses the
system clock bounded below by a durable watermark, so a clock that moves backwards
cannot revive an expired grant. Neither grant timestamps nor CMS signing-time
establish current time.

## Wire Format

The signed CMS content is the byte prefix `rugix.operation-grant.v1\0` followed by
UTF-8 JSON. Signatures cover those exact bytes, and verification never reserializes
JSON. The prefix provides domain separation, so a grant cannot be substituted for
ordinary embedded bundle metadata.

Decoding rejects unsupported versions, mismatched operation types, unknown fields,
duplicate fields, and trailing content. A constraint added by a future issuer
therefore fails closed instead of being ignored.

That property constrains the encoding: **every variant carrying a payload must be
externally tagged**, which is why the signed contract uses `{"system": {...}}` rather
than a `tag` and `content` pair. Sidex generates deserializers that hand unknown
fields to Serde's tracking adapter, and that adapter is what turns them into a
rejection. Adjacent and internal tagging buffer the payload into an intermediate
value first, which hides every unknown field inside that payload from the adapter.
Changing the tagging of `InstallTarget`, `AudienceTarget`, `BootGroupConstraint`, or
`RebootConstraint` would silently drop the guarantee; the test
`installation_contract_rejects_unknown_and_duplicate_constraints` exists to catch
that. Case names use kebab-case, and variants whose cases carry no payload, such as
`RebootMode`, encode as plain strings.

The Sidex contracts are
[`grant.sidex`](../crates/libs/rugix-grants/schemas/grant.sidex) and
[`install.sidex`](../crates/libs/rugix-install-grants/schemas/install.sidex). The
published JSON schema for the installation operation is
[`rugix-install-operation.schema.json`](../schemas/rugix-install-operation.schema.json).
The unsigned 64-bit fields `notBefore` and `expiresAt` accept JSON integers or
decimal strings; Sidex emits decimal strings above JavaScript's maximum safe
integer, 9007199254740991.

Default limits are a 1 MiB CMS envelope, including certificates, and a one-day
validity window.

## Certificate Profile

Every certificate below the trust anchor must carry:

1. A **critical extended key usage** holding the grant authority purpose plus one
   purpose per operation the certificate may authorize, including purposes it only
   delegates to subordinates.
2. A **non-critical scope extension** holding a DER `AuthorityScope`.

```text
AuthorityScope ::= SEQUENCE {
    version    INTEGER,
    namespace  UTF8String,
    targets    SEQUENCE OF ScopeTarget
}

ScopeTarget ::= CHOICE {
    any       [0] NULL,
    recipient [1] UTF8String,
    group     [2] UTF8String
}
```

A verifier implementing this profile MUST reject a certificate that carries the grant
authority purpose without a scope extension. That requirement is what makes breadth
explicit: a permissive authority still has to state `any` and name its namespace. The
scope extension is non-critical only because X.509 verifiers reject critical
extensions they do not recognize; the mandatory purpose is what keeps other verifiers
from accepting these keys for code signing.

DER decoding rejects unknown elements and trailing data, so an extension this verifier
does not fully understand authorizes nothing. An empty target list authorizes nothing.

A subordinate must preserve or narrow its parent's namespace and audience selectors.
Delegation depth and certificate validity use standard basic constraints and validity
periods, which the X.509 path verifier enforces for every certificate in the chain.
Because the grant authority purpose is required on every certificate below the
anchor, a grant authority cannot be chained under an existing code-signing
intermediate.

The locally configured anchor may omit both extensions, because local configuration
is the authorization for the anchor. A scope attached to the anchor is enforced.

## Identifiers

Rugix's delegated object identifier namespace is `1.3.6.1.4.1.67013.100` (Silitics
PEN 67013). These assignments are permanent and must not be reused:

| OID | Purpose |
| --- | --- |
| `1.3.6.1.4.1.67013.100.1` | Grant authority extended key usage |
| `1.3.6.1.4.1.67013.100.2` | Authority scope extension |
| `1.3.6.1.4.1.67013.100.3.1` | Application installation key purpose |
| `1.3.6.1.4.1.67013.100.3.2` | System installation key purpose |

Operation key purposes are assigned under `.3`. The operation type string
`rugix.install.v1` identifies the payload contract and is versioned separately from
the purposes, because both installation targets share one payload.

## Enforcement an Issuer Can Rely On

Rugix Ctrl records an admitted grant before installation side effects and a consumed
grant before activation, identified by a hash of the authenticated content. An issuer
can rely on the following:

- An interrupted transfer may retry the same grant while it remains valid.
- A consumed grant is never admitted again.
- Grants are independent. Several authorities can issue grants for one device without
  coordinating, and consuming one grant does not invalidate another.
- Admission, the record, and activation each revalidate the grant, the certificate
  chain, and the device identity.

Records are retained until their grant expires, up to 1024 at a time, which bounds
the state by the issuing rate within one window. Issuing more unexpired grants than a
device retains delays further installations until some expire.

Replay state is created on first use. The directory is private to the privileged
executor, and that is what protects the history: anything able to delete the records
could equally create new ones, so refusing to create them would add no protection.

## Verify Changes

```sh
mise run check
mise run test:grants
```

`test:grants` needs Linux user and mount namespaces, Python, OpenSSL, and `mount`. It
replaces device paths inside private namespaces and needs no host root access. It
covers configuration validation, certificate preparation and rejection of unprepared
certificates, delegation and escalation, option binding, replay and the time
watermark, streaming expiry, identity changes during installation, daemon admission,
independent publisher signatures, external OpenSSL signing, system installation to
file slots with a test boot controller, and both state locations.
