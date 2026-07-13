# Update Reliability and Recovery

This document describes the observable guarantees and recovery behavior of Rugix Ctrl. It is
intended for operators designing update, shutdown, and incident-response procedures.

## System Update Lifecycle

Before changing an inactive target, Rugix verifies the bundle signature and component policy,
resolves every payload destination, rejects active or unavailable slots, and runs update
preflight. A full system bundle must contain an applicable system-slot payload. Hook execution,
overlay removal, and bootloader preparation begin only after this preflight succeeds.

Each file or block target is flushed and synchronized before Rugix records its payload state.
The boot flow is changed only after all payloads have completed and their state has been saved.
The `--reboot` modes therefore have these meanings:

- `yes`: synchronize the update, select the target as the next trial system, and reboot;
- `set`: synchronize the update and select the target, but do not reboot;
- `no`: synchronize the update without changing boot selection;
- `deferred`: synchronize the update and durably record the target group without changing boot
  selection. Initialization selects that exact group on a later boot and retains the record if
  the bootloader update fails, allowing another retry.

Legacy empty deferred-reboot records are accepted only on systems with exactly two boot groups,
where the intended spare group is unambiguous.

## Upgrade, Trial, and Rollback

A full A/B upgrade writes only inactive slots. The configured boot flow owns trial counting,
commit, and automatic rollback semantics. Operators should commit a healthy trial with
`rugix-ctrl system commit`; an uncommitted trial may be rolled back by the bootloader after its
configured attempt limit. Rugix reports unknown or inconsistent active-group state as an error
instead of guessing a group.

Application bundles finalize every new generation before activating any app. Activation is
deterministic. If one activation fails, Rugix attempts to restore every app already switched and
returns an error containing all rollback outcomes. A generation is not marked complete until its
files, directories, and persisted state are durable. Incomplete generations are ignored during
recovery and can be garbage-collected.

## Power Loss and Interrupted Operations

Power loss before the durability boundary can leave data in an inactive slot or an incomplete app
generation, but Rugix does not persist completion or select that system first. Reinstalling the
bundle overwrites the inactive target. Power loss after a `yes` or `set` boot selection is subject
to the configured boot flow's normal trial and rollback behavior. A `deferred` record remains the
source of truth until target selection succeeds.

Payloads delivered to custom handlers or executed as commands are an intentional limitation:
Rugix propagates handler failures, but cannot make arbitrary external side effects atomic or
durable. Such handlers must implement their own idempotency, synchronization, and recovery.

## Invalid and Malformed Input

Bundles with invalid framing, excessive nesting, inconsistent payload counts, corrupt or oversized
metadata, unsupported required tags, invalid paths, or failed signatures are rejected with an
error. Destination and component checks occur before update mutation. Corruption discovered while
streaming a payload may partially modify only its inactive destination; Rugix does not save its
state or select it for boot.

If component metadata is required with `compatibility.requireBundleComponents = true`, a bundle
without it is rejected. `--skip-compatibility-check` is the explicit operator override and is
reported in logs and machine-readable events. Malformed component metadata is rejected even when
the compatibility comparison is skipped.

## Data Partition Mount Failures

Set `data-partition.fail-closed-on-mount-error = true` when continuing without persistent data is
unsafe. With the compatibility fallback, Rugix starts with ephemeral data, emits a prominent
diagnostic, records it on the config partition when possible, and reports `EphemeralFallback` in
machine-readable system information. Changes made in that mode do not survive reboot.
