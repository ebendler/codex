# Bwrap CUDA Sandbox Design

Date: 2026-05-19

## Summary

Add explicit CUDA hardware access to Codex's Linux bubblewrap sandbox. The
feature is opt-in through the active permissions profile, supports NVIDIA CUDA
compute devices only in the first version, and leaves existing sandbox behavior
unchanged when the flag is absent or false.

## Goals

- Let users opt a permissions profile into CUDA access without disabling the
  sandbox.
- Keep CUDA access profile-scoped, like filesystem and network permissions.
- Expose only compute-oriented NVIDIA device nodes for v1.
- Keep non-GPU hosts usable when the flag is present.
- Use tests to prove whether additional metadata mounts, such as
  `/proc/driver/nvidia`, are needed before adding them.

## Non-Goals

- Do not enable GPU access by default.
- Do not support generic render devices, Vulkan, OpenGL, AMD ROCm, Intel GPUs,
  or `/dev/dri` in v1.
- Do not expose NVIDIA display-oriented device nodes such as
  `/dev/nvidia-modeset`.
- Do not add a host `/proc/driver/nvidia` bind in v1 unless CUDA smoke-test
  evidence proves it is required.
- Do not change the legacy Landlock fallback path unless implementation finds a
  direct compatibility requirement.

## Configuration

User-defined permission profiles gain an optional hardware section:

```toml
default_permissions = "cuda-workspace"

[permissions.cuda-workspace.hardware]
cuda = true
```

`cuda` defaults to `false`. Built-in profiles remain CPU-only for this change.
The profile compiler should parse this into the runtime permission model, rather
than leaving the Linux sandbox helper to reread config.

## Runtime Model

Extend managed permission profiles with a small hardware capability sidecar,
for example:

```rust
pub struct HardwarePermissions {
    pub cuda: bool,
}
```

The exact Rust shape can follow existing protocol conventions, but it should be
serializable with session and turn metadata and should default to no hardware
access. Disabled and external profiles should not acquire managed CUDA behavior
implicitly; CUDA passthrough belongs to managed bwrap sandbox construction.

## Bubblewrap Behavior

When the active managed permission profile has CUDA enabled, the Linux bwrap
argument builder appends compute-only NVIDIA device binds after the baseline
`--dev /dev` mount.

Use device-aware bind flags:

```text
--dev-bind-try /dev/nvidiactl /dev/nvidiactl
--dev-bind-try /dev/nvidia-uvm /dev/nvidia-uvm
--dev-bind-try /dev/nvidia-uvm-tools /dev/nvidia-uvm-tools
--dev-bind-try /dev/nvidia-caps /dev/nvidia-caps
--dev-bind-try /dev/nvidia0 /dev/nvidia0
```

The implementation should discover `/dev/nvidia[0-9]+` entries from the host
instead of guessing a fixed maximum device index. `--dev-bind-try` keeps command
startup portable across machines where optional nodes are missing.

The first version intentionally excludes `/dev/nvidia-modeset` and `/dev/dri`.
No explicit `/proc/driver/nvidia` bind is added initially. The existing bwrap
flow already mounts a fresh `/proc` by default with `--proc /proc`, and it has a
fallback for restrictive environments where mounting procfs is denied.

## Error Handling

Missing CUDA device nodes do not fail bwrap argument construction. If CUDA is
enabled but no compute devices exist, the sandbox starts normally and CUDA
programs fail in their normal runtime path.

Argument construction should only fail for internal errors that would make the
sandbox less restrictive than requested. Optional device absence is not such an
error.

## Testing

Add unit coverage for:

- Config parsing accepts `[permissions.<name>.hardware] cuda = true`.
- Compiled permission profiles preserve CUDA hardware permission through
  serialization and deserialization.
- Bwrap args include CUDA `--dev-bind-try` entries only when CUDA is enabled.
- Bwrap args exclude `/dev/nvidia-modeset`.
- Missing CUDA nodes do not fail argument construction.
- Existing profiles without hardware config produce unchanged bwrap args.

Add runtime validation for GPU hosts:

- A focused Linux sandbox smoke test runs a small CUDA init probe under bwrap
  when CUDA is enabled.
- The test skips cleanly when `/dev/nvidiactl` or `libcuda` is unavailable.
- If the smoke test fails specifically because NVIDIA proc metadata is missing,
  add a follow-up design or amendment for a read-only `/proc/driver/nvidia`
  mount backed by that failure evidence.

## Documentation

Update `codex-rs/linux-sandbox/README.md` to describe the opt-in CUDA behavior.
Regenerate config schema if the config model changes the schema surface.

## Implementation Boundaries

Primary code areas:

- `codex-rs/config/src/permissions_toml.rs` for TOML parsing.
- `codex-rs/core/src/config/permissions.rs` for profile compilation.
- `codex-rs/protocol/src/models.rs` or adjacent protocol types for the runtime
  permission model.
- `codex-rs/linux-sandbox/src/bwrap.rs` for CUDA device bind argument
  construction.
- Existing Linux sandbox tests for bwrap argument coverage and smoke-test
  gating.
