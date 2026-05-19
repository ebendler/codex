#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use codex_core::exec_env::create_env;
use codex_protocol::config_types::ShellEnvironmentPolicy;
use codex_protocol::models::HardwarePermissions;
use codex_protocol::models::PermissionProfile;
use pretty_assertions::assert_eq;
use std::collections::HashMap;
use std::path::Path;
use std::process::Output;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

const CUDA_TIMEOUT_MS: u64 = 10_000;
const BWRAP_UNAVAILABLE_ERR: &str = "bubblewrap is unavailable: no system bwrap was found";

const CUDA_HOST_INIT_PROBE: &str = r#"
import ctypes

errors = []
for library_name in ("libcuda.so.1", "libcuda.so"):
    try:
        cuda = ctypes.CDLL(library_name)
        break
    except OSError as exc:
        errors.append(f"{library_name}: {exc}")
else:
    raise SystemExit("; ".join(errors))

cuda.cuInit.argtypes = [ctypes.c_uint]
cuda.cuInit.restype = ctypes.c_int
cuda.cuDeviceGetCount.argtypes = [ctypes.POINTER(ctypes.c_int)]
cuda.cuDeviceGetCount.restype = ctypes.c_int

result = cuda.cuInit(0)
if result != 0:
    raise SystemExit(f"cuInit failed: {result}")

count = ctypes.c_int()
result = cuda.cuDeviceGetCount(ctypes.byref(count))
if result != 0:
    raise SystemExit(f"cuDeviceGetCount failed: {result}")
if count.value < 1:
    raise SystemExit(f"cuDeviceGetCount reported {count.value} devices")
"#;

const CUDA_SANDBOX_INIT_PROBE: &str = r#"
import ctypes
import os

runtime = os.environ.get("SANDBOX_RUNTIME")
if runtime != "bwrap":
    raise SystemExit(f"expected SANDBOX_RUNTIME=bwrap, got {runtime!r}")

errors = []
for library_name in ("libcuda.so.1", "libcuda.so"):
    try:
        cuda = ctypes.CDLL(library_name)
        break
    except OSError as exc:
        errors.append(f"{library_name}: {exc}")
else:
    raise SystemExit("; ".join(errors))

cuda.cuInit.argtypes = [ctypes.c_uint]
cuda.cuInit.restype = ctypes.c_int
cuda.cuDeviceGetCount.argtypes = [ctypes.POINTER(ctypes.c_int)]
cuda.cuDeviceGetCount.restype = ctypes.c_int

result = cuda.cuInit(0)
if result != 0:
    raise SystemExit(f"cuInit failed: {result}")

count = ctypes.c_int()
result = cuda.cuDeviceGetCount(ctypes.byref(count))
if result != 0:
    raise SystemExit(f"cuDeviceGetCount failed: {result}")
if count.value < 1:
    raise SystemExit(f"cuDeviceGetCount reported {count.value} devices")
"#;

fn create_env_from_core_vars() -> HashMap<String, String> {
    let policy = ShellEnvironmentPolicy::default();
    create_env(&policy, /*thread_id*/ None)
}

async fn run_command_result(
    command: &[&str],
    permission_profile: &PermissionProfile,
) -> std::result::Result<Output, String> {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(err) => panic!("cwd should exist: {err}"),
    };
    let permission_profile_json = match serde_json::to_string(permission_profile) {
        Ok(permission_profile_json) => permission_profile_json,
        Err(err) => panic!("permission profile should serialize: {err}"),
    };

    let mut args = vec![
        "--sandbox-policy-cwd".to_string(),
        cwd.to_string_lossy().to_string(),
        "--permission-profile".to_string(),
        permission_profile_json,
        "--".to_string(),
    ];
    args.extend(command.iter().map(|entry| (*entry).to_string()));

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_codex-linux-sandbox"));
    cmd.args(args)
        .kill_on_drop(true)
        .current_dir(cwd)
        .env_clear()
        .envs(create_env_from_core_vars())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    match tokio::time::timeout(Duration::from_millis(CUDA_TIMEOUT_MS), cmd.output()).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(err)) => Err(format!("sandbox command should execute: {err}")),
        Err(_) => Err(format!(
            "sandbox command timed out after {CUDA_TIMEOUT_MS} ms"
        )),
    }
}

async fn run_command(command: &[&str], permission_profile: &PermissionProfile) -> Output {
    match run_command_result(command, permission_profile).await {
        Ok(output) => output,
        Err(err) => panic!("{err}"),
    }
}

async fn host_cuda_probe_succeeds() -> bool {
    if !Path::new("/dev/nvidiactl").exists() {
        return false;
    }

    let mut cmd = Command::new("python3");
    cmd.arg("-c")
        .arg(CUDA_HOST_INIT_PROBE)
        .kill_on_drop(true)
        .env_clear()
        .envs(create_env_from_core_vars())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    match tokio::time::timeout(Duration::from_millis(CUDA_TIMEOUT_MS), cmd.output()).await {
        Ok(Ok(output)) => output.status.success(),
        Ok(Err(_)) | Err(_) => false,
    }
}

fn is_bwrap_unavailable_output(output: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr.contains(BWRAP_UNAVAILABLE_ERR)
        || (stderr.contains("Can't mount proc on /newroot/proc")
            && (stderr.contains("Operation not permitted")
                || stderr.contains("Permission denied")
                || stderr.contains("Invalid argument")))
        || stderr.contains("No permissions to create a new namespace")
        || stderr.contains("setting up uid map: Permission denied")
}

async fn should_skip_bwrap_tests() -> bool {
    match run_command_result(&["bash", "-lc", "true"], &PermissionProfile::read_only()).await {
        Ok(output) => !output.status.success() && is_bwrap_unavailable_output(&output),
        Err(_) => true,
    }
}

#[tokio::test]
async fn cuda_profile_allows_cuda_driver_init_under_bwrap() {
    if should_skip_bwrap_tests().await {
        eprintln!("skipping CUDA sandbox smoke test: bwrap sandbox prerequisites are unavailable");
        return;
    }

    if !host_cuda_probe_succeeds().await {
        eprintln!("skipping CUDA sandbox smoke test: host CUDA driver probe is unavailable");
        return;
    }

    let permission_profile = PermissionProfile::read_only()
        .with_hardware_permissions(HardwarePermissions { cuda: true });
    let output = run_command(
        &["python3", "-c", CUDA_SANDBOX_INIT_PROBE],
        &permission_profile,
    )
    .await;

    assert_eq!(
        output.status.success(),
        true,
        "sandboxed CUDA probe failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
