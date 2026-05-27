use super::*;
use codex_protocol::models::CdiPermissions;
use codex_protocol::models::ManagedFileSystemPermissions;
use pretty_assertions::assert_eq;

#[test]
fn legacy_landlock_flag_is_included_when_requested() {
    let command = vec!["/bin/true".to_string()];
    let command_cwd = Path::new("/tmp/link");
    let cwd = Path::new("/tmp");

    let default_bwrap = create_linux_sandbox_command_args(
        command.clone(),
        command_cwd,
        cwd,
        /*use_legacy_landlock*/ false,
        /*allow_network_for_proxy*/ false,
    );
    assert_eq!(
        default_bwrap.contains(&"--use-legacy-landlock".to_string()),
        false
    );

    let legacy_landlock = create_linux_sandbox_command_args(
        command,
        command_cwd,
        cwd,
        /*use_legacy_landlock*/ true,
        /*allow_network_for_proxy*/ false,
    );
    assert_eq!(
        legacy_landlock.contains(&"--use-legacy-landlock".to_string()),
        true
    );
}

#[test]
fn proxy_flag_takes_precedence_over_legacy_landlock() {
    let command = vec!["/bin/true".to_string()];
    let command_cwd = Path::new("/tmp/link");
    let cwd = Path::new("/tmp");
    let permission_profile = PermissionProfile::read_only();

    let args = create_linux_sandbox_command_args_for_permission_profile(
        command,
        command_cwd,
        &permission_profile,
        cwd,
        /*use_legacy_landlock*/ true,
        /*allow_network_for_proxy*/ true,
    );
    assert_eq!(
        args.contains(&"--allow-network-for-proxy".to_string()),
        true
    );
    assert_eq!(args.contains(&"--use-legacy-landlock".to_string()), false);
}

#[test]
fn permission_profile_flag_is_included() {
    let command = vec!["/bin/true".to_string()];
    let command_cwd = Path::new("/tmp/link");
    let cwd = Path::new("/tmp");
    let permission_profile = PermissionProfile::read_only();

    let args = create_linux_sandbox_command_args_for_permission_profile(
        command,
        command_cwd,
        &permission_profile,
        cwd,
        /*use_legacy_landlock*/ true,
        /*allow_network_for_proxy*/ false,
    );

    assert_eq!(
        args.windows(2)
            .any(|window| { window[0] == "--permission-profile" && !window[1].is_empty() }),
        true
    );
    assert_eq!(
        args.windows(2)
            .any(|window| window[0] == "--command-cwd" && window[1] == "/tmp/link"),
        true
    );
}

#[test]
fn permission_profile_flag_preserves_cdi_policy() {
    let command = vec!["/bin/true".to_string()];
    let command_cwd = Path::new("/tmp/link");
    let cwd = Path::new("/tmp");
    let permission_profile = PermissionProfile::Managed {
        file_system: ManagedFileSystemPermissions::Unrestricted,
        network: codex_protocol::protocol::NetworkSandboxPolicy::Enabled,
        cdi: Some(CdiPermissions {
            devices: vec!["nvidia.com/gpu=*".to_string()],
            allowed_devices: Some(vec!["nvidia.com/gpu=0".to_string()]),
            denied_devices: vec!["nvidia.com/gpu=debug-*".to_string()],
        }),
    };

    let args = create_linux_sandbox_command_args_for_permission_profile(
        command,
        command_cwd,
        &permission_profile,
        cwd,
        /*use_legacy_landlock*/ false,
        /*allow_network_for_proxy*/ false,
    );
    let permission_profile_json = args
        .windows(2)
        .find_map(|window| (window[0] == "--permission-profile").then_some(&window[1]))
        .expect("permission profile flag");
    let json: serde_json::Value =
        serde_json::from_str(permission_profile_json).expect("permission profile json");

    assert_eq!(
        json["cdi"],
        serde_json::json!({
            "devices": ["nvidia.com/gpu=*"],
            "allowed_devices": ["nvidia.com/gpu=0"],
            "denied_devices": ["nvidia.com/gpu=debug-*"],
        })
    );
}

#[test]
fn proxy_network_requires_managed_requirements() {
    assert_eq!(
        allow_network_for_proxy(/*enforce_managed_network*/ false),
        false
    );
    assert_eq!(
        allow_network_for_proxy(/*enforce_managed_network*/ true),
        true
    );
}
