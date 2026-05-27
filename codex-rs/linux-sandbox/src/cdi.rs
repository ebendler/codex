use codex_protocol::error::CodexErr;
use codex_protocol::error::Result;
use codex_protocol::models::PermissionProfile;
use std::collections::BTreeSet;
use wildmatch::WildMatchPattern;

use crate::bwrap::BwrapCdiDevice;
use crate::bwrap::BwrapCdiEdits;
use crate::bwrap::BwrapCdiMount;
use crate::cdi_resolver::CdiEditScope;
use crate::cdi_resolver::ResolvedCdiDeviceNode;
use crate::cdi_resolver::ResolvedCdiEdits;
use crate::cdi_resolver::ResolvedCdiMount;
use crate::cdi_resolver::UnsupportedCdiEdit;
use crate::cdi_resolver::UnsupportedCdiEditKind;
use crate::cdi_resolver::resolve_cdi_edits;

type CdiPattern = WildMatchPattern<'*', '?'>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RuntimeCdiPolicy {
    pub requested: Vec<String>,
    pub allowed: Option<Vec<String>>,
    pub denied: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct FilteredCdiDevices {
    pub devices: Vec<String>,
    pub warnings: Vec<String>,
}

impl RuntimeCdiPolicy {
    pub(crate) fn from_permission_profile(permission_profile: &PermissionProfile) -> Option<Self> {
        permission_profile
            .cdi_permissions()
            .map(|cdi| RuntimeCdiPolicy {
                requested: cdi.devices.clone(),
                allowed: cdi.allowed_devices.clone(),
                denied: cdi.denied_devices.clone(),
            })
    }
}

pub(crate) fn resolve_cdi_for_bwrap(policy: &RuntimeCdiPolicy) -> Result<BwrapCdiEdits> {
    let cache = container_device_interface::cache::new_cache(Vec::new());
    let mut cache = cache
        .lock()
        .unwrap_or_else(|_| panic!("CDI cache lock poisoned"));
    let available = cache.list_devices();
    let filtered = expand_and_filter_devices(&available, policy)?;
    let resolved = resolve_cdi_edits(&mut cache, &filtered.devices).map_err(|err| {
        CodexErr::Fatal(format!("failed to resolve CDI devices for sandbox: {err}"))
    })?;
    let mut bwrap = translate_resolved_edits(resolved)?;
    let mut warnings = filtered.warnings;
    warnings.extend(bwrap.warnings);
    bwrap.warnings = warnings;
    Ok(bwrap)
}

pub(crate) fn expand_and_filter_devices(
    available: &[String],
    policy: &RuntimeCdiPolicy,
) -> Result<FilteredCdiDevices> {
    let allowed = policy
        .allowed
        .as_ref()
        .map(|allowed| compile_patterns(allowed));
    let denied = compile_patterns(&policy.denied);
    let mut devices = Vec::new();
    let mut seen_devices = BTreeSet::new();
    let mut warned_denied_devices = BTreeSet::new();
    let mut warnings = Vec::new();

    for selector in &policy.requested {
        let selector_pattern = CdiPattern::new(selector);
        let mut selector_allowed_matches = 0usize;
        for device in available {
            if !selector_pattern.matches(device) {
                continue;
            }
            if let Some(allowed) = &allowed
                && !matches_any(device, allowed)
            {
                continue;
            }
            if matches_any(device, &denied) {
                if warned_denied_devices.insert(device.clone()) {
                    warnings.push(format!(
                        "CDI device {device} is denied by managed policy and will not be added to the sandbox"
                    ));
                }
                continue;
            }
            selector_allowed_matches += 1;
            if seen_devices.insert(device.clone()) {
                devices.push(device.clone());
            }
        }

        if selector_allowed_matches == 0 {
            return Err(CodexErr::Fatal(format!(
                "CDI selector `{selector}` did not match any devices allowed by policy"
            )));
        }
    }

    Ok(FilteredCdiDevices { devices, warnings })
}

pub(crate) fn translate_resolved_edits(edits: ResolvedCdiEdits) -> Result<BwrapCdiEdits> {
    let mut bwrap = BwrapCdiEdits::default();

    for env in edits.env {
        match env.split_once('=') {
            Some((key, value)) if !key.is_empty() => {
                bwrap.env.push((key.to_string(), value.to_string()));
            }
            _ => bwrap.warnings.push(format!(
                "CDI requested malformed environment entry `{env}`, which Codex cannot apply in bubblewrap; dropping env"
            )),
        }
    }

    for device in edits.device_nodes {
        if let Some(warning) = unsupported_device_warning(&device) {
            bwrap.warnings.push(warning);
            continue;
        }
        bwrap.devices.push(BwrapCdiDevice {
            host_path: device.host_path,
            container_path: device.container_path,
        });
    }

    for mount in edits.mounts {
        match translate_mount(&mount) {
            Ok(Some(translated)) => bwrap.mounts.push(translated),
            Ok(None) => {}
            Err(warning) => bwrap.warnings.push(warning),
        }
    }

    for unsupported in edits.unsupported {
        bwrap.warnings.push(unsupported_edit_warning(&unsupported));
    }

    Ok(bwrap)
}

fn compile_patterns(patterns: &[String]) -> Vec<CdiPattern> {
    patterns
        .iter()
        .map(String::as_str)
        .map(CdiPattern::new)
        .collect()
}

fn matches_any(value: &str, patterns: &[CdiPattern]) -> bool {
    patterns.iter().any(|pattern| pattern.matches(value))
}

fn unsupported_device_warning(device: &ResolvedCdiDeviceNode) -> Option<String> {
    if !device.host_path.is_absolute() || !device.container_path.is_absolute() {
        return Some(format!(
            "{} requested device node {} from {}, but Codex only supports absolute device paths in bubblewrap; dropping device node",
            scope_description(&device.scope),
            device.container_path.display(),
            device.host_path.display()
        ));
    }
    if let Some(permissions) = &device.permissions
        && !permissions.is_empty()
        && permissions != "rwm"
    {
        return Some(format!(
            "{} requested device node {} with permissions `{permissions}`, which Codex cannot apply in bubblewrap; dropping device node",
            scope_description(&device.scope),
            device.container_path.display()
        ));
    }
    if let Some(typ) = &device.typ
        && !matches!(typ.as_str(), "c" | "b" | "u")
    {
        return Some(format!(
            "{} requested non-device node {} with type `{typ}`, which Codex cannot apply in bubblewrap; dropping device node",
            scope_description(&device.scope),
            device.container_path.display()
        ));
    }
    if device.uid.is_some() || device.gid.is_some() || device.file_mode.is_some() {
        return Some(format!(
            "{} requested ownership or mode changes for device node {}, which Codex cannot apply in bubblewrap; dropping device node",
            scope_description(&device.scope),
            device.container_path.display()
        ));
    }
    None
}

fn translate_mount(mount: &ResolvedCdiMount) -> std::result::Result<Option<BwrapCdiMount>, String> {
    if !mount.host_path.is_absolute() || !mount.container_path.is_absolute() {
        return Err(format!(
            "{} requested mount {} from {}, but Codex only supports absolute mount paths in bubblewrap; dropping mount",
            scope_description(&mount.scope),
            mount.container_path.display(),
            mount.host_path.display()
        ));
    }
    if let Some(typ) = &mount.typ
        && !typ.is_empty()
        && !matches!(typ.as_str(), "bind" | "none")
    {
        return Err(format!(
            "{} requested mount {} with type `{typ}`, which Codex cannot apply in bubblewrap; dropping mount",
            scope_description(&mount.scope),
            mount.container_path.display()
        ));
    }

    let option_set = mount
        .options
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let bind_mount =
        option_set.is_empty() || option_set.contains("bind") || option_set.contains("rbind");
    if !bind_mount {
        return Err(format!(
            "{} requested mount {} without bind or rbind semantics, which Codex cannot apply in bubblewrap; dropping mount",
            scope_description(&mount.scope),
            mount.container_path.display()
        ));
    }
    let supported_options = ["bind", "rbind", "ro"].into_iter().collect::<BTreeSet<_>>();
    let unsupported_options = option_set
        .difference(&supported_options)
        .copied()
        .collect::<Vec<_>>();
    if !unsupported_options.is_empty() {
        return Err(format!(
            "{} requested mount {} with unsupported options `{}`, which Codex cannot apply in bubblewrap; dropping mount",
            scope_description(&mount.scope),
            mount.container_path.display(),
            unsupported_options.join(",")
        ));
    }

    Ok(Some(BwrapCdiMount {
        host_path: mount.host_path.clone(),
        container_path: mount.container_path.clone(),
        read_only: option_set.contains("ro"),
    }))
}

fn unsupported_edit_warning(unsupported: &UnsupportedCdiEdit) -> String {
    format!(
        "{} requested {}, which Codex cannot apply in bubblewrap; dropping {}",
        scope_description(&unsupported.scope),
        unsupported_kind_label(&unsupported.kind),
        unsupported_kind_label(&unsupported.kind)
    )
}

fn unsupported_kind_label(kind: &UnsupportedCdiEditKind) -> &'static str {
    match kind {
        UnsupportedCdiEditKind::Hooks => "hooks",
        UnsupportedCdiEditKind::NetDevices => "netDevices",
        UnsupportedCdiEditKind::IntelRdt => "intelRdt",
        UnsupportedCdiEditKind::AdditionalGids => "additionalGids",
    }
}

fn scope_description(scope: &CdiEditScope) -> String {
    match scope {
        CdiEditScope::Spec { kind, path } => {
            format!("CDI spec {kind} at {}", path.display())
        }
        CdiEditScope::Device { qualified_name, .. } => {
            format!("CDI device {qualified_name}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use pretty_assertions::assert_eq;

    #[test]
    fn policy_filters_devices_with_deny_winning() {
        let available = vec![
            "nvidia.com/gpu=0".to_string(),
            "nvidia.com/gpu=debug-0".to_string(),
        ];
        let policy = RuntimeCdiPolicy {
            requested: vec!["nvidia.com/gpu=*".to_string()],
            allowed: Some(vec!["nvidia.com/gpu=*".to_string()]),
            denied: vec!["nvidia.com/gpu=debug-*".to_string()],
        };

        let result = expand_and_filter_devices(&available, &policy).unwrap();

        assert_eq!(
            result,
            FilteredCdiDevices {
                devices: vec!["nvidia.com/gpu=0".to_string()],
                warnings: vec![
                    "CDI device nvidia.com/gpu=debug-0 is denied by managed policy and will not be added to the sandbox".to_string()
                ],
            }
        );
    }

    #[test]
    fn policy_errors_when_selector_has_no_allowed_matches() {
        let available = vec!["nvidia.com/gpu=debug-0".to_string()];
        let policy = RuntimeCdiPolicy {
            requested: vec!["nvidia.com/gpu=*".to_string()],
            allowed: Some(vec!["nvidia.com/gpu=*".to_string()]),
            denied: vec!["nvidia.com/gpu=debug-*".to_string()],
        };

        let err = expand_and_filter_devices(&available, &policy).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Fatal error: CDI selector `nvidia.com/gpu=*` did not match any devices allowed by policy"
        );
    }

    #[test]
    fn unsupported_cdi_edits_become_warnings() {
        let edits = ResolvedCdiEdits {
            unsupported: vec![UnsupportedCdiEdit {
                kind: UnsupportedCdiEditKind::Hooks,
                count: 1,
                scope: device_scope(),
            }],
            ..Default::default()
        };

        let bwrap = translate_resolved_edits(edits).unwrap();

        assert_eq!(
            bwrap.warnings,
            vec![
                "CDI device vendor.com/device=0 requested hooks, which Codex cannot apply in bubblewrap; dropping hooks".to_string()
            ]
        );
    }

    #[test]
    fn unsupported_cdi_device_details_become_warnings() {
        let edits = ResolvedCdiEdits {
            device_nodes: vec![
                ResolvedCdiDeviceNode {
                    host_path: PathBuf::from("/dev/vendor0"),
                    container_path: PathBuf::from("/dev/vendor0"),
                    typ: Some("c".to_string()),
                    major: Some(1),
                    minor: Some(2),
                    file_mode: None,
                    permissions: Some("r".to_string()),
                    uid: None,
                    gid: None,
                    scope: device_scope(),
                },
                ResolvedCdiDeviceNode {
                    host_path: PathBuf::from("/dev/vendor1"),
                    container_path: PathBuf::from("/dev/vendor1"),
                    typ: Some("c".to_string()),
                    major: Some(1),
                    minor: Some(3),
                    file_mode: Some(0o600),
                    permissions: None,
                    uid: None,
                    gid: None,
                    scope: device_scope(),
                },
                ResolvedCdiDeviceNode {
                    host_path: PathBuf::from("/tmp/vendor-fifo"),
                    container_path: PathBuf::from("/tmp/vendor-fifo"),
                    typ: Some("p".to_string()),
                    major: None,
                    minor: None,
                    file_mode: None,
                    permissions: None,
                    uid: None,
                    gid: None,
                    scope: device_scope(),
                },
            ],
            ..Default::default()
        };

        let bwrap = translate_resolved_edits(edits).unwrap();

        assert_eq!(bwrap.devices, Vec::<BwrapCdiDevice>::new());
        assert_eq!(
            bwrap.warnings,
            vec![
                "CDI device vendor.com/device=0 requested device node /dev/vendor0 with permissions `r`, which Codex cannot apply in bubblewrap; dropping device node".to_string(),
                "CDI device vendor.com/device=0 requested ownership or mode changes for device node /dev/vendor1, which Codex cannot apply in bubblewrap; dropping device node".to_string(),
                "CDI device vendor.com/device=0 requested non-device node /tmp/vendor-fifo with type `p`, which Codex cannot apply in bubblewrap; dropping device node".to_string(),
            ]
        );
    }

    #[test]
    fn translates_clean_env_device_and_mount_edits() {
        let edits = ResolvedCdiEdits {
            env: vec!["VENDOR_VISIBLE_DEVICES=0".to_string()],
            device_nodes: vec![ResolvedCdiDeviceNode {
                host_path: PathBuf::from("/dev/vendor0"),
                container_path: PathBuf::from("/dev/vendor0"),
                typ: Some("c".to_string()),
                major: Some(1),
                minor: Some(2),
                file_mode: None,
                permissions: Some("rwm".to_string()),
                uid: None,
                gid: None,
                scope: device_scope(),
            }],
            mounts: vec![
                ResolvedCdiMount {
                    host_path: PathBuf::from("/opt/vendor/lib.so"),
                    container_path: PathBuf::from("/opt/vendor/lib.so"),
                    typ: None,
                    options: vec!["bind".to_string(), "ro".to_string()],
                    scope: device_scope(),
                },
                ResolvedCdiMount {
                    host_path: PathBuf::from("/opt/vendor/bin"),
                    container_path: PathBuf::from("/opt/vendor/bin"),
                    typ: None,
                    options: Vec::new(),
                    scope: device_scope(),
                },
            ],
            ..Default::default()
        };

        let bwrap = translate_resolved_edits(edits).unwrap();

        assert_eq!(
            bwrap,
            BwrapCdiEdits {
                env: vec![("VENDOR_VISIBLE_DEVICES".to_string(), "0".to_string())],
                devices: vec![BwrapCdiDevice {
                    host_path: PathBuf::from("/dev/vendor0"),
                    container_path: PathBuf::from("/dev/vendor0"),
                }],
                mounts: vec![
                    BwrapCdiMount {
                        host_path: PathBuf::from("/opt/vendor/lib.so"),
                        container_path: PathBuf::from("/opt/vendor/lib.so"),
                        read_only: true,
                    },
                    BwrapCdiMount {
                        host_path: PathBuf::from("/opt/vendor/bin"),
                        container_path: PathBuf::from("/opt/vendor/bin"),
                        read_only: false,
                    },
                ],
                warnings: Vec::new(),
            }
        );
    }

    #[test]
    fn unsupported_mount_options_become_warnings() {
        let edits = ResolvedCdiEdits {
            mounts: vec![
                ResolvedCdiMount {
                    host_path: PathBuf::from("/opt/vendor/lib.so"),
                    container_path: PathBuf::from("/opt/vendor/lib.so"),
                    typ: None,
                    options: vec!["nosuid".to_string()],
                    scope: device_scope(),
                },
                ResolvedCdiMount {
                    host_path: PathBuf::from("/opt/vendor/bin"),
                    container_path: PathBuf::from("/opt/vendor/bin"),
                    typ: None,
                    options: vec!["bind".to_string(), "nodev".to_string()],
                    scope: device_scope(),
                },
                ResolvedCdiMount {
                    host_path: PathBuf::from("/opt/vendor/tmp"),
                    container_path: PathBuf::from("/opt/vendor/tmp"),
                    typ: Some("tmpfs".to_string()),
                    options: Vec::new(),
                    scope: device_scope(),
                },
            ],
            ..Default::default()
        };

        let bwrap = translate_resolved_edits(edits).unwrap();

        assert_eq!(bwrap.mounts, Vec::<BwrapCdiMount>::new());
        assert_eq!(
            bwrap.warnings,
            vec![
                "CDI device vendor.com/device=0 requested mount /opt/vendor/lib.so without bind or rbind semantics, which Codex cannot apply in bubblewrap; dropping mount".to_string(),
                "CDI device vendor.com/device=0 requested mount /opt/vendor/bin with unsupported options `nodev`, which Codex cannot apply in bubblewrap; dropping mount".to_string(),
                "CDI device vendor.com/device=0 requested mount /opt/vendor/tmp with type `tmpfs`, which Codex cannot apply in bubblewrap; dropping mount".to_string(),
            ]
        );
    }

    fn device_scope() -> CdiEditScope {
        CdiEditScope::Device {
            qualified_name: "vendor.com/device=0".to_string(),
            spec_kind: "vendor.com/device".to_string(),
            spec_path: PathBuf::from("/etc/cdi/vendor.yaml"),
        }
    }
}
