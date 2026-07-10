use std::collections::HashSet;
use std::path::PathBuf;

use container_device_interface::cache::Cache;
use container_device_interface::container_edits::ContainerEdits;
use container_device_interface::container_edits_unix::device_info_from_path;
use serde::Deserialize;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ResolvedCdiEdits {
    pub env: Vec<String>,
    pub device_nodes: Vec<ResolvedCdiDeviceNode>,
    pub mounts: Vec<ResolvedCdiMount>,
    pub unsupported: Vec<UnsupportedCdiEdit>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResolvedCdiDeviceNode {
    pub host_path: PathBuf,
    pub container_path: PathBuf,
    pub typ: Option<String>,
    pub major: Option<i64>,
    pub minor: Option<i64>,
    pub file_mode: Option<libc::mode_t>,
    pub permissions: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub scope: CdiEditScope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResolvedCdiMount {
    pub host_path: PathBuf,
    pub container_path: PathBuf,
    pub typ: Option<String>,
    pub options: Vec<String>,
    pub scope: CdiEditScope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UnsupportedCdiEdit {
    pub kind: UnsupportedCdiEditKind,
    pub count: usize,
    pub scope: CdiEditScope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum UnsupportedCdiEditKind {
    Hooks,
    NetDevices,
    IntelRdt,
    AdditionalGids,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CdiEditScope {
    Spec {
        kind: String,
        path: PathBuf,
    },
    Device {
        qualified_name: String,
        spec_kind: String,
        spec_path: PathBuf,
    },
}

pub(super) fn resolve_cdi_edits(
    cache: &mut Cache,
    devices: &[String],
) -> Result<ResolvedCdiEdits, String> {
    let mut resolved = ResolvedCdiEdits::default();
    let mut seen_specs = HashSet::new();
    let mut unresolved = Vec::new();

    for qualified_name in devices {
        let Some(device) = cache.get_device(qualified_name).cloned() else {
            unresolved.push(qualified_name.clone());
            continue;
        };
        let mut spec = device.get_spec();
        let spec_kind = format!("{}/{}", spec.get_vendor(), spec.get_class());
        let spec_path = PathBuf::from(spec.get_path());

        if seen_specs.insert(spec.clone())
            && let Some(edits) = spec.edits()
        {
            resolved.append_container_edits(
                &edits,
                CdiEditScope::Spec {
                    kind: spec_kind.clone(),
                    path: spec_path.clone(),
                },
            )?;
        }

        resolved.append_container_edits(
            &device.edits(),
            CdiEditScope::Device {
                qualified_name: qualified_name.clone(),
                spec_kind,
                spec_path,
            },
        )?;
    }

    if !unresolved.is_empty() {
        return Err(format!(
            "unresolvable CDI devices {}",
            unresolved.join(", ")
        ));
    }

    Ok(resolved)
}

impl ResolvedCdiEdits {
    fn append_container_edits(
        &mut self,
        edits: &ContainerEdits,
        scope: CdiEditScope,
    ) -> Result<(), String> {
        let edits = decode_container_edits(edits)?;

        self.env.extend(edits.env.unwrap_or_default());

        for device_node in edits.device_nodes.unwrap_or_default() {
            self.device_nodes
                .push(resolve_device_node(device_node, scope.clone())?);
        }
        for mount in edits.mounts.unwrap_or_default() {
            self.mounts.push(ResolvedCdiMount {
                host_path: PathBuf::from(mount.host_path),
                container_path: PathBuf::from(mount.container_path),
                typ: mount.typ,
                options: mount.options.unwrap_or_default(),
                scope: scope.clone(),
            });
        }

        self.report_unsupported(
            UnsupportedCdiEditKind::Hooks,
            edits.hooks.as_ref().map_or(0, Vec::len),
            scope.clone(),
        );
        self.report_unsupported(
            UnsupportedCdiEditKind::NetDevices,
            edits.net_devices.as_ref().map_or(0, Vec::len),
            scope.clone(),
        );
        self.report_unsupported(
            UnsupportedCdiEditKind::IntelRdt,
            usize::from(edits.intel_rdt.is_some()),
            scope.clone(),
        );
        self.report_unsupported(
            UnsupportedCdiEditKind::AdditionalGids,
            edits.additional_gids.as_ref().map_or(0, Vec::len),
            scope,
        );

        Ok(())
    }

    fn report_unsupported(
        &mut self,
        kind: UnsupportedCdiEditKind,
        count: usize,
        scope: CdiEditScope,
    ) {
        if count > 0 {
            self.unsupported
                .push(UnsupportedCdiEdit { kind, count, scope });
        }
    }
}

fn decode_container_edits(edits: &ContainerEdits) -> Result<RawContainerEdits, String> {
    // The published crate exposes container edits through serializable CDI
    // schema types, but keeps several schema fields private. Decode that public
    // wire representation so Codex can translate the supported subset without
    // depending on fork-only accessors.
    let value = serde_json::to_value(&edits.container_edits)
        .map_err(|err| format!("failed to encode CDI container edits: {err}"))?;
    serde_json::from_value(value)
        .map_err(|err| format!("failed to decode CDI container edits: {err}"))
}

fn resolve_device_node(
    node: RawDeviceNode,
    scope: CdiEditScope,
) -> Result<ResolvedCdiDeviceNode, String> {
    let host_path = node.host_path.unwrap_or_else(|| node.path.clone());
    let (host_type, host_major, host_minor) = device_info_from_path(&host_path)
        .map_err(|err| format!("failed to inspect CDI device node host path {host_path}: {err}"))?;
    let mut typ = node.typ.filter(|typ| !typ.is_empty());

    match typ.as_deref() {
        None => typ = Some(host_type),
        Some(node_type) if !device_types_match(node_type, &host_type) => {
            return Err(format!(
                "CDI device ({}, {}), host type mismatch ({}, {})",
                node.path, host_path, node_type, host_type
            ));
        }
        _ => {}
    }

    let is_fifo = typ.as_deref() == Some("p");
    let major = node.major.or((!is_fifo).then_some(host_major));
    let minor = node.minor.or((!is_fifo).then_some(host_minor));

    Ok(ResolvedCdiDeviceNode {
        host_path: PathBuf::from(host_path),
        container_path: PathBuf::from(node.path),
        typ,
        major,
        minor,
        file_mode: node.file_mode,
        permissions: node.permissions,
        uid: node.uid,
        gid: node.gid,
        scope,
    })
}

fn device_types_match(node_type: &str, host_type: &str) -> bool {
    node_type == host_type || matches!((node_type, host_type), ("u", "c"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawContainerEdits {
    env: Option<Vec<String>>,
    device_nodes: Option<Vec<RawDeviceNode>>,
    net_devices: Option<Vec<serde_json::Value>>,
    hooks: Option<Vec<serde_json::Value>>,
    mounts: Option<Vec<RawMount>>,
    intel_rdt: Option<serde_json::Value>,
    additional_gids: Option<Vec<u32>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDeviceNode {
    path: String,
    host_path: Option<String>,
    #[serde(rename = "type")]
    typ: Option<String>,
    major: Option<i64>,
    minor: Option<i64>,
    file_mode: Option<libc::mode_t>,
    permissions: Option<String>,
    uid: Option<u32>,
    gid: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMount {
    host_path: String,
    container_path: String,
    #[serde(rename = "type")]
    typ: Option<String>,
    options: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use container_device_interface::spec_dirs::with_spec_dirs;
    use pretty_assertions::assert_eq;

    #[test]
    fn resolves_edits_through_the_published_crate_api() {
        let spec_dir = tempfile::tempdir().expect("create CDI spec directory");
        let spec_path = spec_dir.path().join("vendor.yaml");
        std::fs::write(
            &spec_path,
            r#"cdiVersion: "1.1.0"
kind: "vendor.com/device"
containerEdits:
  env:
    - "GLOBAL=1"
  hooks:
    - hookName: "prestart"
      path: "/bin/true"
devices:
  - name: "gpu0"
    containerEdits:
      env:
        - "DEVICE=1"
      deviceNodes:
        - path: "/dev/cdi-null"
          hostPath: "/dev/null"
          permissions: "rwm"
      mounts:
        - hostPath: "/tmp"
          containerPath: "/mnt/host-tmp"
          options: ["bind", "ro"]
"#,
        )
        .expect("write CDI spec");
        let mut cache = Cache::default();
        with_spec_dirs(&[spec_dir.path().to_str().expect("UTF-8 temp path")])(&mut cache);
        cache.refresh().expect("refresh CDI cache");

        let resolved = resolve_cdi_edits(&mut cache, &["vendor.com/device=gpu0".to_string()])
            .expect("resolve CDI edits");

        assert_eq!(
            resolved,
            ResolvedCdiEdits {
                env: vec!["GLOBAL=1".to_string(), "DEVICE=1".to_string()],
                device_nodes: vec![ResolvedCdiDeviceNode {
                    host_path: PathBuf::from("/dev/null"),
                    container_path: PathBuf::from("/dev/cdi-null"),
                    typ: Some("c".to_string()),
                    major: Some(1),
                    minor: Some(3),
                    file_mode: None,
                    permissions: Some("rwm".to_string()),
                    uid: None,
                    gid: None,
                    scope: CdiEditScope::Device {
                        qualified_name: "vendor.com/device=gpu0".to_string(),
                        spec_kind: "vendor.com/device".to_string(),
                        spec_path: spec_path.clone(),
                    },
                }],
                mounts: vec![ResolvedCdiMount {
                    host_path: PathBuf::from("/tmp"),
                    container_path: PathBuf::from("/mnt/host-tmp"),
                    typ: None,
                    options: vec!["bind".to_string(), "ro".to_string()],
                    scope: CdiEditScope::Device {
                        qualified_name: "vendor.com/device=gpu0".to_string(),
                        spec_kind: "vendor.com/device".to_string(),
                        spec_path: spec_path.clone(),
                    },
                }],
                unsupported: vec![UnsupportedCdiEdit {
                    kind: UnsupportedCdiEditKind::Hooks,
                    count: 1,
                    scope: CdiEditScope::Spec {
                        kind: "vendor.com/device".to_string(),
                        path: spec_path,
                    },
                }],
            }
        );
    }
}
