use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use clap::Parser;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const GENERATED_DEVCONTAINER_DIRNAME: &str = ".codex-devcontainer";

/// Materialize and launch the secure customer devcontainer profile.
#[derive(Debug, Parser)]
pub struct DevcontainerCli {
    /// Workspace where the secure profile should be written.
    #[arg(long = "workspace-folder", value_name = "DIR", default_value = ".")]
    workspace_folder: PathBuf,

    /// Only write the secure profile files; do not run `devcontainer up`.
    #[arg(long = "write-only", default_value_t = false)]
    write_only: bool,

    /// Overwrite existing secure profile files when their contents differ.
    #[arg(long = "force", default_value_t = false)]
    force: bool,

    /// Optional prompt to pass to Codex inside the devcontainer after setup.
    #[arg(
        value_name = "PROMPT",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    prompt: Vec<String>,
}

struct SecureProfileAsset {
    file_name: &'static str,
    contents: &'static str,
}

const SECURE_PROFILE_ASSETS: &[SecureProfileAsset] = &[
    SecureProfileAsset {
        file_name: "Dockerfile.secure",
        contents: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.devcontainer/Dockerfile.secure"
        )),
    },
    SecureProfileAsset {
        file_name: "devcontainer.secure.json",
        contents: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.devcontainer/devcontainer.secure.json"
        )),
    },
    SecureProfileAsset {
        file_name: "init-firewall.sh",
        contents: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.devcontainer/init-firewall.sh"
        )),
    },
    SecureProfileAsset {
        file_name: "post_install.py",
        contents: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.devcontainer/post_install.py"
        )),
    },
    SecureProfileAsset {
        file_name: "post-start.sh",
        contents: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.devcontainer/post-start.sh"
        )),
    },
];

impl DevcontainerCli {
    pub fn run(self) -> Result<()> {
        run_devcontainer(self)
    }

    fn prompt_text(&self) -> Option<String> {
        (!self.prompt.is_empty()).then(|| self.prompt.join(" "))
    }
}

fn run_devcontainer(args: DevcontainerCli) -> Result<()> {
    let workspace_folder = args
        .workspace_folder
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", args.workspace_folder.display()))?;
    let devcontainer_dir = workspace_folder.join(GENERATED_DEVCONTAINER_DIRNAME);
    let prompt = args.prompt_text();

    if args.write_only && prompt.is_some() {
        bail!("cannot pass a prompt together with --write-only");
    }

    let write_summary = materialize_secure_profile(&devcontainer_dir, args.force)?;
    println!(
        "Secure profile files: {} written, {} unchanged",
        write_summary.written, write_summary.unchanged
    );

    if args.write_only {
        println!(
            "Wrote secure devcontainer profile to {}",
            devcontainer_dir.display()
        );
        return Ok(());
    }

    let devcontainer = ensure_devcontainer_cli_available()?;
    let docker_version = ensure_docker_engine_available()?;
    println!("Docker engine: {docker_version}");

    let config = devcontainer_dir.join("devcontainer.secure.json");
    let up_status = Command::new(&devcontainer)
        .arg("up")
        .arg("--workspace-folder")
        .arg(&workspace_folder)
        .arg("--config")
        .arg(&config)
        .status()
        .with_context(|| format!("failed to run `{}`", devcontainer.display()))?;
    if !up_status.success() {
        bail!("`devcontainer up` failed with status {up_status}");
    }

    if let Some(prompt) = prompt {
        let exec_status =
            build_exec_codex_command(&devcontainer, &workspace_folder, &config, &prompt)
                .status()
                .with_context(|| format!("failed to run `{}`", devcontainer.display()))?;
        if !exec_status.success() {
            bail!("`devcontainer exec` failed with status {exec_status}");
        }
    }

    Ok(())
}

#[derive(Debug, Default, Eq, PartialEq)]
struct WriteSummary {
    written: usize,
    unchanged: usize,
}

fn materialize_secure_profile(devcontainer_dir: &Path, force: bool) -> Result<WriteSummary> {
    fs::create_dir_all(devcontainer_dir)
        .with_context(|| format!("failed to create {}", devcontainer_dir.display()))?;

    let mut summary = WriteSummary::default();
    for asset in SECURE_PROFILE_ASSETS {
        let destination = devcontainer_dir.join(asset.file_name);
        let contents = rendered_asset_contents(asset);
        match fs::read(&destination) {
            Ok(existing) if existing == contents.as_bytes() => {
                summary.unchanged += 1;
            }
            Ok(_) if !force => {
                bail!(
                    "{} already exists with different contents; rerun with --force to overwrite it",
                    destination.display()
                );
            }
            Ok(_) => {
                fs::write(&destination, &contents)
                    .with_context(|| format!("failed to write {}", destination.display()))?;
                summary.written += 1;
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                fs::write(&destination, &contents)
                    .with_context(|| format!("failed to write {}", destination.display()))?;
                summary.written += 1;
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to read {}", destination.display()));
            }
        }
    }

    Ok(summary)
}

fn build_exec_codex_command(
    devcontainer: &Path,
    workspace_folder: &Path,
    config: &Path,
    prompt: &str,
) -> Command {
    let mut command = Command::new(devcontainer);
    command
        .arg("exec")
        .arg("--workspace-folder")
        .arg(workspace_folder)
        .arg("--config")
        .arg(config)
        .arg("codex")
        .arg("--")
        .arg(prompt);
    command
}

fn rendered_asset_contents(asset: &SecureProfileAsset) -> String {
    match asset.file_name {
        "Dockerfile.secure" => asset
            .contents
            .replace(".devcontainer/", ".codex-devcontainer/"),
        _ => asset.contents.to_string(),
    }
}

fn ensure_devcontainer_cli_available() -> Result<PathBuf> {
    let devcontainer = which::which("devcontainer").context(
        "could not find `devcontainer` on PATH; install @devcontainers/cli or reinstall Codex via npm so the bundled dependency is available",
    )?;
    let output = Command::new(&devcontainer)
        .arg("--version")
        .output()
        .with_context(|| format!("failed to run `{}`", devcontainer.display()))?;
    if !output.status.success() {
        bail!(
            "`{}` exists but `--version` failed with status {}",
            devcontainer.display(),
            output.status
        );
    }
    Ok(devcontainer)
}

fn ensure_docker_engine_available() -> Result<String> {
    let docker = which::which("docker").context(
        "could not find `docker` on PATH; install Docker and ensure the CLI is available",
    )?;
    let output = Command::new(&docker)
        .arg("info")
        .arg("--format")
        .arg("{{.ServerVersion}}")
        .output()
        .with_context(|| format!("failed to run `{}`", docker.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            bail!("Docker is installed but the engine is not available");
        }
        bail!("Docker is installed but the engine is not available: {stderr}");
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() {
        bail!("Docker is installed but did not report a server version");
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn devcontainer_parses_write_only() {
        let cli = DevcontainerCli::try_parse_from([
            "devcontainer",
            "--workspace-folder",
            "/tmp/workspace",
            "--write-only",
        ])
        .expect("parse");

        assert_eq!(cli.workspace_folder, PathBuf::from("/tmp/workspace"));
        assert!(cli.write_only);
        assert!(!cli.force);
        assert_eq!(cli.prompt_text(), None);
    }

    #[test]
    fn devcontainer_parses_prompt_like_sandbox_args() {
        let cli = DevcontainerCli::try_parse_from([
            "devcontainer",
            "--workspace-folder",
            "/tmp/workspace",
            "make",
            "me",
            "a",
            "sandwich",
        ])
        .expect("parse");

        assert_eq!(cli.prompt_text().as_deref(), Some("make me a sandwich"));
    }

    #[test]
    fn exec_codex_command_passes_prompt_after_double_dash() {
        let command = build_exec_codex_command(
            Path::new("/tmp/devcontainer"),
            Path::new("/tmp/workspace"),
            Path::new("/tmp/workspace/.codex-devcontainer/devcontainer.secure.json"),
            "--help me",
        );

        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            args,
            vec![
                "exec",
                "--workspace-folder",
                "/tmp/workspace",
                "--config",
                "/tmp/workspace/.codex-devcontainer/devcontainer.secure.json",
                "codex",
                "--",
                "--help me",
            ]
        );
    }

    #[test]
    fn materialize_secure_profile_writes_all_assets() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let devcontainer_dir = tempdir.path().join(GENERATED_DEVCONTAINER_DIRNAME);

        let summary =
            materialize_secure_profile(&devcontainer_dir, /*force*/ false).expect("write");

        assert_eq!(
            summary,
            WriteSummary {
                written: SECURE_PROFILE_ASSETS.len(),
                unchanged: 0,
            }
        );
        for asset in SECURE_PROFILE_ASSETS {
            let path = devcontainer_dir.join(asset.file_name);
            assert_eq!(
                fs::read_to_string(path).expect("read"),
                rendered_asset_contents(asset)
            );
        }
    }

    #[test]
    fn materialized_dockerfile_uses_generated_folder_paths() {
        let dockerfile = rendered_asset_contents(&SECURE_PROFILE_ASSETS[0]);

        assert!(dockerfile.contains("COPY .codex-devcontainer/init-firewall.sh"));
        assert!(!dockerfile.contains("COPY .devcontainer/init-firewall.sh"));
    }

    #[test]
    fn materialize_secure_profile_rejects_conflicts_without_force() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let devcontainer_dir = tempdir.path().join(GENERATED_DEVCONTAINER_DIRNAME);
        fs::create_dir_all(&devcontainer_dir).expect("mkdir");
        fs::write(
            devcontainer_dir.join("devcontainer.secure.json"),
            "{ \"name\": \"custom\" }\n",
        )
        .expect("write conflict");

        let err =
            materialize_secure_profile(&devcontainer_dir, /*force*/ false).expect_err("conflict");

        assert!(
            err.to_string().contains("--force"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn materialize_secure_profile_overwrites_conflicts_with_force() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let devcontainer_dir = tempdir.path().join(GENERATED_DEVCONTAINER_DIRNAME);
        fs::create_dir_all(&devcontainer_dir).expect("mkdir");
        fs::write(
            devcontainer_dir.join("devcontainer.secure.json"),
            "{ \"name\": \"custom\" }\n",
        )
        .expect("write conflict");

        let summary = materialize_secure_profile(&devcontainer_dir, /*force*/ true).expect("write");

        assert_eq!(
            summary,
            WriteSummary {
                written: SECURE_PROFILE_ASSETS.len(),
                unchanged: 0,
            }
        );
        assert_eq!(
            fs::read_to_string(devcontainer_dir.join("devcontainer.secure.json")).expect("read"),
            rendered_asset_contents(&SECURE_PROFILE_ASSETS[1])
        );
    }
}
