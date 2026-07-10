use std::path::PathBuf;

use clap::Parser;
use reportify::new_whatever_type;
use reportify::ResultExt;
use xscript::read_str;
use xscript::run;
use xscript::LocalEnv;
use xscript::Out;
use xscript::Run;

new_whatever_type! {
    /// Error running an xtask.
    pub XtaskError
}

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(subcommand)]
    task: Task,
}

#[derive(Debug, Parser)]
pub enum Task {
    Doc,
    Build,
    BuildBinaries { target: Option<String> },
}

pub fn project_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path
}

pub fn get_target_dir() -> PathBuf {
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        target_dir.into()
    } else {
        project_path().join("target")
    }
}

pub fn build_binaries(target: &str) -> reportify::Result<(), XtaskError> {
    let mut env = LocalEnv::new(project_path());
    let git_version = read_str!(env, ["git", "describe", "--tags", "--always"])
        .whatever("unable to determine git version")?;
    env.set_var("RUGIX_GIT_VERSION", git_version.trim());
    run!(
        env,
        [
            "cargo",
            "build",
            "--release",
            "--target",
            target,
            "--bin",
            "rugix-*",
            "--bin",
            "rugix-*",
        ]
        .with_stdout(Out::Inherit)
        .with_stderr(Out::Inherit)
    )
    .whatever("unable to build binaries")?;
    let binaries_dir = project_path().join("build/binaries").join(target);
    if binaries_dir.exists() {
        std::fs::remove_dir_all(&binaries_dir)
            .whatever("unable to remove existing binaries directory")
            .field_debug("path", &binaries_dir)?;
    }
    std::fs::create_dir_all(&binaries_dir)
        .whatever("unable to create binaries directory")
        .field_debug("path", &binaries_dir)?;
    let target_dir = get_target_dir().join(target).join("release");
    for entry in std::fs::read_dir(&target_dir)
        .whatever("unable to read target directory")
        .field_debug("path", &target_dir)?
    {
        let entry = entry.whatever("unable to read directory entry")?;
        let file_type = entry
            .file_type()
            .whatever("unable to determine file type")
            .field_debug("path", entry.path())?;
        if !file_type.is_file() {
            continue;
        }
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        if !(file_name.starts_with("rugix-") || file_name.starts_with("rugix-"))
            || file_name.ends_with(".d")
        {
            continue;
        }
        std::fs::copy(entry.path(), binaries_dir.join(&file_name))
            .whatever("unable to copy binary")
            .field("name", file_name)?;
    }
    Ok(())
}

fn main() -> reportify::Result<(), XtaskError> {
    let args = Args::parse();
    let env = LocalEnv::new(project_path());
    match args.task {
        Task::Doc => {
            run!(
                env,
                ["cargo", "+nightly", "doc", "--document-private-items",]
                    .with_stdout(Out::Inherit)
                    .with_stderr(Out::Inherit)
            )
            .whatever("unable to build documentation")?;
        }
        Task::BuildBinaries { target } => {
            let target = target.as_deref().unwrap_or("aarch64-unknown-linux-musl");
            build_binaries(target)?;
        }
        Task::Build => {
            build_binaries("aarch64-unknown-linux-musl")?;
            build_binaries("x86_64-unknown-linux-musl")?;
        }
    }
    Ok(())
}
