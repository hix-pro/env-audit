use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use walkdir::{DirEntry, WalkDir};

use crate::dotenv::{self, EnvKind};
use crate::patterns::Language;

pub const MAX_FILE_SIZE: u64 = 1024 * 1024;

const IGNORED_DIRECTORIES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    "coverage",
    "vendor",
];

const LOCKFILES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "cargo.lock",
    "go.sum",
    "composer.lock",
    "gemfile.lock",
    "poetry.lock",
    "pipfile.lock",
    "uv.lock",
    "flake.lock",
];

#[derive(Debug, Clone)]
pub struct RawSource {
    pub relative: String,
    pub language: Language,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct RawEnvFile {
    pub relative: String,
    pub kind: EnvKind,
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKind {
    Compose,
    Workflow,
}

#[derive(Debug, Clone)]
pub struct RawConfigFile {
    pub relative: String,
    pub kind: ConfigKind,
    pub content: String,
}

#[derive(Debug)]
pub struct Collected {
    /// Canonical scan root.
    pub root: PathBuf,
    /// Root as the user wrote it, used in reports.
    pub root_display: String,
    pub sources: Vec<RawSource>,
    pub env_files: Vec<RawEnvFile>,
    pub configs: Vec<RawConfigFile>,
    pub files_scanned: usize,
}

/// Walks a repository and reads the files relevant to an environment audit.
pub fn collect(path: &Path) -> Result<Collected> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("cannot access scan path `{}`", path.display()))?;
    if !metadata.is_dir() {
        bail!("scan target is not a directory: {}", path.display());
    }

    let root = fs::canonicalize(path)
        .with_context(|| format!("cannot resolve scan path `{}`", path.display()))?;
    let root_display = if path.as_os_str().is_empty() {
        ".".to_owned()
    } else {
        path.display().to_string()
    };

    let mut collected = Collected {
        root: root.clone(),
        root_display,
        sources: Vec::new(),
        env_files: Vec::new(),
        configs: Vec::new(),
        files_scanned: 0,
    };

    let entries = WalkDir::new(&root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| !is_ignored_directory(entry));

    for entry in entries {
        let entry = entry.context("failed while walking the scan tree")?;
        if entry.depth() == 0 {
            continue;
        }

        let file_type = entry.file_type();
        if file_type.is_symlink() || !file_type.is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy();
        if is_lockfile(&name) {
            continue;
        }

        let size = entry
            .metadata()
            .with_context(|| format!("cannot stat `{}`", entry.path().display()))?
            .len();
        if size > MAX_FILE_SIZE {
            continue;
        }

        let relative = relative_path(entry.path(), &root);
        let extension = Path::new(name.as_ref())
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();

        let env_kind = dotenv::classify_env_file(&name);
        let config_kind = config_kind(&relative, &name);
        let language = Language::from_extension(extension);

        if env_kind.is_none() && config_kind.is_none() && language.is_none() {
            continue;
        }

        let Some(content) = read_text(entry.path(), size)? else {
            continue;
        };
        collected.files_scanned += 1;

        if let Some(kind) = env_kind {
            collected.env_files.push(RawEnvFile {
                relative,
                kind,
                content,
            });
        } else if let Some(kind) = config_kind {
            collected.configs.push(RawConfigFile {
                relative,
                kind,
                content,
            });
        } else if let Some(language) = language {
            collected.sources.push(RawSource {
                relative,
                language,
                content,
            });
        }
    }

    Ok(collected)
}

/// Reads an env file referenced from a Compose `env_file` entry. References
/// outside the scan root, symlinks, missing files, and oversized files are
/// ignored. Only the scan root and its descendants can ever be read.
pub fn read_referenced_env_file(root: &Path, candidate: &Path) -> Result<Option<RawEnvFile>> {
    let symlink_metadata = match fs::symlink_metadata(candidate) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot stat `{}`", candidate.display()));
        }
    };
    if symlink_metadata.file_type().is_symlink() || !symlink_metadata.is_file() {
        return Ok(None);
    }
    if symlink_metadata.len() > MAX_FILE_SIZE {
        return Ok(None);
    }

    let canonical = match fs::canonicalize(candidate) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot resolve `{}`", candidate.display()));
        }
    };
    if !canonical.starts_with(root) {
        return Ok(None);
    }

    let Some(content) = read_text(&canonical, symlink_metadata.len())? else {
        return Ok(None);
    };
    let name = canonical
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let kind = dotenv::classify_env_file(&name).unwrap_or(EnvKind::Real);

    Ok(Some(RawEnvFile {
        relative: relative_path(&canonical, root),
        kind,
        content,
    }))
}

fn is_ignored_directory(entry: &DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    IGNORED_DIRECTORIES.contains(&name.as_ref())
}

fn is_lockfile(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    LOCKFILES.contains(&lower.as_str())
}

fn config_kind(relative: &str, name: &str) -> Option<ConfigKind> {
    if is_compose_file(name) {
        return Some(ConfigKind::Compose);
    }
    let lower = name.to_ascii_lowercase();
    if relative.starts_with(".github/workflows/")
        && (lower.ends_with(".yml") || lower.ends_with(".yaml"))
    {
        return Some(ConfigKind::Workflow);
    }
    None
}

fn is_compose_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some((stem, extension)) = lower.rsplit_once('.') else {
        return false;
    };
    if extension != "yml" && extension != "yaml" {
        return false;
    }
    stem == "compose"
        || stem == "docker-compose"
        || stem.starts_with("compose.")
        || stem.starts_with("docker-compose.")
}

fn read_text(path: &Path, size: u64) -> Result<Option<String>> {
    if size > MAX_FILE_SIZE {
        return Ok(None);
    }
    let file = File::open(path).with_context(|| format!("cannot read `{}`", path.display()))?;
    let mut bytes = Vec::new();
    // The size cap is enforced on the bytes actually read: `size` is a stale
    // stat snapshot, and the file may have grown since it was taken.
    file.take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read `{}`", path.display()))?;
    if bytes.len() > MAX_FILE_SIZE as usize {
        return Ok(None);
    }
    if bytes.contains(&0) {
        return Ok(None);
    }
    Ok(String::from_utf8(bytes).ok())
}

fn relative_path(path: &Path, root: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    #[test]
    fn collects_sources_env_files_and_configs() {
        let temp = tempfile::tempdir().unwrap();
        write(&temp.path().join("src/app.ts"), "process.env.API_URL\n");
        write(&temp.path().join(".env.example"), "API_URL=\n");
        write(&temp.path().join("compose.yaml"), "services: {}\n");
        write(
            &temp.path().join(".github/workflows/ci.yml"),
            "env:\n  CI: true\n",
        );
        write(&temp.path().join("README.md"), "process.env.IGNORED\n");

        let collected = collect(temp.path()).unwrap();
        assert_eq!(collected.files_scanned, 4);
        assert_eq!(collected.sources.len(), 1);
        assert_eq!(collected.sources[0].relative, "src/app.ts");
        assert_eq!(collected.env_files.len(), 1);
        assert_eq!(collected.env_files[0].kind, EnvKind::Example);
        assert_eq!(collected.configs.len(), 2);
        assert!(
            collected
                .configs
                .iter()
                .any(|file| file.kind == ConfigKind::Compose)
        );
        assert!(
            collected
                .configs
                .iter()
                .any(|file| file.kind == ConfigKind::Workflow)
        );
    }

    #[test]
    fn skips_ignored_directories() {
        let temp = tempfile::tempdir().unwrap();
        for directory in IGNORED_DIRECTORIES {
            write(
                &temp.path().join(directory).join("ignored.ts"),
                "process.env.IGNORED\n",
            );
        }
        write(&temp.path().join("kept.ts"), "process.env.KEPT\n");

        let collected = collect(temp.path()).unwrap();
        assert_eq!(collected.sources.len(), 1);
        assert_eq!(collected.sources[0].relative, "kept.ts");
    }

    #[test]
    fn skips_lockfiles_binaries_and_large_files() {
        let temp = tempfile::tempdir().unwrap();
        write(&temp.path().join("Cargo.lock"), "process.env.LOCKED\n");
        fs::write(temp.path().join("binary.ts"), b"process.env.BINARY\0").unwrap();
        let mut large = fs::File::create(temp.path().join("large.ts")).unwrap();
        large
            .write_all(&vec![b'a'; (MAX_FILE_SIZE + 1) as usize])
            .unwrap();
        write(&temp.path().join("ok.ts"), "process.env.OK\n");

        let collected = collect(temp.path()).unwrap();
        assert_eq!(collected.sources.len(), 1);
        assert_eq!(collected.sources[0].relative, "ok.ts");
    }

    #[test]
    fn read_text_enforces_the_size_cap_on_actually_read_bytes() {
        let temp = tempfile::tempdir().unwrap();

        // Exactly the cap still reads.
        let exact = temp.path().join("exact.env");
        fs::write(&exact, vec![b'a'; MAX_FILE_SIZE as usize]).unwrap();
        assert!(read_text(&exact, MAX_FILE_SIZE).unwrap().is_some());

        // A grown file is rejected even when the stale stat claimed it fit.
        let grown = temp.path().join("grown.env");
        fs::write(&grown, vec![b'a'; (MAX_FILE_SIZE + 1) as usize]).unwrap();
        assert!(read_text(&grown, 0).unwrap().is_none());
        assert!(read_text(&grown, MAX_FILE_SIZE + 1).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("secret.ts");
        write(&outside_file, "process.env.OUTSIDE\n");
        symlink(&outside_file, temp.path().join("linked.ts")).unwrap();

        let collected = collect(temp.path()).unwrap();
        assert!(collected.sources.is_empty());
    }

    #[test]
    fn rejects_missing_or_non_directory_roots() {
        let temp = tempfile::tempdir().unwrap();
        assert!(collect(&temp.path().join("missing")).is_err());
        let file = temp.path().join("file.txt");
        write(&file, "hello");
        assert!(collect(&file).is_err());
    }

    #[test]
    fn reads_referenced_env_files_only_inside_the_root() {
        let temp = tempfile::tempdir().unwrap();
        let inside = temp.path().join("config/custom.env");
        write(&inside, "INSIDE=1\n");
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("outside.env");
        write(&outside_file, "OUTSIDE=1\n");

        let root = fs::canonicalize(temp.path()).unwrap();
        let read = read_referenced_env_file(&root, &inside).unwrap().unwrap();
        assert_eq!(read.relative, "config/custom.env");
        assert_eq!(read.kind, EnvKind::Real);
        assert!(
            read_referenced_env_file(&root, &outside_file)
                .unwrap()
                .is_none()
        );
    }
}
