//! Exec-only Host launcher.
//!
//! This binary does not read the bootstrap token, bind a port, or check the
//! source digest. Those remain in the Python Host and the Rust supervisor.
//! After `execve`, PID and process group stay the ones Tauri launched.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const RUNTIME_DIR_NAME: &str = "js-agent-host-runtime";
pub const RUNTIME_BIN_NAME: &str = "js-agent-host";

const O_CLOEXEC: i32 = 0x0100_0000;
const O_NOFOLLOW: i32 = 0x0100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LauncherError {
    LauncherPathUnreadable,
    LauncherPathSymlink,
    RuntimeMissing,
    RuntimeSymlink,
    RuntimeNotRegular,
    RuntimeNotExecutable,
    ExecFailed,
}

impl LauncherError {
    pub fn code(self) -> &'static str {
        match self {
            Self::LauncherPathUnreadable => "launcher_path_unreadable",
            Self::LauncherPathSymlink => "launcher_path_symlink",
            Self::RuntimeMissing => "runtime_missing",
            Self::RuntimeSymlink => "runtime_symlink",
            Self::RuntimeNotRegular => "runtime_not_regular",
            Self::RuntimeNotExecutable => "runtime_not_executable",
            Self::ExecFailed => "exec_failed",
        }
    }
}

pub fn launch() -> Result<(), LauncherError> {
    let launcher = current_executable()?;
    reject_if_symlink(&launcher, LauncherError::LauncherPathSymlink)?;
    let runtime = resolve_runtime_path(&launcher)?;
    exec_runtime(&runtime)
}

pub fn resolve_runtime_path(launcher: &Path) -> Result<PathBuf, LauncherError> {
    reject_if_symlink(launcher, LauncherError::LauncherPathSymlink)?;
    let parent = launcher
        .parent()
        .ok_or(LauncherError::LauncherPathUnreadable)?;
    if parent.file_name() == Some(OsStr::new("MacOS")) {
        join_without_symlinks(
            parent,
            &["..", "Resources", RUNTIME_DIR_NAME, RUNTIME_BIN_NAME],
            LauncherError::RuntimeMissing,
            LauncherError::RuntimeSymlink,
        )
        .and_then(verify_regular_executable)
    } else {
        join_without_symlinks(
            parent,
            &[RUNTIME_DIR_NAME, RUNTIME_BIN_NAME],
            LauncherError::RuntimeMissing,
            LauncherError::RuntimeSymlink,
        )
        .and_then(verify_regular_executable)
    }
}

fn current_executable() -> Result<PathBuf, LauncherError> {
    let raw = macos_executable_path().or_else(|_| {
        std::env::current_exe().map_err(|_| LauncherError::LauncherPathUnreadable)
    })?;
    if raw.as_os_str().is_empty() {
        return Err(LauncherError::LauncherPathUnreadable);
    }
    let absolute = if raw.is_absolute() {
        raw
    } else {
        let cwd = std::env::current_dir().map_err(|_| LauncherError::LauncherPathUnreadable)?;
        cwd.join(raw)
    };
    Ok(absolute)
}

fn macos_executable_path() -> Result<PathBuf, LauncherError> {
    let mut size: u32 = 0;
    unsafe {
        _NSGetExecutablePath(std::ptr::null_mut(), &mut size);
    }
    if size == 0 {
        return Err(LauncherError::LauncherPathUnreadable);
    }
    let mut buffer = vec![0u8; size as usize];
    let rc = unsafe { _NSGetExecutablePath(buffer.as_mut_ptr().cast(), &mut size) };
    if rc != 0 {
        return Err(LauncherError::LauncherPathUnreadable);
    }
    let end = buffer.iter().position(|byte| *byte == 0).unwrap_or(buffer.len());
    if end == 0 {
        return Err(LauncherError::LauncherPathUnreadable);
    }
    Ok(PathBuf::from(OsStr::from_bytes(&buffer[..end])))
}

fn join_without_symlinks(
    base: &Path,
    parts: &[&str],
    missing: LauncherError,
    symlink: LauncherError,
) -> Result<PathBuf, LauncherError> {
    let mut current = base.to_path_buf();
    for part in parts {
        if *part == ".." {
            current = current.parent().ok_or(missing)?.to_path_buf();
        } else {
            current.push(part);
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(symlink),
            Ok(_) => {}
            Err(_) => return Err(missing),
        }
    }
    Ok(current)
}

fn reject_if_symlink(path: &Path, error: LauncherError) -> Result<(), LauncherError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(error),
        Ok(_) => Ok(()),
        Err(_) => Err(LauncherError::LauncherPathUnreadable),
    }
}

fn verify_regular_executable(path: PathBuf) -> Result<PathBuf, LauncherError> {
    let metadata = fs::symlink_metadata(&path).map_err(|_| LauncherError::RuntimeMissing)?;
    if metadata.file_type().is_symlink() {
        return Err(LauncherError::RuntimeSymlink);
    }
    if !metadata.file_type().is_file() {
        return Err(LauncherError::RuntimeNotRegular);
    }
    if metadata.mode() & 0o111 == 0 {
        return Err(LauncherError::RuntimeNotExecutable);
    }
    confirm_nofollow_regular(&path)?;
    Ok(path)
}

fn confirm_nofollow_regular(path: &Path) -> Result<(), LauncherError> {
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        .open(path)
        .map_err(|error| match error.kind() {
            ErrorKind::NotFound => LauncherError::RuntimeMissing,
            _ if error.raw_os_error() == Some(ELOOP) => LauncherError::RuntimeSymlink,
            _ => LauncherError::RuntimeNotRegular,
        })?;
    let metadata = opened
        .metadata()
        .map_err(|_| LauncherError::RuntimeNotRegular)?;
    if !metadata.is_file() {
        return Err(LauncherError::RuntimeNotRegular);
    }
    Ok(())
}

fn exec_runtime(runtime: &Path) -> Result<(), LauncherError> {
    confirm_nofollow_regular(runtime)?;
    let mut command = Command::new(runtime);
    command.args(std::env::args_os().skip(1));
    // argv[0] must be the onedir executable so PyInstaller finds `_internal`.
    command.arg0(runtime.as_os_str());
    let _error = command.exec();
    Err(LauncherError::ExecFailed)
}

const O_RDONLY: i32 = 0;
const ELOOP: i32 = 62;

unsafe extern "C" {
    fn _NSGetExecutablePath(buf: *mut std::os::raw::c_char, bufsize: *mut u32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> PathBuf {
        let unique = format!(
            "js-agent-launcher-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        );
        let dir = PathBuf::from("/private/tmp").join(unique);
        fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    fn write_executable(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent");
        }
        File::create(path).expect("create").set_len(1).ok();
        let mut permissions = fs::metadata(path).expect("meta").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod");
    }

    #[test]
    fn macos_layout_resolves_resources_runtime() {
        let root = scratch();
        let launcher = root.join("JS Agent.app/Contents/MacOS/js-agent-host");
        let runtime = root.join("JS Agent.app/Contents/Resources/js-agent-host-runtime/js-agent-host");
        write_executable(&launcher);
        write_executable(&runtime);
        assert_eq!(resolve_runtime_path(&launcher).expect("resolve"), runtime);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn sibling_layout_resolves_dev_runtime() {
        let root = scratch();
        let launcher = root.join("js-agent-host-aarch64-apple-darwin");
        let runtime = root.join("js-agent-host-runtime/js-agent-host");
        write_executable(&launcher);
        write_executable(&runtime);
        assert_eq!(resolve_runtime_path(&launcher).expect("resolve"), runtime);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn runtime_symlink_is_rejected() {
        let root = scratch();
        let launcher = root.join("JS Agent.app/Contents/MacOS/js-agent-host");
        let runtime_dir = root.join("JS Agent.app/Contents/Resources/js-agent-host-runtime");
        write_executable(&launcher);
        fs::create_dir_all(&runtime_dir).expect("runtime dir");
        std::os::unix::fs::symlink("/private/tmp", runtime_dir.join("js-agent-host"))
            .expect("symlink");
        assert_eq!(
            resolve_runtime_path(&launcher).expect_err("symlink"),
            LauncherError::RuntimeSymlink
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn missing_runtime_fails_closed() {
        let root = scratch();
        let launcher = root.join("JS Agent.app/Contents/MacOS/js-agent-host");
        write_executable(&launcher);
        assert_eq!(
            resolve_runtime_path(&launcher).expect_err("missing"),
            LauncherError::RuntimeMissing
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn non_executable_runtime_fails_closed() {
        let root = scratch();
        let launcher = root.join("js-agent-host-aarch64-apple-darwin");
        let runtime = root.join("js-agent-host-runtime/js-agent-host");
        write_executable(&launcher);
        write_executable(&runtime);
        let mut permissions = fs::metadata(&runtime).expect("meta").permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&runtime, permissions).expect("chmod");
        assert_eq!(
            resolve_runtime_path(&launcher).expect_err("mode"),
            LauncherError::RuntimeNotExecutable
        );
        fs::remove_dir_all(root).ok();
    }
}
