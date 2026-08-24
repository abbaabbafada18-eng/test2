//! Where this installation keeps its data.
//!
//! It used to be wherever the program happened to be started from, which is the
//! program's folder on Windows and `/var/lib/minter` for the Linux service —
//! right in both cases, and wrong everywhere else. Unzipping an update into a
//! new folder opened an empty program while the wallets sat in the old one, and
//! an app launched from macOS Finder would try to create `results/` at the root
//! of the disk.
//!
//! Nothing is ever moved or copied. A vault is the one file where a stray
//! second copy is worse than any inconvenience, and an interrupted move is
//! worse still. Instead the program looks for the data it already has, in the
//! order below, and only invents a location when there is nothing to find:
//!
//! 1. `MINTER_DATA_DIR`, when the operator or the service says outright.
//! 2. The working directory, if the vault is already there — this is every
//!    existing install, and it keeps working untouched, forever.
//! 3. The executable's own folder, if the vault is there — a shortcut whose
//!    working directory is `System32` has bitten this program before.
//! 4. The note the program left itself last time, if that folder still holds
//!    data. This is what makes "unzipped somewhere new" find the old wallets.
//! 5. Otherwise the per-user place the platform keeps application data in.
//!
//! Whatever is chosen, the note is rewritten, so the next copy — wherever it is
//! unzipped — can follow it home.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::types::VAULT_FILE;

/// Set by the operator or by the systemd unit; wins over everything.
pub const DATA_DIR_ENV: &str = "MINTER_DATA_DIR";

/// Folder name used when a per-user location has to be created.
const APP_DIR: &str = "MINTER";

/// The note, kept in the per-user location even when the data is elsewhere.
const POINTER_FILE: &str = "data-location.txt";

static ROOT: OnceLock<PathBuf> = OnceLock::new();

/// True when this folder is already somebody's data directory.
fn holds_data(dir: &Path) -> bool {
    dir.join(VAULT_FILE).exists() || dir.join("config.json").exists()
}

/// The per-user place the platform keeps application data in.
///
/// Read from the environment rather than by taking on a dependency, the same
/// way the imports fallback already does.
pub fn platform_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(|base| PathBuf::from(base).join(APP_DIR))
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|home| {
            PathBuf::from(home)
                .join("Library/Application Support")
                .join(APP_DIR)
        })
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .map(|base| base.join("minter"))
    }
}

fn pointer_path() -> Option<PathBuf> {
    platform_dir().map(|d| d.join(POINTER_FILE))
}

fn read_pointer() -> Option<PathBuf> {
    let raw = std::fs::read_to_string(pointer_path()?).ok()?;
    let path = PathBuf::from(raw.trim());
    (!path.as_os_str().is_empty()).then_some(path)
}

/// Leave the note for the next copy. Failure is silent on purpose: not being
/// able to write it costs a future convenience, never this run.
fn write_pointer(root: &Path) {
    let Some(path) = pointer_path() else { return };
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    if read_pointer().as_deref() == Some(root) {
        return;
    }
    let _ = std::fs::write(path, root.display().to_string());
}

/// The decision itself, with the filesystem handed in.
///
/// Split out because this is the part that can send a run looking at the wrong
/// wallets, and it should be checkable without creating a single file.
fn choose(
    env_dir: Option<PathBuf>,
    cwd: Option<PathBuf>,
    exe_dir: Option<PathBuf>,
    pointer: Option<PathBuf>,
    platform: Option<PathBuf>,
    has_data: &dyn Fn(&Path) -> bool,
) -> PathBuf {
    if let Some(dir) = env_dir {
        return dir;
    }
    // The working directory comes before the note: a second portable copy with
    // its own wallets beside it must stay its own install, not be pulled into
    // the first one's data.
    if let Some(dir) = cwd.clone().filter(|d| has_data(d)) {
        return dir;
    }
    if let Some(dir) = exe_dir.filter(|d| has_data(d)) {
        return dir;
    }
    if let Some(dir) = pointer.filter(|d| has_data(d)) {
        return dir;
    }
    platform.or(cwd).unwrap_or_else(|| PathBuf::from("."))
}

/// Where this installation keeps its data. Decided once per process.
pub fn data_root() -> &'static Path {
    ROOT.get_or_init(|| {
        let root = choose(
            std::env::var_os(DATA_DIR_ENV)
                .map(PathBuf::from)
                .filter(|p| !p.as_os_str().is_empty()),
            std::env::current_dir().ok(),
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_path_buf)),
            read_pointer(),
            platform_dir(),
            &holds_data,
        );
        let _ = std::fs::create_dir_all(&root);
        write_pointer(&root);
        root
    })
    .as_path()
}

/// A file inside the data directory.
pub fn data_file(name: &str) -> PathBuf {
    data_root().join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Option<PathBuf> {
        Some(PathBuf::from(s))
    }

    /// Everyone already running keeps their data exactly where it is.
    #[test]
    fn an_existing_install_is_left_alone() {
        let has = |d: &Path| d == Path::new("/app");
        let root = choose(
            None,
            p("/app"),
            p("/app"),
            p("/elsewhere"),
            p("/home/data"),
            &has,
        );
        assert_eq!(root, PathBuf::from("/app"));
    }

    /// The Linux service starts in its own state directory; same rule, no change.
    #[test]
    fn the_service_directory_wins_the_same_way() {
        let has = |d: &Path| d == Path::new("/var/lib/minter");
        let root = choose(
            None,
            p("/var/lib/minter"),
            p("/opt/minter"),
            None,
            p("/root/.local/share/minter"),
            &has,
        );
        assert_eq!(root, PathBuf::from("/var/lib/minter"));
    }

    /// A shortcut whose working directory is System32 must not strand the vault.
    #[test]
    fn the_executables_folder_is_tried_when_the_working_directory_is_elsewhere() {
        let has = |d: &Path| d == Path::new("/app");
        let root = choose(
            None,
            p("/windows/system32"),
            p("/app"),
            None,
            p("/appdata/MINTER"),
            &has,
        );
        assert_eq!(root, PathBuf::from("/app"));
    }

    /// The whole point: unzipped somewhere new, the note leads back to the data.
    #[test]
    fn a_fresh_copy_follows_the_note_to_the_old_wallets() {
        let has = |d: &Path| d == Path::new("/old-install");
        let root = choose(
            None,
            p("/new-folder"),
            p("/new-folder"),
            p("/old-install"),
            p("/appdata/MINTER"),
            &has,
        );
        assert_eq!(root, PathBuf::from("/old-install"));
    }

    /// A note pointing at a folder that no longer has anything is not followed.
    #[test]
    fn a_stale_note_is_ignored() {
        let has = |_: &Path| false;
        let root = choose(
            None,
            p("/new-folder"),
            p("/new-folder"),
            p("/deleted"),
            p("/appdata/MINTER"),
            &has,
        );
        assert_eq!(root, PathBuf::from("/appdata/MINTER"));
    }

    /// A second portable copy with its own wallets stays its own install.
    #[test]
    fn a_portable_copy_is_not_pulled_into_another_installs_data() {
        let has = |d: &Path| d == Path::new("/stick") || d == Path::new("/old-install");
        let root = choose(
            None,
            p("/stick"),
            p("/stick"),
            p("/old-install"),
            p("/appdata/MINTER"),
            &has,
        );
        assert_eq!(root, PathBuf::from("/stick"));
    }

    /// Nothing to find anywhere: a new install lands where the platform says.
    #[test]
    fn a_new_install_lands_in_the_platform_directory() {
        let has = |_: &Path| false;
        let root = choose(
            None,
            p("/"),
            p("/Applications/MINTER.app/Contents/MacOS"),
            None,
            p("/home/Library/Application Support/MINTER"),
            &has,
        );
        assert_eq!(
            root,
            PathBuf::from("/home/Library/Application Support/MINTER")
        );
    }

    /// An explicit setting is obeyed even when data sits somewhere else.
    #[test]
    fn the_environment_override_beats_every_search() {
        let has = |_: &Path| true;
        let root = choose(
            p("/srv/minter"),
            p("/app"),
            p("/app"),
            p("/old"),
            p("/home/data"),
            &has,
        );
        assert_eq!(root, PathBuf::from("/srv/minter"));
    }
}
