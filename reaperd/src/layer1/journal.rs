//! Write-ahead journal for Layer 1 device mutations.
//!
//! Every mutation records the value it replaces before the command runs. The
//! journal is written atomically and is the only source of truth for restore:
//! a mutation that is not journaled must never reach the device.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};

/// On-disk format version; a mismatch refuses to load.
pub const VERSION: u32 = 1;

/// Category of a journaled mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A boot receiver component that was disabled.
    Receiver,
    /// An app op that was set.
    Appop,
    /// A standby bucket that was set.
    Standby,
}

/// One device mutation and the value it replaced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// Android user the mutation applied to.
    pub user: u32,
    /// Package the mutation applied to.
    pub package: String,
    /// Category of the mutation.
    pub kind: Kind,
    /// Component, app-op name, or `"bucket"`.
    pub key: String,
    /// Value the mutation replaced, in the format the restore command takes.
    pub previous: String,
}

impl Item {
    /// Builds one journal entry.
    pub fn new(
        user: u32,
        package: impl Into<String>,
        kind: Kind,
        key: impl Into<String>,
        previous: impl Into<String>,
    ) -> Self {
        Self {
            user,
            package: package.into(),
            kind,
            key: key.into(),
            previous: previous.into(),
        }
    }

    /// Returns whether this item addresses the same device setting.
    pub fn same_key(&self, user: u32, package: &str, kind: Kind, key: &str) -> bool {
        self.user == user && self.package == package && self.kind == kind && self.key == key
    }
}

#[derive(Deserialize)]
struct Document {
    version: u32,
    #[serde(default)]
    item: Vec<Item>,
}

#[derive(Serialize)]
struct DocumentRef<'a> {
    version: u32,
    item: &'a [Item],
}

/// The journal file and its items, kept in memory while a pass runs.
pub struct Journal {
    path: PathBuf,
    items: Vec<Item>,
}

impl Journal {
    /// Loads the journal, treating a missing file as empty.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed, or carries an
    /// unsupported version.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: path.to_path_buf(),
                    items: Vec::new(),
                });
            }
            Err(err) => {
                return Err(err).with_context(|| format!("failed to read {}", path.display()));
            }
        };
        let document: Document =
            toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))?;
        ensure!(
            document.version == VERSION,
            "unsupported journal version {} in {}",
            document.version,
            path.display()
        );
        Ok(Self {
            path: path.to_path_buf(),
            items: document.item,
        })
    }

    /// Returns every journaled item.
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// Finds the item that already covers one device setting.
    pub fn find(&self, user: u32, package: &str, kind: Kind, key: &str) -> Option<&Item> {
        self.items
            .iter()
            .find(|item| item.same_key(user, package, kind, key))
    }

    /// Appends `item` unless an item for the same setting exists.
    pub fn append(&mut self, item: Item) -> bool {
        if self
            .find(item.user, &item.package, item.kind, &item.key)
            .is_some()
        {
            return false;
        }
        self.items.push(item);
        true
    }

    /// Drops the item for one device setting and reports whether it existed.
    pub fn remove(&mut self, user: u32, package: &str, kind: Kind, key: &str) -> bool {
        let before = self.items.len();
        self.items
            .retain(|item| !item.same_key(user, package, kind, key));
        self.items.len() != before
    }

    /// Drops every item belonging to `package` and returns how many were removed.
    pub fn remove_package(&mut self, package: &str) -> usize {
        let before = self.items.len();
        self.items.retain(|item| item.package != package);
        before - self.items.len()
    }

    /// Writes the journal atomically with mode 0600.
    ///
    /// # Errors
    ///
    /// Returns an error if the document cannot be serialized or the file cannot
    /// be written or renamed into place.
    pub fn save(&self) -> anyhow::Result<()> {
        let document = DocumentRef {
            version: VERSION,
            item: &self.items,
        };
        let text =
            toml::to_string_pretty(&document).context("failed to serialize Layer 1 journal")?;
        write_atomic(&self.path, text.as_bytes())
    }
}

fn write_atomic(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("failed to open {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to chmod {}", tmp.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", tmp.display()))?;
    drop(file);
    fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))?;
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::assert_is_empty,
    reason = "assert! is clearer than comparing with an empty collection"
)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_items() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let mut journal = Journal::load(&path).expect("missing journal is empty");
        assert!(journal.items().is_empty());
        assert!(journal.append(Item::new(
            0,
            "com.example",
            Kind::Receiver,
            "com.example/.Boot",
            "default",
        )));
        assert!(!journal.append(Item::new(
            0,
            "com.example",
            Kind::Receiver,
            "com.example/.Boot",
            "enabled",
        )));
        assert!(journal.append(Item::new(
            0,
            "com.example",
            Kind::Appop,
            "RUN_IN_BACKGROUND",
            "default",
        )));
        journal.save().expect("save");

        let loaded = Journal::load(&path).expect("load");
        assert_eq!(loaded.items(), journal.items());
        assert_eq!(loaded.items()[0].kind, Kind::Receiver);
    }

    #[test]
    fn atomic_replace_keeps_one_complete_document() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let mut journal = Journal::load(&path).expect("empty");
        journal.append(Item::new(0, "a", Kind::Standby, "bucket", "10"));
        journal.save().expect("first save");
        journal.append(Item::new(0, "b", Kind::Standby, "bucket", "20"));
        journal.save().expect("second save");

        let loaded = Journal::load(&path).expect("load");
        assert_eq!(loaded.items().len(), 2);
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn rejects_corrupt_journal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        fs::write(&path, "this is not toml").expect("write");
        assert!(Journal::load(&path).is_err());
    }

    #[test]
    fn rejects_unknown_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        fs::write(&path, "version = 2\n").expect("write");
        assert!(Journal::load(&path).is_err());
    }

    #[test]
    fn removes_by_key_and_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let mut journal = Journal::load(&path).expect("empty");
        journal.append(Item::new(0, "a", Kind::Appop, "op1", "default"));
        journal.append(Item::new(0, "a", Kind::Appop, "op2", "default"));
        journal.append(Item::new(0, "b", Kind::Appop, "op1", "default"));
        assert!(journal.remove(0, "a", Kind::Appop, "op1"));
        assert!(!journal.remove(0, "a", Kind::Appop, "op1"));
        assert_eq!(journal.remove_package("a"), 1);
        assert_eq!(journal.items().len(), 1);
    }
}
