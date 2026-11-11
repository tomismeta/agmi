use super::*;

struct Fixture {
    config: Config,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let (directory, config) = tests::bound_fixture();
        Self {
            config,
            _directory: directory,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let writer = lock_path(&self.config, "writer").unwrap();
        let prefix = writer.file_stem().unwrap().to_string_lossy();
        if let Ok(entries) = fs::read_dir(writer.parent().unwrap()) {
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{prefix}."))
                {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

fn replacement(config: &Config) {
    let path = lock_path(config, "writer").unwrap();
    let temporary = path.with_extension("replacement");
    let mut file = private_file(&temporary).unwrap();
    file.write_all(WRITER_MARKER).unwrap();
    file.sync_all().unwrap();
    fs::rename(temporary, path).unwrap();
}

#[test]
fn immutable_writer_anchor_refuses_missing_and_same_marker_replacement() {
    for replace in [false, true] {
        let fixture = Fixture::new();
        let config = &fixture.config;
        let (owner, mut store) = AccountLock::acquire(config).unwrap();
        let binding_path = lock_path(config, "binding").unwrap();
        let binding = fs::read(&binding_path).unwrap();
        let writer_path = lock_path(config, "writer").unwrap();
        let before = store.control().unwrap().generation;
        let control_token =
            lane_control_status(config, LaneId::Answer).unwrap()["desired"]["control_token"]
                .as_str()
                .unwrap()
                .to_owned();
        let gate = AccountAdmissionGuard::acquire(config).unwrap();
        if replace {
            replacement(config);
        } else {
            fs::remove_file(&writer_path).unwrap();
        }
        assert!(store.continuity().is_err());
        assert!(store.recover().is_err());
        assert!(store.set_paused(false, &gate).is_err());
        drop(gate);
        assert!(AccountLock::acquire(config).is_err());
        assert!(
            AccountAdmissionGuard::for_control(config)
                .and_then(|gate| AccountLock::control_store(config, &gate))
                .is_err()
        );
        assert!(AccountLock::adopt(config).is_err());
        assert!(AccountLock::stopped(config).is_err());
        assert!(lane_control_status(config, LaneId::Answer).is_err());
        assert!(
            set_lane_paused(
                config,
                LaneId::Answer,
                true,
                &control_token,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .is_err()
        );
        assert_eq!(store.control().unwrap().generation, before);
        assert_eq!(fs::read(binding_path).unwrap(), binding);
        assert_eq!(writer_path.exists(), replace);
        drop(store);
        drop(owner);
    }
}

#[test]
fn running_store_never_learns_a_rewritten_writer_anchor() {
    let fixture = Fixture::new();
    let config = &fixture.config;
    let (_owner, mut store) = AccountLock::acquire(config).unwrap();
    let path = lock_path(config, "binding").unwrap();
    let mut binding = read_binding(config).unwrap().unwrap();
    binding.writer_inode.as_mut().unwrap().inode += 1;
    write_binding(&path, &binding).unwrap();
    let changed = fs::read(&path).unwrap();
    assert!(store.continuity().is_err());
    assert!(store.publish_dispatch_witness().is_err());
    assert_eq!(fs::read(path).unwrap(), changed);
}

#[test]
fn explicit_first_anchor_preserves_original_values_and_requires_intact_marker() {
    for intact in [true, false] {
        let fixture = Fixture::new();
        let config = &fixture.config;
        drop(AccountLock::acquire(config).unwrap());
        let path = lock_path(config, "binding").unwrap();
        let mut legacy = read_binding(config).unwrap().unwrap();
        legacy.writer_inode = None;
        write_binding(&path, &legacy).unwrap();
        let serialized = serde_json::to_vec(&legacy).unwrap();
        assert!(
            !String::from_utf8(serialized.clone())
                .unwrap()
                .contains("writer_inode")
        );
        if !intact {
            let writer =
                lane_control::opened_file(&lock_path(config, "writer").unwrap(), true, false)
                    .unwrap();
            writer.set_len(0).unwrap();
        }
        assert!(AccountLock::acquire(config).is_err());
        assert!(
            AccountAdmissionGuard::for_control(config)
                .and_then(|gate| AccountLock::control_store(config, &gate))
                .is_err()
        );
        if intact {
            let metadata = Store::read_only(config).unwrap().unwrap();
            assert_eq!(
                metadata.writer_authority_status().unwrap()["state"],
                "writer_unanchored"
            );
            drop(metadata);
            drop(AccountLock::adopt(config).unwrap());
            let mut adopted = read_binding(config).unwrap().unwrap();
            assert!(adopted.writer_inode.take().is_some());
            assert_eq!(serde_json::to_vec(&adopted).unwrap(), serialized);
        } else {
            assert!(AccountLock::adopt(config).is_err());
            assert_eq!(fs::read(path).unwrap(), serialized);
        }
    }
}

#[test]
fn anchored_initialization_interruption_only_finishes_same_inode() {
    let fixture = Fixture::new();
    let config = &fixture.config;
    drop(AccountLock::acquire(config).unwrap());
    let writer_path = lock_path(config, "writer").unwrap();
    let binding = read_binding(config).unwrap().unwrap();
    let writer = lane_control::opened_file(&writer_path, true, false).unwrap();
    writer.set_len(0).unwrap();
    drop(writer);
    assert!(AccountLock::acquire(config).is_err());
    assert!(
        AccountAdmissionGuard::for_control(config)
            .and_then(|gate| AccountLock::control_store(config, &gate))
            .is_err()
    );
    drop(AccountLock::adopt(config).unwrap());
    assert_eq!(
        read_binding(config).unwrap().unwrap().writer_inode,
        binding.writer_inode
    );
    assert_eq!(fs::read(writer_path).unwrap(), WRITER_MARKER);
}

#[test]
fn adoption_does_not_recreate_missing_required_gates() {
    let fixture = Fixture::new();
    let config = &fixture.config;
    drop(AccountLock::acquire(config).unwrap());
    let mut binding = read_binding(config).unwrap().unwrap();
    binding.writer_inode = None;
    write_binding(&lock_path(config, "binding").unwrap(), &binding).unwrap();
    let gate = lock_path(config, &format!("lane-{}-answer", binding.database_id)).unwrap();
    fs::remove_file(&gate).unwrap();
    assert!(AccountLock::adopt(config).is_err());
    assert!(!gate.exists());
    assert!(
        read_binding(config)
            .unwrap()
            .unwrap()
            .writer_inode
            .is_none()
    );
}

#[test]
fn metadata_identity_mismatch_resolves_original_authority_without_writes() {
    let fixture = Fixture::new();
    let config = &fixture.config;
    drop(AccountLock::acquire(config).unwrap());
    let binding = fs::read(lock_path(config, "binding").unwrap()).unwrap();
    let mut changed = config.clone();
    changed.network.chain.push_str("-changed");
    let store = Store::read_only(&changed).unwrap().unwrap();
    assert_eq!(
        store.writer_authority_status().unwrap()["state"],
        "anchored"
    );
    assert!(store.check_config_identity(&changed).is_err());
    assert_eq!(
        fs::read(lock_path(config, "binding").unwrap()).unwrap(),
        binding
    );
    for suffix in ["writer", "binding", "admission"] {
        assert!(!lock_path(&changed, suffix).unwrap().exists());
    }
}

#[test]
fn present_null_or_partial_writer_metadata_is_not_legacy_absence() {
    let fixture = Fixture::new();
    let config = &fixture.config;
    drop(AccountLock::acquire(config).unwrap());
    let path = lock_path(config, "binding").unwrap();
    let valid: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for invalid in [
        Value::Null,
        json!({"device":1}),
        json!({"device":1,"inode":0}),
    ] {
        let mut binding = valid.clone();
        binding["writer_inode"] = invalid;
        write_binding_bytes(&path, &serde_json::to_vec(&binding).unwrap()).unwrap();
        assert!(AccountLock::acquire(config).is_err());
        assert!(AccountLock::adopt(config).is_err());
    }
}
