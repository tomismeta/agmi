//! Qualify and dispatch the same private snapshot of the configured executable.
//! The operator must trust the executable; its native header is not proof that it is self-contained.
//! A loopback fixture measures the native encoder, not a substitute provider.
use super::*;
use std::borrow::Cow;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::sync::Arc;
use tokio::sync::Mutex;

mod probe;

const UNAVAILABLE: SolverNotStarted = SolverNotStarted("native_qualification_unavailable");
const FAILED: SolverNotStarted = SolverNotStarted("native_qualification_failed");
const MAX_IMAGE: u64 = 512 * 1024 * 1024;
const STOCK_ENDPOINT: &str = "https://opencode.ai/inference/go/v1";
#[cfg(feature = "omp-go-fixture")]
const FIXTURE_KEY: &str = "agmi-loopback-fixture";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<std::fs::Metadata> for FileStamp {
    fn from(m: std::fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            size: m.len(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}

fn stamp(path: &Path) -> Result<Option<FileStamp>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => Ok(Some(m.into())),
        Ok(_) => Err(UNAVAILABLE.into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(UNAVAILABLE.into()),
    }
}

fn executable_stamp(path: &Path) -> Result<FileStamp> {
    use std::os::unix::ffi::OsStrExt;

    let current = stamp(path)?.context(UNAVAILABLE)?;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).context(UNAVAILABLE)?;
    // An executable scratch copy must not bypass a disabled installation.
    ensure!(
        unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), libc::X_OK, libc::AT_EACCESS) }
            == 0,
        UNAVAILABLE
    );
    Ok(current)
}

#[derive(Debug, PartialEq, Eq)]
struct Scope {
    home: PathBuf,
    files: Inventory,
    endpoint: Cow<'static, str>,
}

impl Scope {
    fn current(model: &ModelConfig) -> Result<Self> {
        let home = dirs::home_dir().context(UNAVAILABLE)?;
        // This proof covers the stock catalog and native default auth store.
        // It cannot stand in for arbitrary executable provider overrides.
        let route = model.omp.as_ref();
        ensure!(
            route.is_none_or(|r| {
                r.profile
                    .as_deref()
                    .is_none_or(|profile| profile == "default")
                    && r.agent_dir.is_none()
                    && r.env.is_empty()
                    && r.provider_discovery_cwd
                        .as_ref()
                        .is_none_or(|cwd| *cwd == home)
            }),
            UNAVAILABLE
        );
        let (files, endpoint) = Self::inventory(&home)?;
        Ok(Self {
            home,
            files,
            endpoint,
        })
    }

    fn inventory(home: &Path) -> Result<(Inventory, Cow<'static, str>)> {
        let mut files = Vec::new();
        #[cfg(feature = "omp-go-fixture")]
        let mut fixture_endpoint = None;
        for root in [
            home.join(".omp"),
            home.join(".omp/agent"),
            home.join(".pi"),
            home.join(".pi/agent"),
            home.join(".config/omp"),
            home.join(".config/omp/agent"),
        ] {
            for name in ["config.yml", "models.yml", "plugins.yml"] {
                let path = root.join(name);
                let state = stamp(&path)?;
                if state.is_some() {
                    ensure!(
                        root == home.join(".omp/agent") && name != "plugins.yml",
                        UNAVAILABLE
                    );
                    if name == "models.yml" {
                        #[cfg(feature = "omp-go-fixture")]
                        {
                            fixture_endpoint = Some(loopback_overlay(&path)?);
                        }
                        #[cfg(not(feature = "omp-go-fixture"))]
                        return Err(UNAVAILABLE.into());
                    }
                }
                files.push((path, state));
            }
        }
        #[cfg(feature = "omp-go-fixture")]
        let endpoint = {
            ensure!(
                fixture_endpoint.is_some() == (GoMode::inference() == GoMode::Fixture),
                UNAVAILABLE
            );
            fixture_endpoint.map_or(Cow::Borrowed(STOCK_ENDPOINT), Cow::Owned)
        };
        #[cfg(not(feature = "omp-go-fixture"))]
        let endpoint = Cow::Borrowed(STOCK_ENDPOINT);
        Ok((files, endpoint))
    }

    fn verify(&self) -> Result<()> {
        let (files, endpoint) = Self::inventory(&self.home)?;
        ensure!(
            files == self.files && endpoint == self.endpoint,
            UNAVAILABLE
        );
        Ok(())
    }
}

#[cfg(feature = "omp-go-fixture")]
fn loopback_overlay(path: &Path) -> Result<String> {
    // JSON is a YAML subset; only the isolated loopback fixture may replace
    // the stock endpoint, without changing route metadata or using a real key.
    ensure!(GoMode::inference() == GoMode::Fixture, UNAVAILABLE);
    ensure!(
        std::fs::metadata(path).context(UNAVAILABLE)?.len() <= 4096,
        UNAVAILABLE
    );
    let data: Value = serde_json::from_reader(std::fs::File::open(path).context(UNAVAILABLE)?)
        .context(UNAVAILABLE)?;
    let entry = &data["providers"]["opencode-go"];
    let endpoint = entry["baseUrl"].as_str().context(UNAVAILABLE)?;
    let url = reqwest::Url::parse(endpoint).context(UNAVAILABLE)?;
    ensure!(
        url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some()
            && url.path() == "/v1"
            && endpoint == format!("{}/v1", url.origin().ascii_serialization())
            && data
                == json!({"providers":{"opencode-go":{"baseUrl":endpoint,"apiKey":FIXTURE_KEY}}}),
        UNAVAILABLE
    );
    Ok(endpoint.to_owned())
}

type Inventory = Vec<(PathBuf, Option<FileStamp>)>;
struct Image {
    _workspace: Scratch,
    executable: PathBuf,
}

fn snapshot(path: &Path, expected: FileStamp) -> Result<Image> {
    use std::io::{Read, Seek, SeekFrom};
    let workspace = Scratch::new()?;
    let executable = workspace.0.join("omp");
    let mut source = std::fs::File::open(path).context(FAILED)?;
    ensure!(
        FileStamp::from(source.metadata().context(FAILED)?) == expected
            && expected.size <= MAX_IMAGE,
        FAILED
    );
    let mut magic = [0; 4];
    source.read_exact(&mut magic).context(FAILED)?;
    // Reject script launchers. A native header alone says nothing about what
    // the configured executable loads or runs after launch.
    let native = if cfg!(target_os = "macos") {
        matches!(
            u32::from_be_bytes(magic),
            0xfeedfacf | 0xcffaedfe | 0xcafebabe | 0xbebafeca | 0xcafebabf | 0xbfbafeca
        )
    } else {
        magic == *b"\x7fELF"
    };
    ensure!(native, UNAVAILABLE);
    source.seek(SeekFrom::Start(0)).context(FAILED)?;
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&executable)
        .context(FAILED)?;
    let copied =
        std::io::copy(&mut (&mut source).take(expected.size + 1), &mut target).context(FAILED)?;
    ensure!(
        copied == expected.size
            && FileStamp::from(source.metadata().context(FAILED)?) == expected
            && stamp(path)? == Some(expected),
        FAILED
    );
    target
        .set_permissions(std::fs::Permissions::from_mode(0o500))
        .context(FAILED)?;
    drop(target);
    Ok(Image {
        _workspace: workspace,
        executable,
    })
}

pub(in crate::solver) struct Qualified {
    image: Arc<Image>,
    configured: PathBuf,
    source: PathBuf,
    stamp: FileStamp,
    selection: String,
    scope: Scope,
    model_digest: String,
}

impl Qualified {
    pub(in crate::solver) fn executable(&self) -> Result<&Path> {
        ensure!(
            resolve_executable(&self.configured).is_ok_and(|path| path == self.source),
            UNAVAILABLE
        );
        ensure!(executable_stamp(&self.source)? == self.stamp, UNAVAILABLE);
        self.scope.verify()?;
        Ok(&self.image.executable)
    }

    pub(super) fn verify_before_dispatch(&self, entry: &Value) -> Result<String> {
        self.executable()?;
        let digest = verify_descriptor(entry, &self.scope.endpoint)?;
        ensure!(digest == self.model_digest, FAILED);
        Ok(digest)
    }
}

// The two model lanes can share a receipt for identical scope, executable and
// route. A bounded positive cache owns only private, qualified snapshots.
static CACHE: Mutex<Vec<Arc<Qualified>>> = Mutex::const_new(Vec::new());

pub(in crate::solver) fn release_cache() {
    if let Ok(mut cache) = CACHE.try_lock() {
        cache.clear();
    }
}

pub(in crate::solver) async fn qualify(
    model: &ModelConfig,
    source: &Path,
    deadline: ExecutionDeadline,
) -> Result<Option<Arc<Qualified>>> {
    let (provider, name) = model.omp_selection().map_err(|_| UNAVAILABLE)?;
    if provider != "opencode-go" {
        return Ok(None);
    }
    ensure!(model.reasoning != "off", UNAVAILABLE);
    let (_, _, selection) = selection(model)?;
    let scope = Scope::current(model)?;
    let current = executable_stamp(source)?;
    let mut cache = CACHE.lock().await;
    if let Some(found) = cache.iter().find(|entry| {
        entry.source == source
            && entry.configured == model.executable
            && entry.stamp == current
            && entry.selection == selection
            && entry.scope == scope
    }) {
        return Ok(Some(found.clone()));
    }
    let image = match cache
        .iter()
        .find(|entry| entry.source == source && entry.stamp == current)
    {
        Some(found) => found.image.clone(),
        None => {
            let path = source.to_owned();
            Arc::new(
                tokio::task::spawn_blocking(move || snapshot(&path, current))
                    .await
                    .context(FAILED)??,
            )
        }
    };
    validate_settings(&image.executable, &scope, deadline).await?;
    let mut qualified = None;
    for case in [
        #[cfg(feature = "omp-go-fixture")]
        probe::Case::RejectAuth,
        probe::Case::Capture,
        probe::Case::RejectEffort,
        probe::Case::RejectServedModel,
    ] {
        let Some(digest) = run_probe(
            &image.executable,
            provider,
            name,
            &model.reasoning,
            case,
            deadline,
        )
        .await
        .map_err(|_| FAILED)?
        else {
            continue;
        };
        ensure!(
            qualified
                .as_ref()
                .is_none_or(|previous| previous == &digest),
            FAILED
        );
        qualified = Some(digest);
    }
    ensure!(
        executable_stamp(source)? == current && Scope::current(model)? == scope,
        UNAVAILABLE
    );
    let result = Arc::new(Qualified {
        image,
        configured: model.executable.clone(),
        source: source.to_owned(),
        stamp: current,
        selection,
        scope,
        model_digest: qualified.context(FAILED)?,
    });
    cache.retain(|entry| entry.source != result.source || entry.stamp == result.stamp);
    if cache.len() >= 4 {
        cache.remove(0);
    }
    cache.push(result.clone());
    Ok(Some(result))
}

fn spawn_isolated(
    executable: &Path,
    args: &[String],
    work: &Path,
    home: &Path,
) -> Result<OwnedChild> {
    #[cfg(target_os = "linux")]
    {
        // No host home, sockets or network routes are available to the probe.
        let mut command = Command::new("/usr/bin/bwrap");
        // SAFETY: this child-only hook makes one syscall. Mark descriptors
        // close-on-exec rather than closing Rust's exec-error pipe early.
        // A kernel without this facility must refuse the isolated launch.
        unsafe {
            command.pre_exec(|| {
                if libc::syscall(
                    libc::SYS_close_range,
                    3 as libc::c_uint,
                    libc::c_uint::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) == 0
                {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        command.env_clear().args([
            "--unshare-user",
            "--unshare-all",
            "--unshare-net",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--tmpfs",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
        ]);
        for path in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
            command.args(["--ro-bind-try", path, path]);
        }
        command
            .arg("--bind")
            .arg(work)
            .arg(work)
            .arg("--ro-bind")
            .arg(executable)
            .arg("/agmi-omp")
            .arg("--chdir")
            .arg(work)
            .arg("--setenv")
            .arg("HOME")
            .arg(home)
            .arg("--setenv")
            .arg("TMPDIR")
            .arg(work.join("tmp"))
            .args([
                "--setenv",
                "LANG",
                "C.UTF-8",
                "--setenv",
                "OMP_PROFILE",
                "default",
            ])
            .args(["--", "/agmi-omp"])
            .args(args);
        spawn_owned(command).map_err(|_| UNAVAILABLE.into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (executable, args, work, home);
        Err(UNAVAILABLE.into())
    }
}

async fn validate_settings(
    executable: &Path,
    scope: &Scope,
    deadline: ExecutionDeadline,
) -> Result<()> {
    // Let OMP interpret the one supported settings file in isolation. Never
    // expose the native credential store or run proof commands in the real home.
    use std::io::Read;
    let scratch = Scratch::new()?;
    let home = scratch.0.join("home");
    let agent = home.join(".omp/agent");
    std::fs::create_dir_all(&agent).context(UNAVAILABLE)?;
    std::fs::create_dir(scratch.0.join("tmp")).context(UNAVAILABLE)?;
    let settings = scope.home.join(".omp/agent/config.yml");
    if let Some((_, Some(expected))) = scope.files.iter().find(|(path, _)| *path == settings) {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&settings)
            .context(UNAVAILABLE)?;
        ensure!(
            FileStamp::from(file.metadata().context(UNAVAILABLE)?) == *expected
                && expected.size <= 64 * 1024,
            UNAVAILABLE
        );
        let mut bytes = Vec::with_capacity(expected.size as usize);
        (&mut file)
            .take(expected.size + 1)
            .read_to_end(&mut bytes)
            .context(UNAVAILABLE)?;
        ensure!(
            bytes.len() as u64 == expected.size
                && FileStamp::from(file.metadata().context(UNAVAILABLE)?) == *expected,
            UNAVAILABLE
        );
        private_file(&agent.join("config.yml"), &bytes)?;
    }
    let args = ["config", "list", "--scope=global", "--json"].map(str::to_owned);
    #[cfg(feature = "omp-go-fixture")]
    let mut child = if GoMode::inference() == GoMode::Fixture {
        spawn_environment(
            executable,
            &args,
            &scratch.0,
            &OmpConfig::default(),
            &home,
            None,
        )?
    } else {
        spawn_isolated(executable, &args, &scratch.0, &home)?
    };
    #[cfg(not(feature = "omp-go-fixture"))]
    let mut child = spawn_isolated(executable, &args, &scratch.0, &home)?;
    let bytes = tokio::time::timeout_at(
        deadline.at,
        collect_native_evidence(
            &mut child,
            Vec::new(),
            NativeProtocol::Discovery,
            None,
            &mut Default::default(),
        ),
    )
    .await
    .context(UNAVAILABLE)?
    .context(UNAVAILABLE)?;
    let global: Value = serde_json::from_slice(&bytes).context(UNAVAILABLE)?;
    ensure!(
        global
            .as_object()
            .is_some_and(
                |settings| settings.iter().all(|(key, entry)| match key.as_str() {
                    "modelRoles" | "update" | "setupVersion" => true,
                    // Native OMP may report nested settings as separate dotted keys.
                    "update.auto" => entry["value"].is_boolean(),
                    "retry.enabled" | "retry.modelFallback" => entry["value"] == false,
                    "retry" => entry["value"]
                        .as_object()
                        .is_some_and(|retry| retry.iter().all(|(name, value)| matches!(
                            name.as_str(),
                            "enabled" | "modelFallback"
                        ) && value == false)),
                    _ => false,
                })
            ),
        UNAVAILABLE
    );
    Ok(())
}

async fn run_probe(
    executable: &Path,
    provider: &str,
    name: &str,
    effort: &str,
    case: probe::Case,
    deadline: ExecutionDeadline,
) -> Result<Option<String>> {
    #[cfg(feature = "omp-go-fixture")]
    if matches!(case, probe::Case::RejectAuth) && GoMode::inference() != GoMode::Fixture {
        return Ok(None);
    }
    #[cfg(feature = "omp-go-fixture")]
    let endpoint = if GoMode::inference() == GoMode::Fixture {
        Some(probe::Probe::start(case, name, effort).await?)
    } else {
        None
    };
    let scratch = Scratch::new()?;
    let home = scratch.0.join("home");
    let agent = home.join(".omp/agent");
    std::fs::create_dir_all(&agent)?;
    #[cfg(feature = "omp-go-fixture")]
    if let Some(endpoint) = &endpoint {
        let key = if matches!(case, probe::Case::RejectAuth) {
            "agmi-loopback-wrong-fixture-key"
        } else {
            FIXTURE_KEY
        };
        private_file(
            &agent.join("models.yml"),
            &serde_json::to_vec(&json!({"providers":{(provider):{
                "baseUrl":format!("{}/v1",endpoint.origin()), "apiKey":key
            }}}))?,
        )?;
    }
    #[cfg(feature = "omp-go-fixture")]
    let mode = if endpoint.is_some() {
        GoMode::Probe
    } else {
        GoMode::StockProbe
    };
    #[cfg(not(feature = "omp-go-fixture"))]
    let mode = GoMode::StockProbe;
    if mode == GoMode::StockProbe {
        private_file(
            &scratch.0.join("omp-probe-response.json"),
            &serde_json::to_vec(&probe::response(case, name, effort)?)?,
        )?;
    }
    let model = ModelConfig {
        harness: Harness::Omp,
        executable: executable.to_owned(),
        model: format!("{provider}/{name}"),
        reasoning: effort.to_owned(),
        omp: Some(OmpConfig {
            provider_discovery_cwd: Some(home.clone()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let invocation = launch::new_invocation_id()?;
    let prepared = prepare_json(
        &model,
        json!({"kind":"answer","probe":probe::REQUEST_MARKER}).to_string(),
        probe::POLICY,
        &invocation,
        &scratch.0,
        deadline,
        mode,
    )?;
    #[cfg(feature = "omp-go-fixture")]
    let (mut owner, origin) = if let Some(endpoint) = &endpoint {
        (
            spawn_environment(
                executable,
                &prepared.args,
                &scratch.0,
                &OmpConfig::default(),
                &home,
                Some(endpoint.proxy()),
            )?,
            Cow::Owned(format!("{}/v1", endpoint.origin())),
        )
    } else {
        (
            spawn_isolated(executable, &prepared.args, &scratch.0, &home)?,
            Cow::Borrowed(STOCK_ENDPOINT),
        )
    };
    #[cfg(not(feature = "omp-go-fixture"))]
    let (mut owner, origin) = (
        spawn_isolated(executable, &prepared.args, &scratch.0, &home)?,
        Cow::Borrowed(STOCK_ENDPOINT),
    );
    let (terminal, descriptor) = exchange_inference(
        &mut owner,
        prepared.input,
        deadline,
        Descriptor::Probe(origin.as_ref()),
        None,
    )
    .await?;
    if mode == GoMode::StockProbe {
        // Only the guarded synthetic fetch callback emits this dispatch witness.
        ensure!(
            terminal.entries["entries"]
                .as_array()
                .is_some_and(|entries| entries.len() == 2 && entries[0]["customType"] == DISPATCH),
            FAILED
        );
    }
    let mut report = NativeReportedEvidence::default();
    let returned = terminal.verify(model.model, &mut report);
    #[cfg(feature = "omp-go-fixture")]
    if let Some(endpoint) = endpoint {
        endpoint.finish().await?;
    }
    match case {
        #[cfg(feature = "omp-go-fixture")]
        probe::Case::RejectAuth => {
            ensure!(
                descriptor.is_none()
                    && returned.is_err_and(|e| failure_code(&e) == "native_auth_unavailable"),
                FAILED
            );
            return Ok(None);
        }
        probe::Case::Capture => {
            let (_, _, _, output) = returned?;
            ensure!(
                output == probe::OUTPUT && report.model.is_some_and(|model| model.value == name),
                FAILED
            );
        }
        probe::Case::RejectEffort => ensure!(
            returned.is_err_and(|e| failure_code(&e) == "native_api_unsupported"),
            FAILED
        ),
        probe::Case::RejectServedModel => ensure!(
            returned.is_err_and(|e| failure_code(&e) == "native_provenance_mismatch"),
            FAILED
        ),
    }
    Ok(Some(descriptor.context(FAILED)?))
}

pub(super) fn verify_descriptor(entry: &Value, endpoint: &str) -> Result<String> {
    ensure!(
        entry["route_url"]
            .as_str()
            .is_some_and(|url| url.trim_end_matches('/') == endpoint),
        FAILED
    );
    let digest = entry["route_digest"].as_str().context(FAILED)?;
    ensure!(
        digest.len() == 64 && digest.bytes().all(|c| c.is_ascii_hexdigit()),
        FAILED
    );
    Ok(digest.to_owned())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "requires Bubblewrap and unprivileged Linux namespaces"]
    async fn isolated_probe_closes_host_descriptors_and_stops_with_parent() -> Result<()> {
        let scratch = Scratch::new()?;
        std::fs::create_dir(scratch.0.join("tmp"))?;
        // A real inherited descriptor to a file outside the mounted scratch.
        let canary = tempfile::tempfile()?;
        // SAFETY: F_DUPFD returns a fresh non-CLOEXEC descriptor owned by us.
        let raw = unsafe { libc::fcntl(canary.as_raw_fd(), libc::F_DUPFD, 64) };
        ensure!(raw >= 64, "failed to create inheritable test descriptor");
        // SAFETY: raw was just allocated and has no other owner.
        let inherited = unsafe { OwnedFd::from_raw_fd(raw) };
        let args = [
            "-ec".into(),
            "test ! -e /proc/self/fd/$1; printf R; read -r input".into(),
            "agmi-probe".into(),
            inherited.as_raw_fd().to_string(),
        ];
        let shell = std::fs::canonicalize("/bin/sh")?;
        let mut child = spawn_isolated(&shell, &args, &scratch.0, &scratch.0)?;
        let input = child.child.stdin.take().context("missing test stdin")?;
        let mut output = child.child.stdout.take().context("missing test stdout")?;
        let mut ready = [0];
        tokio::time::timeout(Duration::from_secs(5), output.read_exact(&mut ready)).await??;
        assert_eq!(ready, *b"R");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), child.wait())
                .await
                .is_err(),
            "probe should be blocked while stdin remains open"
        );
        drop(child);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), output.read(&mut ready)).await??,
            0,
            "sandbox payload must exit with its parent, even with stdin open"
        );
        drop(input);
        Ok(())
    }
}
