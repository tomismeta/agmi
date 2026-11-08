use agmi::{
    admin,
    config::{Config, WorkKind},
    health, lifecycle, runtime,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const SCHEMA: &str = "agmi.cli.v1";

#[derive(Parser)]
#[command(
    name = "agmi",
    version,
    about = "Agents Gonna Mine It.",
    long_about = "Reliable, configurable MinePOA participation. New installations are paused; diagnostics never submit work."
)]
struct Cli {
    /// Local TOML configuration. Credentials are referenced, never embedded.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Emit a versioned JSON envelope.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect the compiled release identity without loading configuration.
    BuildInfo {
        #[arg(long)]
        manifest: bool,
    },
    /// Verify an existing hosted credential and create read-only, paused configuration.
    Init {
        #[arg(long)]
        account: String,
        #[arg(long, default_value = "poa-mainnet-1")]
        chain: String,
        #[arg(long, default_value = "https://minepoa.com")]
        base_url: String,
        /// Reference an existing private credential; never copy or replace it.
        #[arg(long, conflicts_with_all = ["key_stdin", "key_prompt"], required_unless_present_any = ["key_stdin", "key_prompt"])]
        api_key_file: Option<PathBuf>,
        /// Read a key from stdin, never from a command argument.
        #[arg(long)]
        key_stdin: bool,
        /// Prompt on the controlling terminal with echo disabled.
        #[arg(long, conflicts_with = "key_stdin")]
        key_prompt: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Replace a local credential only after paused/stopped and same-identity checks.
    Credentials {
        #[command(subcommand)]
        command: CredentialCommand,
    },
    /// Verify, install and enable a fresh local release without starting or resuming.
    Install {
        #[arg(long)]
        binary: PathBuf,
        /// Expected digest obtained through an operator-trusted channel.
        #[arg(long)]
        sha256: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Update from an operator-trusted local binary or explicit retained r-SHA256.
    Update {
        #[arg(long, conflicts_with_all = ["binary", "sha256"], required_unless_present = "binary")]
        release: Option<String>,
        #[arg(long, requires = "sha256")]
        binary: Option<PathBuf>,
        #[arg(long, requires = "binary")]
        sha256: Option<String>,
        #[arg(long)]
        stopped: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Explicit user-systemd controls; never change participation pause.
    Service {
        #[arg(value_parser = ["status", "start", "stop", "restart", "enable", "disable"])]
        action: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Inspect private recovery evidence or reconcile an already-bound request.
    Recover {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    /// Run the supervised participation loop using the configured modes.
    Run {
        /// Perform one bounded cycle and exit.
        #[arg(long)]
        once: bool,
    },
    /// Inspect local durable state without contacting MinePOA or a model.
    Status,
    /// Inspect sanitized read progress, failures and retry deadlines without network access.
    Reads,
    /// Inspect sanitized durable operations without exposing bearer IDs or payloads.
    Operations {
        #[command(subcommand)]
        command: OperationsCommand,
    },
    /// Check sanitized local liveness and participation evidence without side effects.
    Health {
        /// Stale heartbeat/observation limit; raised to the configured cycle timing floor.
        #[arg(long, default_value_t = 180, value_parser = clap::value_parser!(u64).range(1..))]
        stale_seconds: u64,
        /// Maximum total age of queued or pending work (not reset by polling).
        #[arg(long, default_value_t = 1800, value_parser = clap::value_parser!(u64).range(1..))]
        work_seconds: u64,
        /// Grace from first observation of the current epoch before requiring an answer.
        #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(1..))]
        answer_grace_seconds: u64,
        /// Require resumed active capabilities; false still requires a live controller.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        expect_participation: bool,
        /// Minimum free MiB on the state filesystem; zero disables this guard.
        #[arg(long, default_value_t = 128)]
        min_free_mib: u64,
    },
    /// Discover, inspect, validate or atomically update configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Privately inspect or update model guidance through stdin.
    Guidance {
        #[command(subcommand)]
        command: GuidanceCommand,
    },
    /// Durably prevent new submissions and model work.
    Pause,
    /// Explicitly resume configured capabilities (does not change their modes).
    Resume,
    /// Abandon interrupted model-only work while stopped; never resets a sent request.
    RecoverModel,
    /// Read sanitized local runtime events.
    Logs {
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
    },
    /// Show configured model routes without starting a harness.
    Agents,
    /// Discover commands and their effects.
    Commands,
}

#[derive(Subcommand)]
enum CredentialCommand {
    /// Never issues or revokes a remote key; stdin/file must already hold a replacement.
    Rotate {
        #[arg(long, conflicts_with_all = ["key_stdin", "key_prompt"], required_unless_present_any = ["key_stdin", "key_prompt"])]
        api_key_file: Option<PathBuf>,
        #[arg(long)]
        key_stdin: bool,
        #[arg(long, conflicts_with = "key_stdin")]
        key_prompt: bool,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum RecoveryCommand {
    /// Private output includes captured payload/model text and opaque identifiers.
    Inspect {
        #[arg(long)]
        operation: i64,
    },
    /// Adopt an intact journal while its writer is stopped.
    Adopt,
    /// Grant one risk-admitted dispatch while stopped, in explicit manual mode.
    Authorize {
        #[arg(long)]
        epoch: u64,
        #[arg(long, value_parser = ["answer", "judge", "mine"])]
        kind: String,
    },
    /// List manual grant history without network or journal writes.
    Grants {
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        before: Option<i64>,
    },
    /// Revoke one unconsumed grant while the writer is stopped; preserves history.
    Revoke {
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        grant: i64,
    },
    /// Verify terminal evidence for an identifier already bound in the journal.
    Resolve {
        #[arg(long)]
        operation: i64,
        #[arg(long, conflicts_with = "txid")]
        job_id: Option<String>,
        #[arg(long)]
        txid: Option<String>,
    },
}

#[derive(Subcommand)]
enum OperationsCommand {
    /// Newest-first stable pagination; next_before continues the filtered list.
    List {
        #[arg(long, value_parser = ["answer", "judge", "mine"])]
        kind: Option<String>,
        #[arg(long)]
        state: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        before: Option<i64>,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
    },
}

fn work_kind(kind: &str) -> WorkKind {
    match kind {
        "answer" => WorkKind::Answer,
        "judge" => WorkKind::Judge,
        "mine" => WorkKind::Mine,
        _ => unreachable!("clap validates work kind"),
    }
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Discover configurable fields without loading a configuration or journal.
    Schema,
    /// Validate and atomically apply a nested JSON merge patch from stdin.
    Apply {
        #[arg(long)]
        expected_revision: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the absolute configured state location only; never open its journal.
    StatePath,
    /// Create a read-only example configuration; refuses to overwrite a file.
    Init,
    /// Show nonsecret configuration without reading guidance files.
    Show,
    /// Validate configuration and guidance without network requests or model calls.
    Check,
}

#[derive(Subcommand)]
enum GuidanceCommand {
    /// Private output includes guidance text and revision tokens.
    Show {
        #[arg(long, value_parser = ["answer", "judge"])]
        kind: String,
        #[arg(long, default_value = "user", value_parser = ["core", "user"])]
        layer: String,
    },
    /// Atomically set private UTF-8 guidance from stdin; missing means create-only.
    Set {
        #[arg(long, value_parser = ["answer", "judge"])]
        kind: String,
        #[arg(long, default_value = "user", value_parser = ["core", "user"])]
        layer: String,
        #[arg(long)]
        expected_config_revision: String,
        #[arg(long)]
        expected_revision: String,
        #[arg(long)]
        dry_run: bool,
    },
}

fn administration_input() -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take((admin::MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("cannot read administration input")?;
    Ok(bytes)
}

fn config_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(path) = &cli.config {
        return Ok(path.clone());
    }
    Ok(dirs::config_dir()
        .context("cannot locate configuration directory; use --config")?
        .join("agmi/config.toml"))
}

fn initialize(path: &Path) -> Result<Value> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).context("cannot create configuration directory")?;
    }
    let _configuration_guard = admin::lock_config_directory(path)?;
    let text = toml::to_string_pretty(&Config::default())?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("cannot create configuration; an existing file is never overwritten")?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(
        json!({"path":path,"created":true,"note":"Set your existing account and local credential-file reference. New runtime state starts paused."}),
    )
}

fn discovery() -> Value {
    json!({"commands":[
        {"name":"init","network_reads":true,"network_writes":false,"local_writes":"unless --dry-run","purpose":"existing identity only; --account and --api-key-file, --key-stdin or --key-prompt; never registers or resumes"},
        {"name":"credentials rotate","network_reads":true,"network_writes":false,"local_writes":"credential only unless --dry-run","purpose":"requires initialized, paused, stopped account; verifies replacement identity; file/stdin/hidden prompt"},
        {"name":"install","network_reads":false,"network_writes":false,"local_writes":"unless --dry-run","purpose":"fresh install --binary local-path --sha256 trusted-digest; stage, activate stopped, enable; never starts/resumes"},
        {"name":"update","network_reads":false,"network_writes":false,"local_writes":"unless --dry-run","purpose":"--binary local-path --sha256 trusted-digest or retained --release r-SHA256; preserves service intent, --stopped forces stopped"},
        {"name":"service","network_reads":false,"network_writes":false,"local_writes":"unless status or --dry-run","purpose":"status/start/stop/restart/enable/disable; does not resume participation"},
        {"name":"run","network_reads":true,"model_calls":"active capabilities only","network_writes":"active capabilities and resumed state only","local_writes":true},
        {"name":"status","network_reads":false,"network_writes":false,"purpose":"local state and blockers"},
        {"name":"reads","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"sanitized read progress, failure categories and retry deadlines"},
        {"name":"health","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"sanitized local health; unhealthy exits nonzero"},
        {"name":"config init","network_writes":false,"local_writes":true},
        {"name":"config show","network_writes":false,"local_writes":false},
        {"name":"config check","network_writes":false,"local_writes":false},
        {"name":"config state-path","network_writes":false,"local_writes":false,"purpose":"plain absolute state path without opening journal"},
        {"name":"config schema","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"setting types, defaults and immutable boundaries; no config required"},
        {"name":"config apply","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":"unless --dry-run","purpose":"nested JSON merge patch on stdin; --expected-revision from config show.file_revision"},
        {"name":"guidance show","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"private_output":true,"purpose":"--kind answer|judge --layer core|user (default user); private text and revision tokens"},
        {"name":"guidance set","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":"unless --dry-run","private_output":true,"purpose":"UTF-8 stdin; --kind, --layer core|user, --expected-config-revision and --expected-revision; missing means create-only"},
        {"name":"build-info","network_writes":false,"local_writes":false,"purpose":"compiled release identity; --manifest emits installer manifest verbatim"},
        {"name":"pause","network_writes":false,"local_writes":true},
        {"name":"resume","network_writes":false,"local_writes":true,"purpose":"authorize configured capabilities"},
        {"name":"recover-model","network_writes":false,"local_writes":true,"purpose":"allow regeneration of model-only work; requires stopped writer"},
        {"name":"recover inspect","network_reads":false,"network_writes":false,"local_writes":false,"purpose":"private captured operation and evidence; may contain payload/model text"},
        {"name":"recover adopt","network_reads":false,"network_writes":false,"local_writes":true,"purpose":"stopped-writer intact journal migration"},
        {"name":"recover resolve","network_reads":true,"network_writes":false,"local_writes":true,"purpose":"verify authoritative terminal evidence for an already-bound request; never force-clear"},
        {"name":"recover authorize","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":true,"purpose":"stopped-writer one-dispatch manual participation grant; --epoch N --kind answer|judge|mine"},
        {"name":"recover grants","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"paginated grant history; --limit N --before ID"},
        {"name":"recover revoke","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":true,"purpose":"stopped-writer revoke --grant ID without erasing grant history"},
        {"name":"operations list","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"sanitized paginated operation IDs, state, epoch, timing and linkage; --kind --state --before --limit"},
        {"name":"logs","network_writes":false,"purpose":"sanitized local events"},
        {"name":"agents","network_writes":false,"model_calls":false},
        {"name":"commands","network_writes":false,"local_writes":false}
    ],"capabilities":["answer","judge","mine"],"modes":["active","read_only","off"],
        "participation_modes":["strict","participation_first","manual"],
        "limits":["Local pause cannot retract dispatched requests or stop server-side auto-mining.","A timeout does not prove a submission failed."]})
}

async fn execute(cli: &Cli) -> Result<(&'static str, Value)> {
    if matches!(cli.command, Command::BuildInfo { .. }) {
        return Ok(("build_info", runtime::build_info()));
    }
    if matches!(cli.command, Command::Commands) {
        return Ok(("commands", discovery()));
    }
    if matches!(
        cli.command,
        Command::Config {
            command: ConfigCommand::Schema
        }
    ) {
        return Ok(("config_schema", admin::schema()));
    }
    let path = config_path(cli)?;
    match &cli.command {
        Command::Init {
            account,
            chain,
            base_url,
            api_key_file,
            key_stdin,
            state_dir,
            dry_run,
            ..
        } => {
            let bytes = lifecycle::credential_input(api_key_file.as_deref(), *key_stdin)?;
            return Ok((
                "init",
                lifecycle::init(
                    &path,
                    lifecycle::InitOptions {
                        account,
                        chain,
                        base_url,
                        credential_file: api_key_file.as_deref(),
                        state_dir: state_dir.as_deref(),
                        dry_run: *dry_run,
                    },
                    &bytes,
                )
                .await?,
            ));
        }
        Command::Credentials {
            command:
                CredentialCommand::Rotate {
                    api_key_file,
                    key_stdin,
                    dry_run,
                    ..
                },
        } => {
            let bytes = lifecycle::credential_input(api_key_file.as_deref(), *key_stdin)?;
            return Ok((
                "credential_rotate",
                lifecycle::rotate(&path, &bytes, *dry_run).await?,
            ));
        }
        Command::Install {
            binary,
            sha256,
            dry_run,
        } => {
            anyhow::ensure!(
                sha256.len() == 64
                    && sha256
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "expected SHA256 must be 64 lowercase hex digits"
            );
            let binary = std::path::absolute(binary).context("cannot resolve local binary path")?;
            anyhow::ensure!(
                cli.config.is_none(),
                "installer uses ~/.config/agmi/config.toml; --config is unsupported"
            );
            return Ok((
                "install",
                lifecycle::installer(
                    &[
                        "install".into(),
                        binary.to_string_lossy().into_owned(),
                        "--sha256".into(),
                        sha256.clone(),
                    ],
                    *dry_run,
                )?,
            ));
        }
        Command::Update {
            release,
            binary,
            sha256,
            stopped,
            dry_run,
        } => {
            anyhow::ensure!(
                cli.config.is_none(),
                "installer uses ~/.config/agmi/config.toml; --config is unsupported"
            );
            let mut arguments = if let Some(release) = release {
                anyhow::ensure!(
                    release
                        .strip_prefix("r-")
                        .is_some_and(|hash| hash.len() == 64
                            && hash
                                .bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
                    "release must be an explicit r-SHA256 identity"
                );
                vec!["activate".into(), release.clone()]
            } else {
                let binary = std::path::absolute(
                    binary
                        .as_ref()
                        .context("update requires --binary or --release")?,
                )
                .context("cannot resolve local binary path")?;
                let hash = sha256.as_ref().context("update binary requires --sha256")?;
                anyhow::ensure!(
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                    "expected SHA256 must be 64 lowercase hex digits"
                );
                vec![
                    "update".into(),
                    binary.to_string_lossy().into_owned(),
                    "--sha256".into(),
                    hash.clone(),
                ]
            };
            if *stopped {
                arguments.push("--stopped".into());
            }
            return Ok(("update", lifecycle::installer(&arguments, *dry_run)?));
        }
        Command::Service { action, dry_run } => {
            anyhow::ensure!(
                cli.config.is_none(),
                "service uses ~/.config/agmi/config.toml; --config is unsupported"
            );
            return Ok((
                "service",
                lifecycle::installer(&["service".into(), action.clone()], *dry_run)?,
            ));
        }
        _ => {}
    }
    if matches!(
        cli.command,
        Command::Config {
            command: ConfigCommand::Init
        }
    ) {
        return Ok(("config_init", initialize(&path)?));
    }
    match &cli.command {
        Command::Run { once } => {
            runtime::run(&path, *once).await?;
            return Ok(("run", json!({"stopped":true})));
        }
        Command::Config {
            command: ConfigCommand::Show,
        } => {
            return Ok(("config", admin::show(&path)?));
        }
        Command::Config {
            command:
                ConfigCommand::Apply {
                    expected_revision,
                    dry_run,
                },
        } => {
            return Ok((
                "config_apply",
                admin::apply(&path, expected_revision, &administration_input()?, *dry_run)?,
            ));
        }
        Command::Guidance {
            command: GuidanceCommand::Show { kind, layer },
        } => {
            return Ok(("guidance", admin::guidance_show(&path, kind, layer)?));
        }
        Command::Guidance {
            command:
                GuidanceCommand::Set {
                    kind,
                    layer,
                    expected_config_revision,
                    expected_revision,
                    dry_run,
                },
        } => {
            return Ok((
                "guidance_set",
                admin::guidance_set(
                    &path,
                    kind,
                    layer,
                    expected_config_revision,
                    expected_revision,
                    &administration_input()?,
                    *dry_run,
                )?,
            ));
        }
        _ => {}
    }
    // Use the same lock order as config apply: source directory, then admission.
    // Keep the source snapshot stable until a control command establishes binding.
    let _configuration_guard = match &cli.command {
        Command::Pause
        | Command::Resume
        | Command::RecoverModel
        | Command::Recover {
            command:
                RecoveryCommand::Adopt
                | RecoveryCommand::Authorize { .. }
                | RecoveryCommand::Revoke { .. },
        } => Some(admin::lock_config_directory(&path)?),
        _ => None,
    };
    let config = if matches!(
        cli.command,
        Command::Resume
            | Command::Config {
                command: ConfigCommand::Check
            }
    ) {
        Config::load(&path)?
    } else {
        Config::load_metadata(&path)?
    };
    match &cli.command {
        Command::Operations {
            command:
                OperationsCommand::List {
                    kind,
                    state,
                    before,
                    limit,
                },
        } => Ok((
            "operations_list",
            runtime::operations_list(
                &config,
                kind.as_deref().map(work_kind),
                state.as_deref(),
                *before,
                usize::from(*limit),
            )?,
        )),
        Command::Recover { command } => match command {
            RecoveryCommand::Inspect { operation } => Ok((
                "recovery_inspect",
                runtime::recovery_inspect(&config, *operation)?,
            )),
            RecoveryCommand::Adopt => {
                runtime::recovery_adopt(&config)?;
                Ok((
                    "recovery_adopt",
                    json!({"schema":2,"uncertainty_preserved":true}),
                ))
            }
            RecoveryCommand::Authorize { epoch, kind } => Ok((
                "recovery_authorize",
                runtime::recovery_authorize(&config, *epoch, work_kind(kind))?,
            )),
            RecoveryCommand::Grants { before, limit } => Ok((
                "recovery_grants",
                runtime::recovery_grants(&config, *before, usize::from(*limit))?,
            )),
            RecoveryCommand::Revoke { grant } => Ok((
                "recovery_revoke",
                runtime::recovery_revoke(&config, *grant)?,
            )),
            RecoveryCommand::Resolve {
                operation,
                job_id,
                txid,
            } => Ok((
                "recovery_resolve",
                runtime::recovery_resolve(&path, *operation, job_id.as_deref(), txid.as_deref())
                    .await?,
            )),
        },
        Command::Status => Ok(("status", runtime::status(&config)?)),
        Command::Reads => Ok(("reads", runtime::reads(&config)?)),
        Command::Health {
            stale_seconds,
            work_seconds,
            answer_grace_seconds,
            expect_participation,
            min_free_mib,
        } => Ok((
            "health",
            health::check(
                &config,
                health::Options {
                    stale_seconds: *stale_seconds,
                    work_seconds: *work_seconds,
                    answer_grace_seconds: *answer_grace_seconds,
                    expect_participation: *expect_participation,
                    min_free_mib: *min_free_mib,
                },
            )?,
        )),
        Command::Pause => {
            runtime::pause(&config)?;
            Ok((
                "pause",
                json!({"paused":true,"server_auto_mining":"not_controlled"}),
            ))
        }
        Command::Resume => {
            runtime::resume(&config)?;
            Ok((
                "resume",
                json!({"paused":false,"capabilities":config.capabilities}),
            ))
        }
        Command::RecoverModel => Ok((
            "recover_model",
            json!({"abandoned_models":runtime::recover_model(&config)?,
                "network_requests_reset":false,"note":"Regeneration may incur another model charge."}),
        )),
        Command::Logs { limit } => Ok(("logs", runtime::events(&config, usize::from(*limit))?)),
        Command::Agents => Ok((
            "agents",
            json!({"routes":config.solver,"revision":config.optional_revision()?,"verified":false,"note":"Configured routes only; this command does not invoke models or inspect auth secrets or guidance contents."}),
        )),
        Command::Config {
            command: ConfigCommand::Check,
        } => {
            config.validate()?;
            Ok((
                "config_check",
                json!({"valid":true,"revision":config.revision()?,"network_verified":false,"auth_verified":false}),
            ))
        }
        Command::BuildInfo { .. }
        | Command::Init { .. }
        | Command::Credentials { .. }
        | Command::Install { .. }
        | Command::Update { .. }
        | Command::Service { .. }
        | Command::Run { .. }
        | Command::Config {
            command: ConfigCommand::StatePath,
        }
        | Command::Commands
        | Command::Guidance { .. }
        | Command::Config {
            command: ConfigCommand::Schema | ConfigCommand::Show | ConfigCommand::Apply { .. },
        }
        | Command::Config {
            command: ConfigCommand::Init,
        } => unreachable!(),
    }
}

#[tokio::main]
async fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    let json_requested = arguments.iter().any(|argument| argument == "--json");
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error)
            if json_requested
                && !matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) =>
        {
            eprintln!(
                "{}",
                json!({"schema":SCHEMA,"ok":false,"type":"error","error":{
                "code":"invalid_arguments","message":"Invalid command arguments; use agmi commands or --help."}})
            );
            std::process::exit(2);
        }
        Err(error) => error.exit(),
    };
    if matches!(cli.command, Command::BuildInfo { manifest: true }) {
        print!("{}", include_str!(env!("AGMI_BUILD_MANIFEST_PATH")));
        return;
    }
    if matches!(
        cli.command,
        Command::Config {
            command: ConfigCommand::StatePath
        }
    ) {
        match config_path(&cli).and_then(|path| Config::load_metadata(&path)) {
            Ok(config) => println!("{}", config.state_dir.display()),
            Err(_) => {
                eprintln!("agmi: cannot read configuration metadata");
                std::process::exit(1);
            }
        }
        return;
    }
    match execute(&cli).await {
        Ok((kind, data)) => {
            let ok = kind != "health" || data["healthy"].as_bool() == Some(true);
            let value = json!({"schema":SCHEMA,"ok":ok,"type":kind,"data":data});
            if cli.json {
                println!("{value}");
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("JSON value serializes")
                );
            }
            if !ok {
                std::process::exit(1);
            }
        }
        Err(error) => {
            // Errors must be constructed at safe boundaries; never print Debug chains
            // containing HTTP requests, credentials, provider output or answer text.
            if cli.json {
                eprintln!(
                    "{}",
                    json!({"schema":SCHEMA,"ok":false,"type":"error","error":{
                        "code":admin::error_code(&error).unwrap_or("operation_failed"),
                        "message":error.to_string()}})
                );
            } else {
                eprintln!("agmi: {error}");
            }
            std::process::exit(1);
        }
    }
}
