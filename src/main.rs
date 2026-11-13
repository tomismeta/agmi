mod cli_error;

use agmi::{
    admin,
    capability::LaneId,
    config::{Config, NetworkConfig},
    doctor, health, lifecycle, logs, registration, runtime, update,
};
use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
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
    long_about = "Reliable, configurable MinePOA participation. New installations are paused; diagnostics never submit work.",
    after_help = "EVERYDAY WORKFLOW\n  agmi health                 Check core and individual lane health\n  agmi status                 Inspect local participation evidence\n  agmi doctor                 Distinguish automatic waits from intervention\n  agmi doctor --repair        Explicitly authorize eligible guarded repairs\n  agmi logs --follow          Follow sanitized local events\n  agmi update --check         Check latest stable without changes\n  agmi update                 Compatible update, then diagnose readiness\n  agmi update --repair        Update and authorize guarded repairs\n  agmi update --migrate       Explicit stopped migration maintenance\n\nOrdinary compatible updates preserve configuration, guidance, credentials and pause intent.\nMigration maintenance may change pause/generation/revisions and never resumes participation.\nUnknown submissions are never replayed or erased by maintenance.\nUse agmi <command> --help for examples and agmi --json commands for effect metadata."
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

fn network_options(
    profile: Option<&Path>,
    chain: Option<&str>,
    base_url: Option<&str>,
) -> Result<NetworkConfig> {
    let mut network = profile
        .map(NetworkConfig::read_profile)
        .transpose()?
        .unwrap_or_default();
    if let Some(chain) = chain {
        network.chain = chain.into();
    }
    if let Some(origin) = base_url {
        network.base_url = origin.into();
    }
    network.origin()?;
    network.api.validate()?;
    Ok(network)
}

#[derive(Subcommand)]
enum Command {
    /// Inspect the compiled release identity without loading configuration.
    BuildInfo {
        /// Emit the raw installer manifest even with --json (explicit envelope exception).
        #[arg(long)]
        manifest: bool,
    },
    /// Explicitly create a hosted identity, or inspect local registration evidence.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Verify an existing hosted credential and create read-only, paused configuration.
    Init {
        #[arg(long)]
        account: String,
        #[arg(long)]
        chain: Option<String>,
        #[arg(long)]
        base_url: Option<String>,
        /// Network defaults, trust and API route templates; contains no credential value.
        #[arg(long)]
        network_config: Option<PathBuf>,
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
    /// Install a fresh stopped release, or only publish a verified release with --stage-only.
    Install {
        #[arg(long)]
        binary: PathBuf,
        /// Expected digest obtained through an operator-trusted channel.
        #[arg(long)]
        sha256: String,
        /// Publish a verified release only; never select, enable, stop or start units.
        #[arg(long)]
        stage_only: bool,
        /// Select the current journal format over supported older formats; stays stopped.
        #[arg(long, conflicts_with = "stage_only")]
        migration_only: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Update compatible releases, or explicitly prepare stopped migration maintenance.
    #[command(
        after_help = "EXAMPLES\n  agmi update --check\n  agmi update\n  agmi update --repair\n  agmi update --dry-run\n  agmi update --binary /path/to/agmi --sha256 <trusted-digest>\n  agmi update --migrate --proposal proposal.json\n  agmi update --release r-<selected-sha256> --migrate --proposal request.json --expected-token <token>\n\nDefault source: published stable releases from tomismeta/agmi, never main.\nChecks/dry runs never execute incoming code or assess operational compatibility.\nOrdinary compatible updates preserve configuration, pause/generation and runtime intent.\n--migrate is disruptive maintenance: disable boot activation, stop and if needed pause.\nExact marker-only conversion completes automatically; other conversion prepares a\nprivate preview for exact request/token approval pinned to the selected --release.\nNo migration automatically starts or resumes participation. Changed revisions can\ninvalidate grants/captures. --proposal FILE|- reads private JSON (64 KiB maximum);\nonly explicit '-' reads stdin. Use --json and private output files for preparation.\nPublished 0.1.0/0.1.1 clients need a one-time independently verified new executable\ninvoked directly; old online discovery cannot bootstrap the journal-format crossing.\n--repair authorizes only guarded refusal recovery, not abandonment or replay.\nUpdate, conversion and readiness are separate outcomes. Managed updates use only\nthe default configuration. No force, automatic risk approval, rollback or resume."
    )]
    Update {
        /// Select a retained compatible release instead of downloading.
        #[arg(long, conflicts_with_all = ["binary", "sha256"])]
        release: Option<String>,
        /// Select a local binary instead of downloading; requires its trusted digest.
        #[arg(long, requires = "sha256")]
        binary: Option<PathBuf>,
        #[arg(long, requires = "binary")]
        sha256: Option<String>,
        /// Internal compare-and-swap fence for incoming verified installer handoff.
        #[arg(long, hide = true, requires = "binary", conflicts_with_all = ["check", "repair", "dry_run"])]
        expected_release: Option<String>,
        /// Query latest stable without installing or repairing.
        #[arg(long, conflicts_with_all = ["release", "binary", "sha256", "stopped", "dry_run", "repair"])]
        check: bool,
        /// Authorize guarded refusal repairs and legacy identity normalization after update/no-op.
        #[arg(long)]
        repair: bool,
        /// Leave the service stopped after activation; never changes pause intent.
        #[arg(long)]
        stopped: bool,
        /// Verified supported-old-format bootstrap; disables boot activation, never starts or repairs.
        #[arg(long, requires = "stopped", conflicts_with_all = ["check", "repair"])]
        migration_only: bool,
        /// Stopped, boot-disabled migration maintenance; may pause and invalidate grants/captures.
        #[arg(long, conflicts_with_all = ["repair", "migration_only"])]
        migrate: bool,
        /// Private JSON proposal, at most 64 KiB; only an explicit '-' reads stdin.
        #[arg(long, requires = "migrate", value_name = "FILE|-")]
        proposal: Option<PathBuf>,
        /// Apply the exact prepared token; requires an explicit selected-release pin.
        #[arg(long, requires_all = ["migrate", "release"], conflicts_with_all = ["binary", "sha256"])]
        expected_token: Option<String>,
        /// Explicit risk approval; must equal --expected-token.
        #[arg(long, requires = "expected_token")]
        accept_risk_change: Option<String>,
        /// Show the update/repair plan without applying changes.
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
    #[command(
        after_help = "Local snapshot only; no network or model calls. Exit zero means the snapshot was\nread successfully, not that participation is healthy; use health for that check.\nOperational health and retained risk are separate. Historical unknowns do not fail\nan open fresh-work path; actual blockers and unavailable current evidence still do.\nCurrent actions precede background reconciliation. --verbose shows retained detail."
    )]
    Status {
        /// Include complete retained diagnostic evidence.
        #[arg(long)]
        verbose: bool,
    },
    /// Diagnose unattended progress; optionally apply guarded local evidence repairs.
    #[command(
        after_help = "EXAMPLES\n  agmi doctor\n  agmi --json doctor\n  agmi doctor --repair\n\nRead-only by default. Exit zero means an unattended path exists and repair did not\nfail; it is not a healthy or settled outcome. Inspect operational health separately.\n--repair authorizes only evidence-proven refusal recovery and eligible legacy\nidentity normalization. It never clears blanket unknowns, replays uncertain work,\nverifies identity, replaces credentials, raises budgets or changes retry deadlines.\nCurrent blockers take precedence over background reconciliation. Automatic recovery\nis a retained path, not a promise that old outcomes will ever resolve."
    )]
    Doctor {
        /// Apply eligible local repairs, briefly stopping/restoring a matching managed runtime if needed.
        #[arg(long)]
        repair: bool,
        /// Include complete retained diagnostic evidence.
        #[arg(long)]
        verbose: bool,
    },
    /// Inspect sanitized read progress, failures and retry deadlines without network access.
    Reads,
    /// Inspect sanitized durable operations without exposing bearer IDs or payloads.
    Operations {
        #[command(subcommand)]
        command: OperationsCommand,
    },
    /// Check sanitized local liveness and participation evidence without side effects.
    #[command(
        after_help = "Local checks for controller, answer, judge and mine; no network or model calls.\nExit zero means operationally clear under the selected checks, not remote finality.\nRetained unknowns and accepted work awaiting finality can require risk attention\nwhile healthy remains true, under finite or unbounded policy. Actual capacity or\nsame-work blockers, overdue local execution and unavailable current evidence still\nfail the check. Fresh complete empty judging inventory is healthy idle; stale or\npartial inventory is not proof of no work. Unknown outcomes never authorize replay.\n--verbose shows full evidence; model failures describe native completion, not receipt errors."
    )]
    Health {
        /// Include complete retained diagnostic evidence.
        #[arg(long)]
        verbose: bool,
        /// Stale heartbeat/observation limit; raised to the configured cycle timing floor.
        #[arg(long, default_value_t = 180, value_parser = clap::value_parser!(u64).range(1..))]
        stale_seconds: u64,
        /// Maximum age of current queued/pending work; excludes background recovery.
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
    /// Inspect or fence one lane independently of its configured mode.
    #[command(
        after_help = "EXAMPLES\n  agmi lane show answer\n  agmi --json lane pause answer --expected-control <control-token>\n  agmi lane resume answer --expected-control <current-control-token> --wait-seconds 30\n\nRead desired.control_token from lane show before each change. This token is not a\nconfig file revision. A current-token no-op does not advance control revision.\nPause acknowledges a local admission fence, not remote cancellation or settlement.\nAlready-started native work and remote jobs may continue; dispatch uncertainty is\nreported separately. Resume removes only this lane override, grants no retry right,\nand does not prove admission open. Desired configuration, journal closure and runtime\nobservations are distinct. --wait-seconds bounds lock/write acquisition (1..=300,\ndefault 30), not stalled OS I/O or a remote completion deadline. No model or guidance\nfiles are loaded by lane commands."
    )]
    Lane {
        #[command(subcommand)]
        command: LaneCommand,
    },
    /// Durably prevent new submissions and model work.
    Pause,
    /// Explicitly resume configured capabilities (does not change their modes).
    Resume,
    /// Abandon interrupted model-only work while stopped; never refunds execution exposure or resets sent requests.
    RecoverModel,
    /// Read sanitized local runtime events.
    #[command(
        after_help = "EXAMPLES\n  agmi logs --limit 50\n  agmi logs --follow\n  agmi --json logs --follow\n\nFollowing prints the initial retained tail oldest-first, then new event IDs.\nJSON following emits one agmi.cli.v1 log_event envelope per line. No credentials,\nguidance or private event detail is read. Ctrl-C or SIGTERM stops following.\nRetention gaps or journal replacement stop the stream rather than silently skipping."
    )]
    Logs {
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
        /// Follow newly recorded sanitized events without network requests.
        #[arg(long, short)]
        follow: bool,
    },
    /// Print shell completions; does not install or modify shell files.
    #[command(
        after_help = "EXAMPLES\n  agmi completions bash\n  agmi completions zsh\n  agmi completions fish\n\nPrints a script to stdout; choose where to install it in your shell configuration.\nWith --json, returns the script in the normal envelope. No configuration is loaded."
    )]
    Completions {
        #[arg(value_parser = ["bash", "zsh", "fish"])]
        shell: String,
    },
    /// Show configured model routes without starting a harness.
    Agents,
    /// Discover commands and their effects.
    Commands,
}

fn lane_parser() -> clap::builder::PossibleValuesParser {
    clap::builder::PossibleValuesParser::new(LaneId::ALL.map(LaneId::as_str))
}

fn model_lane_parser() -> clap::builder::PossibleValuesParser {
    clap::builder::PossibleValuesParser::new(
        agmi::capability::DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.model_task.is_some())
            .map(|descriptor| descriptor.id.as_str())
            .collect::<Vec<_>>(),
    )
}

#[derive(Subcommand)]
enum LaneCommand {
    /// Read desired control, authoritative closure and sourced runtime observation.
    ///
    /// Control/admission evidence only; use status or health for per-lane operational health.
    Show {
        #[arg(value_parser = lane_parser())]
        lane: String,
    },
    /// Commit a local fence against new preflight, inference and effect admission.
    Pause {
        #[arg(value_parser = lane_parser())]
        lane: String,
        /// Opaque desired.control_token returned by lane show; not file_revision.
        #[arg(long)]
        expected_control: String,
        /// Acquisition deadline only; stalled OS I/O is not a hard wall-clock bound.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
        wait_seconds: u64,
    },
    /// Remove only this override; neither grants retries nor proves admission open.
    Resume {
        #[arg(value_parser = lane_parser())]
        lane: String,
        #[arg(long)]
        expected_control: String,
        /// Acquisition deadline only; stalled OS I/O is not a hard wall-clock bound.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
        wait_seconds: u64,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Plan without effects; --confirm authorizes bounded proof of work and registration.
    ///
    /// The API key is returned only once. A crash after remote creation but before
    /// durable private response capture can permanently lose it. An uncertain
    /// attempt is never automatically submitted again.
    Create {
        #[arg(long)]
        label: String,
        #[arg(long)]
        chain: Option<String>,
        /// Explicitly trusted HTTPS origin, or an isolated loopback fixture.
        #[arg(long)]
        base_url: Option<String>,
        #[arg(long)]
        network_config: Option<PathBuf>,
        #[arg(long)]
        invited_by: Option<String>,
        /// Maximum accepted challenge difficulty; never lowers server difficulty.
        #[arg(long, default_value_t = 24, value_parser = clap::value_parser!(u32).range(0..=256))]
        max_pow_bits: u32,
        /// Maximum number of nonce hashes for one attempt.
        #[arg(long, default_value_t = 67_108_864, value_parser = clap::value_parser!(u64).range(1..))]
        max_pow_hashes: u64,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
        pow_seconds: u64,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
        http_seconds: u64,
        /// Explicitly accept this exact server algorithm identifier.
        #[arg(long)]
        expected_pow_algo: Option<String>,
        /// Authorize remote creation and acknowledge the irreversible lost-key crash window.
        #[arg(long)]
        confirm: bool,
        /// Explicit new attempt only after a definitive rejection and its retry floor.
        #[arg(long, requires = "confirm")]
        retry_rejected: bool,
    },
    /// Inspect sanitized local registration evidence without network or file writes.
    Status,
    /// Recover retained registration files locally; never contacts the network.
    Resume {
        /// Authorize local credential/configuration publication from the captured response.
        #[arg(long)]
        confirm: bool,
    },
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
        #[arg(long, value_parser = lane_parser())]
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
    /// Verify bound terminal evidence, or preview/retire a retained pre-enqueue refusal locally.
    Resolve {
        #[arg(long)]
        operation: i64,
        #[arg(long, conflicts_with = "txid")]
        job_id: Option<String>,
        #[arg(long)]
        txid: Option<String>,
        /// Local retained-evidence recovery; no network. Defaults to preview, never resubmits.
        #[arg(long, conflicts_with_all = ["job_id", "txid"])]
        refusal: bool,
        /// Explicit nonmutating refusal preview; returns an eligible record's approval token.
        #[arg(long, requires = "refusal", conflicts_with = "apply")]
        dry_run: bool,
        /// Apply exactly the reviewed refusal preview while the controller is stopped.
        #[arg(long, requires = "refusal", value_name = "PREVIEW_TOKEN")]
        apply: Option<String>,
    },
}

#[derive(Subcommand)]
enum OperationsCommand {
    /// Newest-first stable pagination; next_before continues the filtered list.
    List {
        #[arg(long, value_parser = lane_parser())]
        kind: Option<String>,
        #[arg(long)]
        state: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        before: Option<i64>,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
    },
}

fn work_kind(kind: &str) -> LaneId {
    LaneId::ALL
        .into_iter()
        .find(|lane| lane.as_str() == kind)
        .expect("clap validates registered lane")
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
    /// Explicit local configuration/journal conversion; never submits network work.
    Migrate {
        #[command(subcommand)]
        command: MigrationCommand,
    },
}

#[derive(Subcommand)]
enum MigrationCommand {
    /// Preview a JSON proposal from stdin; retain its request and token for apply.
    #[command(after_help = r#"INPUT
  {"caps":{"answer":2,"judge":1,"mine":1}}
  {"candidate_toml":"[capabilities.answer]\nmode = \"active\"\n..."}
  {}

These are operator-selected examples, not recommended risk limits.
Legacy initial authority adoption additionally requires "adopt_legacy":true.
An unchanged current-shape configuration with a format-3 journal accepts {}.
A per-lane configuration carrying the retired schema_version = 2 marker with a
format-4 journal also accepts {} for explicit marker removal; policy, lane
controls, generation and journal history remain unchanged. Ordinary config
loading rejects the retired marker. Capability candidate TOML is unversioned.
Conversion requires a stopped controller and durable global pause. The preview
token binds target_journal_format; a sealed migration is never silently retargeted.
Keep the returned request and token together. Apply reads that request from stdin;
changed or unproven exposure additionally requires --accept-risk-change TOKEN.
Preview and apply make no network or model calls; migration never resumes participation."#)]
    Preview,
    /// Apply the preview's request JSON from stdin; conversion remains paused.
    Apply {
        #[arg(long)]
        expected_token: String,
        /// Required only for changed/unproven exposure; must equal the preview token.
        #[arg(long)]
        accept_risk_change: Option<String>,
    },
    /// Finish the exact sealed target; historical target 3 still needs a separate current-format migration.
    #[command(
        after_help = "Resume never resumes participation or retargets a seal. A recognized historical target-3 seal finishes its original conversion unchanged, remains paused, and reports further_migration_required=true. Then explicitly preview and apply a separate format-3-to-current conversion before running. Inspect config migrate status for recovery_supported, recovery_prerequisite and preserved history. Unsupported recovery refuses without rewriting evidence."
    )]
    Resume {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        expected_token: String,
    },
    /// Inspect recovery support, prerequisites and preserved migration history without loading configuration.
    Status {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Print private sealed inputs to stdout for explicit conflict recovery.
    Export {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        expected_token: String,
    },
}

#[derive(Subcommand)]
enum GuidanceCommand {
    /// Private output includes guidance text and revision tokens.
    Show {
        #[arg(long, value_parser = model_lane_parser())]
        kind: String,
        #[arg(long, default_value = "user", value_parser = ["core", "user"])]
        layer: String,
    },
    /// Atomically set private UTF-8 guidance from stdin; missing means create-only.
    Set {
        #[arg(long, value_parser = model_lane_parser())]
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

fn update_proposal(path: &Path) -> Result<Value> {
    let invalid = || {
        cli_error::BoundaryError(
            "update_invalid_proposal",
            "Update proposal must be a private JSON object of at most 64 KiB; only --proposal - reads stdin.",
        )
    };
    let mut bytes = Vec::new();
    if path == Path::new("-") {
        std::io::stdin()
            .lock()
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
    } else {
        std::fs::File::open(path)
            .map_err(|_| invalid())?
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
    }
    anyhow::ensure!(bytes.len() <= 64 * 1024, invalid());
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    anyhow::ensure!(value.is_object(), invalid());
    Ok(value)
}

fn update_actions(data: &mut Value) {
    // Keep a specific continuation if an earlier layer already supplied one.
    if data["next_actions"].is_array() {
        return;
    }
    let commands: Vec<(&[&str], bool)> = match data["update"]["status"].as_str() {
        Some("migration_required") => vec![
            (&["update", "--migrate"], true),
            (&["update", "--help"], false),
        ],
        Some("migration_prepared") => vec![
            (&["update", "--help"], false),
            (&["config", "migrate", "apply", "--help"], false),
        ],
        Some("migration_complete_stopped") => vec![
            (&["config", "check"], false),
            (&["status"], false),
            (&["service", "status"], false),
        ],
        Some("recovery_required") => vec![
            (&["config", "migrate", "status", "--help"], false),
            (&["config", "migrate", "export", "--help"], false),
        ],
        _ if data["migration"]["phase"] == "complete"
            || data["migration"]["phase"] == "failed"
            || data["migration"]["phase"] == "prepared"
            || data["update"]["migrate"] == true =>
        {
            vec![
                (&["service", "status"], false),
                (&["config", "migrate", "status", "--help"], false),
            ]
        }
        _ => vec![(&["update", "--check"], false), (&["doctor"], false)],
    };
    let mut actions: Vec<Value> = commands
        .into_iter()
        .map(|(argv, authorization)| cli_error::action(None, argv, authorization))
        .collect();
    let prepared = data["update"]["status"] == "migration_prepared";
    if data["migration"]["pending"] == false
        && data["migration"]["recovery_prerequisite"] == "authority_adoption"
    {
        actions.insert(
            0,
            cli_error::action(None, &["recover", "adopt", "--help"], false),
        );
        actions.insert(0, json!({"kind":"instruction","authorization_required":true,
            "message":"The historical seal is complete but proves only writer authority. Keep every controller/native task stopped, inspect admission authority, then separately approve canonical recover adopt. Do not repeat the old token or enable/start participation."}));
    } else if data["migration"]["pending"] == false
        && data["migration"]["further_migration_required"] == true
    {
        if let Some(release) = data["migration"]["release_id"].as_str() {
            actions.insert(
                0,
                cli_error::action(None, &["update", "--release", release, "--migrate"], true),
            );
        }
        actions.insert(0, json!({"kind":"instruction","authorization_required":false,
            "message":"The original historical seal is complete. Prepare and review a separate current-format conversion with a new request/token; the old approval cannot authorize it. Keep services stopped and boot-disabled."}));
    } else if (prepared
        || (data["update"]["status"] == "recovery_required"
            && data["migration"]["pending"] == true))
        && let (Some(release), Some(token)) = (
            data["migration"]["release_id"].as_str(),
            data["migration"]["token"].as_str(),
        )
    {
        let mut argv = vec!["update", "--release", release, "--migrate"];
        if prepared {
            argv.extend(["--proposal", "request.json"]);
        }
        argv.extend(["--expected-token", token]);
        actions.insert(0, cli_error::action(None, &argv, true));
        if prepared {
            actions.insert(0, json!({"kind":"instruction","authorization_required":false,
                "message":"Review the private preview and save its exact request as private request.json before executing the pinned continuation."}));
        }
        if data["migration"]["risk_change_required"] == true {
            actions.push(json!({"kind":"instruction","authorization_required":true,
                "message":"The pinned continuation also needs --accept-risk-change with the exact expected token, only after separate review and explicit approval of the preview's risk change."}));
        }
    }
    data["next_actions"] = Value::Array(actions);
}

fn migration_can_offer_activation(data: &Value) -> bool {
    data["migration"]["phase"] == "complete"
        && data["migration"]["pending"] == false
        && data["migration"]["target_journal_format"] == agmi::journal::CURRENT_JOURNAL_FORMAT
        && data["migration"]["further_migration_required"] != true
        && data["migration"].get("recovery_prerequisite") == Some(&Value::Null)
}

fn update_consequences(data: &Value) {
    match data["update"]["status"].as_str() {
        Some("migration_required") => println!(
            "Migration required; ordinary update has not authorized conversion. Use --migrate for stopped, boot-disabled maintenance. Pause/revision changes may invalidate grants/captures; participation will not automatically resume."
        ),
        Some("migration_prepared") => {
            println!(
                "Preparation only: conversion awaits exact request/token approval pinned to the selected release. Services remain stopped and boot-disabled; participation is not resumed."
            );
            if data["private"] == true && data["preview"].is_object() {
                println!("Private migration preview (do not publish):");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data["preview"]).expect("migration preview JSON")
                );
            }
        }
        Some("recovery_required" | "migration_complete_stopped")
            if data["migration"]["pending"] == false
                && data["migration"]["recovery_prerequisite"] == "authority_adoption" =>
        {
            println!(
                "Historical conversion complete; explicit admission-authority adoption is still required. Keep all controllers/native work stopped. Inspect authority and separately approve recover adopt; do not enable/start services or repeat the old token."
            )
        }
        Some("recovery_required" | "migration_complete_stopped")
            if data["migration"]["pending"] == false
                && data["migration"]["further_migration_required"] == true =>
        {
            println!(
                "The original historical seal is complete, not the current-format upgrade. Prepare and approve a separate conversion with a new token. Keep services stopped and boot-disabled; the old approval cannot authorize the next conversion."
            )
        }
        Some("migration_complete_stopped") if !migration_can_offer_activation(data) => println!(
            "Current-format completion and authority prerequisites are not confirmed. Keep participation stopped; inspect canonical migration status before any activation."
        ),
        Some("migration_complete_stopped") => println!(
            "Migration complete, not participation readiness: services remain stopped and boot-disabled; migration does not unpause participation. Check configuration and local status; separately enable/start services and review readiness before explicit resume."
        ),
        Some("recovery_required") => println!(
            "Migration recovery required. Keep participation stopped; inspect canonical migration status/export and finish only the exact sealed token/target. Never restart an incompatible old writer."
        ),
        _ if matches!(
            data["migration"]["phase"].as_str(),
            Some("complete" | "failed")
        ) =>
        {
            println!(
                "Inspect migration and installation phases separately. Failure does not prove rollback or unchanged pause/boot intent; inspect actual state and canonical migration recovery before any start or participation resume."
            )
        }
        Some("failed") if data["update"]["migrate"] == true => println!(
            "Migration did not finish. Inspect the installation evidence before retrying: maintenance may have stopped services or changed durable pause. No automatic rollback, start or participation resume is authorized."
        ),
        _ => {}
    }
}

fn config_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(path) = &cli.config {
        return Ok(std::path::absolute(path)?);
    }
    Ok(std::path::absolute(
        dirs::home_dir()
            .context("cannot locate home directory; use --config")?
            .join(".config/agmi/config.toml"),
    )?)
}

fn health_prerequisite(code: &'static str) -> Value {
    json!({
        "components":health::unknown_components(),
        "healthy":false,"attention_required":true,"issues":[code],"warnings":[],
        "readiness":"prerequisites_missing","evidence":"local_only",
        "assessment_scope":{"evidence":"local_only","state_filesystem":"not_assessed"},
        "operational":{"status":"unknown","issues":[code]},
        "risk":health::unknown_risk(),
        "initialized":null,"paused":null,"mutations":false,
        "work":health::unknown_work(code),"intervention":health::unknown_intervention(code)
    })
}

fn doctor_prerequisite(code: &'static str, repair: bool) -> Value {
    let mut report = health_prerequisite(code);
    report["repair_requested"] = json!(repair);
    report["repair_outcome"] = json!(if repair { "failed" } else { "not_requested" });
    report["repairs"] = json!({"eligible":[],"ineligible":[],"applied":[],"skipped":[],
        "failure":if repair {Some(code)} else {None},"restoration":{"manager_action":"none","runtime":"unchanged"}});
    report
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
    let mut value = json!({"commands":[
        {"name":"identity create","network_reads":"only with --confirm","network_writes":"only with --confirm; at most one registration POST per durable attempt","model_calls":false,"local_writes":"only with --confirm","confirmation_flag":"--confirm","purpose":"without --confirm: nonmutating plan; explicit bounded hosted identity creation; never starts, initializes or resumes participation"},
        {"name":"identity status","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"local sanitized registration evidence and safe next actions; never retries registration"},
        {"name":"identity resume","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":"only with --confirm","confirmation_flag":"--confirm","purpose":"nonmutating plan or explicit local-only publication from retained successful registration evidence; never repeats proof work or registration"},
        {"name":"init","network_reads":true,"network_writes":false,"local_writes":"unless --dry-run","purpose":"existing identity only; --account and --api-key-file, --key-stdin or --key-prompt; never registers or resumes"},
        {"name":"credentials rotate","network_reads":true,"network_writes":false,"local_writes":"credential only unless --dry-run","purpose":"requires initialized, paused, stopped account; verifies replacement identity; file/stdin/hidden prompt"},
        {"name":"install","network_reads":false,"network_writes":false,"local_writes":"unless --dry-run","purpose":"--binary local-path --sha256 trusted-digest; fresh install selects stopped; --stage-only only publishes; --migration-only permits supported older journal formats to current, disables boot activation, stays stopped and never converts state"},
        {"name":"update","network_reads":"latest stable metadata/assets unless explicit local source","network_writes":false,"model_calls":false,"local_writes":"unless --check or --dry-run","confirmation_flag":"--repair for guarded recovery; --migrate for stopped migration maintenance","private_output":"canonical preview only for explicitly requested migration preparation","purpose":"ordinary compatible update preserves configuration, guidance, credentials, pause/generation and runtime intent, then doctor; --migrate disables boot activation, stops and may pause, prepares private conversion approval or completes exact marker-only conversion, never resumes participation; --expected-token requires --release; --proposal FILE|- is private JSON, never argv JSON; --migration-only is stopped bootstrap without conversion"},
        {"name":"service","network_reads":false,"network_writes":false,"local_writes":"unless status or --dry-run","purpose":"status/start/stop/restart/enable/disable; does not resume participation"},
        {"name":"run","network_reads":true,"model_calls":"active capabilities only","network_writes":"active capabilities and resumed state only","local_writes":true},
        {"name":"status","network_reads":false,"network_writes":false,"purpose":"local operational state, current blockers and separate retained risk; success means snapshot read, not healthy"},
        {"name":"reads","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"sanitized read progress, failure categories and retry deadlines"},
        {"name":"health","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"local operational health for core and each lane; retained risk alone does not fail health; unhealthy exits nonzero"},
        {"name":"doctor","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":"only with --repair","confirmation_flag":"--repair","purpose":"local unattended/intervention diagnosis; --repair orchestrates existing guarded refusal recovery, preserving runtime intent; a restored runtime may resume its configured network/model work"},
        {"name":"config init","network_writes":false,"local_writes":true},
        {"name":"config show","network_writes":false,"local_writes":false},
        {"name":"config check","network_writes":false,"local_writes":false},
        {"name":"config state-path","network_writes":false,"local_writes":false,"purpose":"plain absolute state path without opening journal"},
        {"name":"config schema","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"setting types, defaults and immutable boundaries; no config required"},
        {"name":"config apply","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":"unless --dry-run","purpose":"nested JSON merge patch on stdin; --expected-revision from config show.file_revision"},
        {"name":"config migrate preview","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"private_output":true,"purpose":"JSON proposal on stdin; explicit per-lane caps/candidate for legacy sources, or {} for unchanged current-shape config with format-3 journal; requires stopped durable global pause; snapshot token binds target_journal_format","target_journal_format":agmi::journal::CURRENT_JOURNAL_FORMAT},
        {"name":"config migrate apply","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":true,"private_output":true,"purpose":"preview request JSON on stdin; --expected-token and, when required, matching --accept-risk-change token; converts only the token-bound target while stopped and remains paused"},
        {"name":"config migrate resume","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":true,"purpose":"--state-dir and --expected-token; finishes only the exact sealed target; recognized historical target3 returns further_migration_required=true and requires separate 3-to-current preview/apply; never resumes participation or retargets evidence"},
        {"name":"config migrate status","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"--state-dir; recovery_supported, recovery_prerequisite and preserved history without loading conflicting configuration"},
        {"name":"config migrate export","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"private_output":true,"purpose":"--state-dir and --expected-token; privately export sealed inputs for explicit conflict recovery"},
        {"name":"guidance show","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"private_output":true,"purpose":"--kind answer|judge --layer core|user (default user); private text and revision tokens"},
        {"name":"guidance set","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":"unless --dry-run","private_output":true,"purpose":"UTF-8 stdin; --kind, --layer core|user, --expected-config-revision and --expected-revision; missing means create-only"},
        {"name":"build-info","network_writes":false,"local_writes":false,"purpose":"compiled release identity; --manifest emits installer manifest verbatim"},
        {"name":"pause","network_writes":false,"local_writes":true},
        {"name":"resume","network_writes":false,"local_writes":true,"purpose":"authorize configured capabilities"},
        {"name":"lane show","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"<lane>; read desired.control_token, journal closure, sourced admission observation and dispatch uncertainty; control evidence, not health certification; use status or health for operational readiness"},
        {"name":"lane pause","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":true,"purpose":"<lane> --expected-control <control-token> [--wait-seconds 30]; commit local admission fence only; no cancellation, settlement or uncertainty erasure"},
        {"name":"lane resume","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":true,"purpose":"<lane> --expected-control <control-token> [--wait-seconds 30]; remove only lane pause override; no retry authority or proof of open admission"},
        {"name":"recover-model","network_writes":false,"local_writes":true,"purpose":"abandon local model preparation; requires stopped writer; retry policy and recorded execution exposure remain binding"},
        {"name":"recover inspect","network_reads":false,"network_writes":false,"local_writes":false,"purpose":"private captured operation and evidence; may contain payload/model text"},
        {"name":"recover adopt","network_reads":false,"network_writes":false,"local_writes":true,"purpose":"stopped-writer anchoring of compatible intact state; legacy schema conversion uses config migrate"},
        {"name":"recover resolve","network_reads":true,"network_writes":false,"local_writes":true,"purpose":"verify already-bound terminal evidence; --operation ID --refusal --dry-run is local-only and nonmutating; --refusal --apply TOKEN retires the reviewed refusal while stopped without network calls or replay"},
        {"name":"recover authorize","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":true,"purpose":"stopped-writer one-dispatch manual participation grant; --epoch N --kind answer|judge|mine"},
        {"name":"recover grants","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"paginated grant history; --limit N --before ID"},
        {"name":"recover revoke","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":true,"purpose":"stopped-writer revoke --grant ID without erasing grant history"},
        {"name":"operations list","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"sanitized paginated operation IDs, state, epoch, timing and linkage; --kind --state --before --limit"},
        {"name":"logs","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"sanitized local events; --follow streams retained tail then new IDs, stopping on retention gaps or journal replacement"},
        {"name":"completions","network_reads":false,"network_writes":false,"model_calls":false,"local_writes":false,"purpose":"print Bash, Zsh or Fish completions from command definitions; never installs shell files"},
        {"name":"agents","network_reads":false,"network_writes":false,"local_writes":false,"model_calls":false,"purpose":"independent desired answer/judge harness, model and guidance references; mine has no model route; not effective or native-reported evidence"},
        {"name":"commands","network_writes":false,"local_writes":false}
    ],"capabilities":LaneId::ALL,"lane_descriptors":agmi::capability::DESCRIPTORS,"modes":["active","read_only","off"],
        "participation_modes":["strict","participation_first","manual"],
        "lane_control":{"token_source":"lane show <lane>: desired.control_token","expected_flag":"--expected-control","wait_seconds":{"default":30,"minimum":1,"maximum":300,"scope":"acquisition_not_stalled_os_io"},"fence_scope":"local_admission","resume_proves_open":false,"config_save_is_fence":false},
        "fairness":{"policy":"served_in_round","eligibility_before_preference":true,"successful_opportunity_bound":2 * LaneId::COUNT - 1,"bound_scope":"continuously eligible lane; successful effect opportunities, not wall-clock time"},
        "limits":["Lane pause acknowledges a local admission fence; already-started native work and remote jobs may continue. Unsettled dispatch intent is reported, not repaired.","A timeout does not prove a submission failed.","Journal not_closed means only that pause controls do not close admission. Runtime observations may be stale or unknown; resume never fabricates open admission.","Hosted registration returns its API key once. Remote creation followed by a crash before durable private response capture can permanently lose the key; uncertain attempts are never automatically resubmitted."],
        "output_contract":{"json_schema":SCHEMA,"next_actions":"typed_actions_with_argv_not_shell",
            "raw_exception":"build-info --manifest is raw manifest text even with --json",
            "logs_follow":"with --json, one log_event envelope per event; retention gaps and journal replacement fail explicitly",
            "completions":"raw shell script without --json; normal envelope containing shell and script with --json",
            "state_path":"config state-path is plain text only without --json"}});
    for command in value["commands"]
        .as_array_mut()
        .expect("discovery commands")
    {
        command["authorization_required"] =
            json!(command["local_writes"] == true || command["local_writes"].is_string());
    }
    value
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
    let path = match config_path(cli) {
        Ok(path) => path,
        Err(_) if matches!(cli.command, Command::Health { .. }) => {
            return Ok(("health", health_prerequisite("config_location_unavailable")));
        }
        Err(_) if matches!(cli.command, Command::Doctor { .. }) => {
            let Command::Doctor { repair, .. } = cli.command else {
                unreachable!()
            };
            return Ok((
                "doctor",
                doctor_prerequisite("config_location_unavailable", repair),
            ));
        }
        Err(_) => {
            return Err(cli_error::BoundaryError(
                "config_location_unavailable",
                "Cannot locate configuration; select its path explicitly with --config.",
            )
            .into());
        }
    };
    match &cli.command {
        Command::Identity { command } => {
            return match command {
                IdentityCommand::Create {
                    label,
                    chain,
                    base_url,
                    network_config,
                    invited_by,
                    max_pow_bits,
                    max_pow_hashes,
                    pow_seconds,
                    http_seconds,
                    expected_pow_algo,
                    confirm,
                    retry_rejected,
                } => {
                    let network = network_options(
                        network_config.as_deref(),
                        chain.as_deref(),
                        base_url.as_deref(),
                    ).map_err(|_| cli_error::BoundaryError(
                        "registration_configuration_invalid",
                        "Invalid network profile, origin or API route configuration; no registration was attempted.",
                    ))?;
                    Ok((
                        "identity_create",
                        registration::create(
                            &path,
                            registration::CreateOptions {
                                label: label.clone(),
                                chain: network.chain,
                                base_url: network.base_url,
                                api: network.api,
                                trusted_origins: network.trusted_origins,
                                invited_by: invited_by.clone(),
                                max_pow_bits: *max_pow_bits,
                                max_pow_hashes: *max_pow_hashes,
                                pow_seconds: *pow_seconds,
                                http_seconds: *http_seconds,
                                expected_pow_algo: expected_pow_algo.clone(),
                                retry_rejected: *retry_rejected,
                            },
                            *confirm,
                        )
                        .await?,
                    ))
                }
                IdentityCommand::Status => Ok(("identity_status", registration::status(&path)?)),
                IdentityCommand::Resume { confirm } => {
                    Ok(("identity_resume", registration::resume(&path, *confirm)?))
                }
            };
        }
        Command::Init {
            account,
            chain,
            base_url,
            network_config,
            api_key_file,
            key_stdin,
            state_dir,
            dry_run,
            ..
        } => {
            let network = network_options(
                network_config.as_deref(),
                chain.as_deref(),
                base_url.as_deref(),
            )?;
            let bytes = lifecycle::credential_input(api_key_file.as_deref(), *key_stdin)?;
            return Ok((
                "init",
                lifecycle::init(
                    &path,
                    lifecycle::InitOptions {
                        account,
                        network,
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
            stage_only,
            migration_only,
            dry_run,
        } => {
            anyhow::ensure!(
                sha256.len() == 64
                    && sha256
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                cli_error::BoundaryError(
                    "invalid_release_digest",
                    "Expected SHA256 must be 64 lowercase hex digits; no installer was started."
                )
            );
            let binary = std::path::absolute(binary).context("cannot resolve local binary path")?;
            anyhow::ensure!(
                cli.config.is_none(),
                cli_error::BoundaryError(
                    "service_config_unsupported",
                    "Installer uses only ~/.config/agmi/config.toml; --config is unsupported. No installer was started."
                )
            );
            let mut arguments = vec![
                if *stage_only { "stage" } else { "install" }.into(),
                binary.to_string_lossy().into_owned(),
                "--sha256".into(),
                sha256.clone(),
            ];
            if *migration_only {
                arguments.push("--migration-only".into());
            }
            return Ok(("install", lifecycle::installer(&arguments, *dry_run)?));
        }
        Command::Update {
            release,
            binary,
            sha256,
            expected_release,
            check,
            repair,
            stopped,
            migration_only,
            migrate,
            proposal,
            expected_token,
            accept_risk_change,
            dry_run,
        } => {
            anyhow::ensure!(
                cli.config.is_none(),
                cli_error::BoundaryError(
                    "service_config_unsupported",
                    "Managed updates use only ~/.config/agmi/config.toml; --config is unsupported. No update was started."
                )
            );
            anyhow::ensure!(
                accept_risk_change.is_none()
                    || (expected_token.is_some() && accept_risk_change == expected_token),
                cli_error::BoundaryError(
                    "update_invalid_arguments",
                    "Risk approval must match the exact expected migration token. No update was started."
                )
            );
            let proposal = proposal.as_deref().map(update_proposal).transpose()?;
            return Ok((
                "update",
                update::run(
                    &path,
                    update::Options {
                        release: release.as_deref(),
                        binary: binary.as_deref(),
                        sha256: sha256.as_deref(),
                        expected_release: expected_release.as_deref(),
                        check: *check,
                        repair: *repair,
                        stopped: *stopped,
                        migration_only: *migration_only,
                        migrate: *migrate,
                        proposal: proposal.as_ref(),
                        expected_token: expected_token.as_deref(),
                        accept_risk_change: accept_risk_change.as_deref(),
                        dry_run: *dry_run,
                    },
                )
                .await?,
            ));
        }
        Command::Service { action, dry_run } => {
            anyhow::ensure!(
                cli.config.is_none(),
                cli_error::BoundaryError(
                    "service_config_unsupported",
                    "Service uses only ~/.config/agmi/config.toml; --config is unsupported. No installer was started."
                )
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
        Command::Config {
            command: ConfigCommand::Migrate { command },
        } => {
            use agmi::store::migration;
            return match command {
                MigrationCommand::Preview => {
                    let input = serde_json::from_slice(&administration_input()?)
                        .context("invalid migration proposal JSON")?;
                    Ok(("config_migrate_preview", migration::preview(&path, &input)?))
                }
                MigrationCommand::Apply {
                    expected_token,
                    accept_risk_change,
                } => {
                    let input = serde_json::from_slice(&administration_input()?)
                        .context("invalid migration proposal JSON")?;
                    Ok((
                        "config_migrate_apply",
                        migration::apply(
                            &path,
                            &input,
                            expected_token,
                            accept_risk_change.as_deref(),
                        )?,
                    ))
                }
                MigrationCommand::Resume {
                    state_dir,
                    expected_token,
                } => Ok((
                    "config_migrate_resume",
                    migration::resume(&path, state_dir, expected_token)?,
                )),
                MigrationCommand::Status { state_dir } => {
                    Ok(("config_migrate_status", migration::status(state_dir)?))
                }
                MigrationCommand::Export {
                    state_dir,
                    expected_token,
                } => {
                    let mut data = migration::export(state_dir, expected_token)?;
                    data["private"] = json!(true);
                    Ok(("config_migrate_export", data))
                }
            };
        }
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
    let lane_deadline = match &cli.command {
        Command::Lane { command } => {
            let seconds = match command {
                LaneCommand::Show { .. } => 30,
                LaneCommand::Pause { wait_seconds, .. }
                | LaneCommand::Resume { wait_seconds, .. } => *wait_seconds,
            };
            Some(std::time::Instant::now() + std::time::Duration::from_secs(seconds))
        }
        _ => None,
    };
    let _configuration_guard = match &cli.command {
        Command::Lane { .. } => Some(admin::lock_config_directory_until(
            &path,
            lane_deadline.expect("lane acquisition deadline"),
        )?),
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
        Config::load(&path)
    } else {
        Config::load_metadata(&path)
    };
    let config = match config {
        Ok(config) => config,
        Err(error) => {
            let code = if error
                .downcast_ref::<agmi::config::ConfigDiagnostic>()
                .is_some_and(agmi::config::ConfigDiagnostic::is_missing)
            {
                "config_missing"
            } else {
                "config_invalid"
            };
            if matches!(cli.command, Command::Health { .. }) {
                return Ok(("health", health_prerequisite(code)));
            }
            if let Command::Doctor { repair, .. } = cli.command {
                return Ok(("doctor", doctor_prerequisite(code, repair)));
            }
            return Err(error);
        }
    };
    match &cli.command {
        Command::Lane { command } => match command {
            LaneCommand::Show { lane } => Ok((
                "lane_show",
                agmi::store::lane_control_status(&config, work_kind(lane))?,
            )),
            LaneCommand::Pause {
                lane,
                expected_control,
                ..
            }
            | LaneCommand::Resume {
                lane,
                expected_control,
                ..
            } => {
                let paused = matches!(command, LaneCommand::Pause { .. });
                let deadline = lane_deadline.expect("lane acquisition deadline");
                Ok((
                    if paused { "lane_pause" } else { "lane_resume" },
                    agmi::store::set_lane_paused(
                        &config,
                        work_kind(lane),
                        paused,
                        expected_control,
                        deadline,
                    )?,
                ))
            }
        },
        Command::Config {
            command: ConfigCommand::StatePath,
        } => Ok(("config_state_path", json!({"path":config.state_dir}))),
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
                refusal,
                dry_run: _,
                apply,
            } => Ok((
                "recovery_resolve",
                if *refusal {
                    agmi::store::recovery_refusal(&path, *operation, apply.as_deref())?
                } else {
                    runtime::recovery_resolve(&path, *operation, job_id.as_deref(), txid.as_deref())
                        .await?
                },
            )),
        },
        Command::Status { .. } => Ok(("status", runtime::status(&config)?)),
        Command::Doctor { repair, .. } => Ok(("doctor", doctor::check(&path, *repair))),
        Command::Reads => Ok(("reads", runtime::reads(&config)?)),
        Command::Health {
            stale_seconds,
            work_seconds,
            answer_grace_seconds,
            expect_participation,
            min_free_mib,
            ..
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
                "network_requests_reset":false,"model_exposure_reset":false,
                "note":"Abandonment does not prove inference stopped or grant another attempt. Eligible regeneration may incur another model charge."}),
        )),
        Command::Logs {
            limit,
            follow: false,
        } => Ok(("logs", runtime::events(&config, usize::from(*limit))?)),
        Command::Agents => Ok((
            "agents",
            json!({"routes":LaneId::ALL.into_iter().filter_map(|lane| config.model(lane).map(|model| (lane.as_str(), model))).collect::<std::collections::BTreeMap<_, _>>(),
                "configuration_state":"desired_saved","runtime_application":"unverified","fence_acknowledged":false,
                "revision":config.optional_revision()?,"verified":false,
                "lane_descriptors":agmi::capability::DESCRIPTORS,
                "note":"Desired routes only; inspect status for effective loaded routes and operations for sourced native reports. Mine has no model or guidance route. No harness, authentication secret or guidance content is inspected."}),
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
        | Command::Identity { .. }
        | Command::Credentials { .. }
        | Command::Install { .. }
        | Command::Update { .. }
        | Command::Service { .. }
        | Command::Run { .. }
        | Command::Commands
        | Command::Completions { .. }
        | Command::Logs { follow: true, .. }
        | Command::Guidance { .. }
        | Command::Config {
            command:
                ConfigCommand::Schema
                | ConfigCommand::Show
                | ConfigCommand::Apply { .. }
                | ConfigCommand::Migrate { .. },
        }
        | Command::Config {
            command: ConfigCommand::Init,
        } => unreachable!(),
    }
}

// Reduce only at the presentation boundary; readiness and repair decisions use
// the complete internal evidence above.
fn compact_diagnostics(data: &mut Value) {
    if let Some(object) = data.as_object_mut() {
        for field in [
            "pending_work",
            "captured_work",
            "reads",
            "request_restrictions",
        ] {
            if let Some(value) = object.remove(field) {
                object.insert(
                    format!("{field}_count"),
                    json!(value.as_array().map(Vec::len)),
                );
            }
        }
    }
    fn reduce(value: &mut Value) {
        match value {
            Value::Object(object) => {
                for field in ["blocker_ids", "historical_unknown_answers"] {
                    object.remove(field);
                }
                // Component evidence duplicates canonical top-level work, routing
                // and observations; its classification and reasons remain visible.
                if object.contains_key("status")
                    && object.get("evidence").is_some_and(Value::is_object)
                {
                    object.remove("evidence");
                }
                for child in object.values_mut() {
                    reduce(child);
                }
            }
            Value::Array(values) => {
                for value in values {
                    reduce(value);
                }
            }
            _ => {}
        }
    }
    if let Some(api) = data
        .pointer_mut("/components/api")
        .and_then(Value::as_object_mut)
        && let Some(Value::Array(mut resources)) = api.remove("resources")
    {
        let mut background = json!({"count":0,"degraded":0,"unknown":0});
        resources.retain(|resource| {
            if resource["dependency"] != "background_remote_work" {
                return true;
            }
            background["count"] = json!(background["count"].as_u64().unwrap() + 1);
            if let Some(state @ ("degraded" | "unknown")) = resource["health"]["state"].as_str() {
                background[state] = json!(background[state].as_u64().unwrap() + 1);
            }
            false
        });
        api.insert("resources".into(), json!(resources));
        api.insert("background_resources".into(), background);
    }
    reduce(data);
}

#[tokio::main]
async fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    let json_requested = arguments.iter().any(|argument| argument == "--json");
    let parser_config = arguments
        .windows(2)
        .find(|pair| pair[0] == "--config" && !pair[1].to_string_lossy().starts_with('-'))
        .map(|pair| PathBuf::from(&pair[1]))
        .or_else(|| {
            arguments.iter().find_map(|argument| {
                argument
                    .to_str()
                    .and_then(|value| value.strip_prefix("--config="))
                    .map(PathBuf::from)
            })
        });
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            error.exit()
        }
        Err(error) => {
            let error = cli_error::parser(&error, parser_config.as_deref());
            if json_requested {
                eprintln!(
                    "{}",
                    json!({"schema":SCHEMA,"ok":false,"type":"error","error":error})
                );
            } else {
                cli_error::human_error(&error);
            }
            std::process::exit(2);
        }
    };
    if matches!(cli.command, Command::BuildInfo { manifest: true }) {
        print!("{}", include_str!(env!("AGMI_BUILD_MANIFEST_PATH")));
        return;
    }
    if let Command::Completions { shell } = &cli.command {
        let generator = match shell.as_str() {
            "bash" => clap_complete::Shell::Bash,
            "zsh" => clap_complete::Shell::Zsh,
            "fish" => clap_complete::Shell::Fish,
            _ => unreachable!("validated shell"),
        };
        let mut script = Vec::new();
        clap_complete::generate(generator, &mut Cli::command(), "agmi", &mut script);
        let result = if cli.json {
            writeln!(
                std::io::stdout().lock(),
                "{}",
                json!({"schema":SCHEMA,"ok":true,
                "type":"completions","data":{"shell":shell,"script":String::from_utf8(script).expect("completion UTF-8")}})
            )
        } else {
            std::io::stdout().lock().write_all(&script)
        };
        if let Err(error) = result
            && error.kind() != std::io::ErrorKind::BrokenPipe
        {
            eprintln!("agmi: cannot write completion output");
            std::process::exit(1);
        }
        return;
    }
    let action_config = config_path(&cli).ok();
    if let Command::Logs {
        limit,
        follow: true,
    } = cli.command
    {
        let result = async {
            let path = config_path(&cli)?;
            let config = Config::load_metadata(&path)?;
            logs::follow(&config, usize::from(limit), cli.json).await
        }
        .await;
        if let Err(error) = result {
            let diagnostic = cli_error::execution(&error, action_config.as_deref());
            if cli.json {
                eprintln!(
                    "{}",
                    json!({"schema":SCHEMA,"ok":false,"type":"error","error":diagnostic})
                );
            } else {
                eprintln!("agmi: {} [{}]", diagnostic["message"], diagnostic["code"]);
            }
            std::process::exit(1);
        }
        return;
    }
    match execute(&cli).await {
        Ok((kind, mut data)) => {
            if kind == "config_state_path" && !cli.json {
                println!("{}", data["path"].as_str().expect("state path is UTF-8"));
                return;
            }
            if kind == "init" {
                cli_error::onboarding(&mut data, action_config.as_deref());
            }
            if matches!(kind, "health" | "status" | "doctor") {
                cli_error::diagnostics(&mut data, action_config.as_deref());
            }
            if kind == "update" && data["readiness"]["intervention"].is_object() {
                cli_error::diagnostics(&mut data["readiness"], action_config.as_deref());
            }
            if kind == "update" {
                update_actions(&mut data);
            }
            if matches!(kind, "install" | "service") {
                data["next_actions"] =
                    json!([cli_error::action(None, &["service", "status"], false)]);
            }
            if let Command::Identity {
                command:
                    IdentityCommand::Create { confirm, .. } | IdentityCommand::Resume { confirm },
            } = &cli.command
            {
                data["authorization"] = json!({
                    "required":true,
                    "source":if *confirm { "explicit_confirmation" } else { "not_confirmed" },
                    "confirmed":confirm,
                    "dry_run":!confirm
                });
            }
            if matches!(
                cli.command,
                Command::Pause
                    | Command::Resume
                    | Command::Doctor { repair: true, .. }
                    | Command::Run { .. }
                    | Command::Init { .. }
                    | Command::Install { .. }
                    | Command::Update { check: false, .. }
                    | Command::Credentials { .. }
                    | Command::RecoverModel
                    | Command::Recover {
                        command: RecoveryCommand::Adopt
                            | RecoveryCommand::Authorize { .. }
                            | RecoveryCommand::Revoke { .. }
                            | RecoveryCommand::Resolve { .. }
                    }
                    | Command::Config {
                        command: ConfigCommand::Init
                            | ConfigCommand::Apply { .. }
                            | ConfigCommand::Migrate {
                                command: MigrationCommand::Apply { .. }
                                    | MigrationCommand::Resume { .. },
                            }
                    }
                    | Command::Guidance {
                        command: GuidanceCommand::Set { .. }
                    }
            ) || matches!(&cli.command, Command::Service { action, .. } if action != "status")
            {
                data["authorization"] = json!({"required":true,"source":"explicit_command",
                    "dry_run":data["dry_run"].as_bool().or_else(|| data["update"]["dry_run"].as_bool()).or_else(|| data["plan"]["dry_run"].as_bool()).unwrap_or(false)});
            }
            let ok = match kind {
                "health" => data["healthy"].as_bool() == Some(true),
                "doctor" => {
                    data["intervention"]["unattended"] == true
                        && data["repairs"]["failure"].is_null()
                }
                "update" => data["success"] == true,
                _ => true,
            };
            let verbose = matches!(
                cli.command,
                Command::Status { verbose: true }
                    | Command::Health { verbose: true, .. }
                    | Command::Doctor { verbose: true, .. }
            );
            if matches!(kind, "status" | "health" | "doctor") && !verbose {
                compact_diagnostics(&mut data);
            }
            let value = json!({"schema":SCHEMA,"ok":ok,"type":kind,"data":data});
            if cli.json {
                println!("{value}");
            } else {
                cli_error::human(kind, &value["data"]);
                if kind == "update" {
                    update_consequences(&value["data"]);
                }
                if verbose {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&value["data"]).expect("diagnostic JSON")
                    );
                }
            }
            if !ok {
                std::process::exit(1);
            }
        }
        Err(error) => {
            let error = cli_error::execution(&error, action_config.as_deref());
            if cli.json {
                eprintln!(
                    "{}",
                    json!({"schema":SCHEMA,"ok":false,"type":"error","error":error})
                );
            } else {
                cli_error::human_error(&error);
            }
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_outcomes_keep_actionable_steps_without_doctor_or_automatic_resume() {
        for (status, phase) in [
            ("migration_required", "required"),
            ("migration_prepared", "prepared"),
            ("migration_complete_stopped", "complete"),
            ("recovery_required", "recovery_required"),
            ("failed", "complete"),
            ("failed", "failed"),
        ] {
            let mut report = json!({"update":{"status":status},"migration":{"phase":phase}});
            update_actions(&mut report);
            let actions = report["next_actions"].to_string();
            assert!(!actions.contains("\"doctor\""));
            assert!(!actions.contains("\"resume\""));
            assert!(!actions.contains("\"start\""));
            let specific = report["next_actions"].clone();
            update_actions(&mut report);
            assert_eq!(report["next_actions"], specific);
        }
        let mut ordinary =
            json!({"update":{"status":"updated"},"migration":{"phase":"not_required"}});
        update_actions(&mut ordinary);
        assert!(ordinary["next_actions"].to_string().contains("\"doctor\""));
        for status in ["migration_prepared", "recovery_required"] {
            let release = format!("r-{}", "a".repeat(64));
            let token = format!("agmi.atomic-migration.v1:{}", "b".repeat(64));
            let mut report = json!({"update":{"status":status},
                "migration":{"phase":if status == "migration_prepared" {"prepared"} else {"recovery_required"},
                    "release_id":release,"token":token,"risk_change_required":true,
                    "pending":status == "recovery_required"}});
            update_actions(&mut report);
            let action = report["next_actions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|action| {
                    action["kind"] == "command" && action["authorization_required"] == true
                })
                .unwrap();
            let argv = action["argv"].as_array().unwrap();
            assert!(
                argv.windows(2)
                    .any(|pair| pair == [json!("--release"), json!(release)])
            );
            assert!(
                argv.windows(2)
                    .any(|pair| pair == [json!("--expected-token"), json!(token)])
            );
            assert_eq!(
                argv.contains(&json!("--proposal")),
                status == "migration_prepared"
            );
            assert!(!argv.contains(&json!("--accept-risk-change")));
        }
    }

    #[test]
    fn completed_historical_recovery_never_repeats_old_approval_or_offers_activation() {
        let release = format!("r-{}", "a".repeat(64));
        let token = format!("agmi.atomic-migration.v1:{}", "b".repeat(64));
        for adoption in [false, true] {
            let mut report = json!({"update":{"status":"recovery_required"},
                "migration":{"phase":"complete","pending":false,"release_id":release,"token":token,
                    "target_journal_format":if adoption {4} else {3},
                    "further_migration_required":!adoption,
                    "recovery_prerequisite":if adoption {Some("authority_adoption")} else {None}}});
            update_actions(&mut report);
            assert!(!migration_can_offer_activation(&report));
            let actions = report["next_actions"].as_array().unwrap();
            assert!(
                !actions
                    .iter()
                    .filter_map(|action| action["argv"].as_array())
                    .any(|argv| argv.contains(&json!("--expected-token")))
            );
            if adoption {
                assert!(
                    actions
                        .iter()
                        .any(|action| action["argv"]
                            == json!(["agmi", "recover", "adopt", "--help"]))
                );
            } else {
                assert!(actions.iter().any(|action| action["argv"]
                    == json!(["agmi", "update", "--release", release, "--migrate"])));
            }
        }
        let mut completed = json!({"migration":{"phase":"complete","pending":false,
            "target_journal_format":agmi::journal::CURRENT_JOURNAL_FORMAT,
            "further_migration_required":false,"recovery_prerequisite":null}});
        assert!(migration_can_offer_activation(&completed));
        completed["migration"]
            .as_object_mut()
            .unwrap()
            .remove("recovery_prerequisite");
        assert!(!migration_can_offer_activation(&completed));
    }

    #[test]
    fn pinned_migration_preview_and_dry_run_arguments_parse_without_unstated_input() {
        for arguments in [
            vec!["agmi", "update", "--migrate"],
            vec!["agmi", "update", "--migrate", "--check"],
            vec![
                "agmi",
                "update",
                "--migrate",
                "--dry-run",
                "--proposal",
                "-",
            ],
            vec![
                "agmi",
                "update",
                "--release",
                "r-pin",
                "--migrate",
                "--expected-token",
                "token",
                "--accept-risk-change",
                "token",
            ],
            vec![
                "agmi",
                "update",
                "--release",
                "r-pin",
                "--migrate",
                "--dry-run",
                "--expected-token",
                "token",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
    }

    #[test]
    fn compact_diagnostics_preserves_essentials_without_mutating_internal_evidence() {
        let full = json!({
            "last_reported_build":{"version":"fixture"},
            "writer_authority":{"status":"valid"},
            "effective_runtime":{"policy":{"capabilities":{"answer":{"preparation":{"max_attempts_per_work":"unbounded"}}}}},
            "observations":{"answer":{"epoch":7}},
            "work":{"answer":{"phase":"observing","admission":{"allowed":true,"own_count":2000,"own_limit":"unbounded","blocker_ids":[1,2],"historical_unknown_answers":[1,2]}}},
            "intervention":{"unattended":true},
            "pending_work":[{"model_attempt":{"producer":{"requested":{}}}}],
            "captured_work":[],
            "reads":[{},{}]
        });
        let mut compact = full.clone();
        compact_diagnostics(&mut compact);
        for field in [
            "last_reported_build",
            "writer_authority",
            "effective_runtime",
            "observations",
            "intervention",
        ] {
            assert_eq!(compact[field], full[field]);
        }
        assert_eq!(compact["pending_work_count"], 1);
        assert_eq!(compact["reads_count"], 2);
        assert!(compact.get("pending_work").is_none());
        assert!(
            compact["work"]["answer"]["admission"]
                .get("blocker_ids")
                .is_none()
        );
        assert_eq!(compact["work"]["answer"]["admission"]["own_count"], 2000);
        assert!(full["pending_work"][0]["model_attempt"].is_object());
        for command in ["status", "health", "doctor"] {
            assert!(Cli::try_parse_from(["agmi", command, "--verbose"]).is_ok());
        }
    }

    #[test]
    fn refusal_resolution_requires_explicit_preview_approval_and_excludes_bound_recovery() {
        for arguments in [
            vec![
                "agmi",
                "recover",
                "resolve",
                "--operation",
                "1",
                "--refusal",
            ],
            vec![
                "agmi",
                "recover",
                "resolve",
                "--operation",
                "1",
                "--refusal",
                "--dry-run",
            ],
            vec![
                "agmi",
                "recover",
                "resolve",
                "--operation",
                "1",
                "--refusal",
                "--apply",
                "token",
            ],
            vec![
                "agmi",
                "recover",
                "resolve",
                "--operation",
                "1",
                "--job-id",
                "bound",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
        for arguments in [
            vec![
                "agmi",
                "recover",
                "resolve",
                "--operation",
                "1",
                "--apply",
                "token",
            ],
            vec![
                "agmi",
                "recover",
                "resolve",
                "--operation",
                "1",
                "--dry-run",
            ],
            vec![
                "agmi",
                "recover",
                "resolve",
                "--operation",
                "1",
                "--refusal",
                "--dry-run",
                "--apply",
                "token",
            ],
            vec![
                "agmi",
                "recover",
                "resolve",
                "--operation",
                "1",
                "--refusal",
                "--job-id",
                "bound",
            ],
            vec![
                "agmi",
                "recover",
                "resolve",
                "--operation",
                "1",
                "--refusal",
                "--txid",
                "bound",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_err());
        }
    }
}
