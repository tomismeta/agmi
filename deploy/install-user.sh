#!/bin/sh
# Linux user-systemd release sets. State and native credentials are never copied.
set -eu
LC_ALL=C
export LC_ALL
umask 077

usage() {
    printf '%s\n' \
        'Usage: sh deploy/install-user.sh stage /absolute/path/to/agmi' \
        '       sh deploy/install-user.sh activate RELEASE_ID [--stopped]' \
        '       sh deploy/install-user.sh status' \
        'Stage validates a matching binary/unit set without stopping or starting anything.' \
        'Activate explicitly stops, switches current, daemon-reloads and restarts the runtime and health timer.' \
        '--stopped performs the cutover/reload without starting, for explicit stopped-writer migration.' \
        'Neither command initializes state, resumes participation, enables units, or rolls back a journal.' \
        'Config: ~/.config/agmi/config.toml; releases: ~/.local/share/agmi/releases.' \
        'A previous release may be activated only with the same journal schema.'
}
fail() { printf 'agmi release: %s\n' "$*" >&2; exit 1; }
case ${HOME-} in /*) ;; *) fail 'HOME must be an absolute per-user directory.' ;; esac
case ${1-} in
    --help|-h) usage; exit 0 ;;
    stage) [ "$#" -eq 2 ] || { usage >&2; exit 2; } ;;
    activate)
        if [ "$#" -ne 2 ] && { [ "$#" -ne 3 ] || [ "$3" != --stopped ]; }; then
            usage >&2
            exit 2
        fi ;;
    status) [ "$#" -eq 1 ] || { usage >&2; exit 2; } ;;
    *) usage >&2; exit 2 ;;
esac
[ "$(uname -s)" = Linux ] || fail 'Installation requires Linux user-systemd and GNU coreutils.'
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$HOME/.local/share/agmi/releases
bin_dir=$HOME/.local/bin
unit_dir=$HOME/.config/systemd/user
config=$HOME/.config/agmi/config.toml
reserve_kib=262144
margin_kib=4096
units='agmi.service agmi-health.service agmi-health.timer'

metadata() {
    key=$1
    file=$2
    found=0
    while IFS='=' read -r name value; do
        if [ "$name" = "$key" ]; then
            [ "$found" -eq 0 ] || fail "Duplicate manifest field: $key"
            printf '%s\n' "$value"
            found=1
        fi
    done < "$file"
    [ "$found" -eq 1 ] || fail "Missing manifest field: $key"
}
sha256() {
    sha256sum -- "$1" | { read -r digest rest; printf '%s\n' "$digest"; }
}
valid_id() {
    case $1 in r-*) suffix=${1#r-} ;; *) return 1 ;; esac
    [ "${#suffix}" -eq 64 ] || return 1
    case $suffix in *[!0-9a-f]*) return 1 ;; esac
}
release_checksums() {
    (CDPATH= cd -- "$1" && sha256sum agmi agmi.service agmi-health.service agmi-health.timer MANIFEST)
}
validate_release() (
    release=$1
    expected_id=$2
    valid_id "$expected_id" || fail 'Invalid release ID.'
    [ -d "$release" ] && [ ! -L "$release" ] || fail 'Release directory is missing or is a symlink.'
    for file in agmi agmi.service agmi-health.service agmi-health.timer MANIFEST SHA256SUMS; do
        [ -f "$release/$file" ] && [ ! -L "$release/$file" ] || fail "Missing or linked release artifact: $file"
    done
    [ -x "$release/agmi" ] || fail 'Release binary is not executable.'
    actual_checksums=$(release_checksums "$release")
    recorded_checksums=$(cat "$release/SHA256SUMS")
    [ "$actual_checksums" = "$recorded_checksums" ] || fail 'Release checksum verification failed.'
    [ "$(metadata release_id "$release/MANIFEST")" = "$expected_id" ] || fail 'Release ID does not match its manifest.'
    [ "$(metadata binary_sha256 "$release/MANIFEST")" = "${expected_id#r-}" ] || fail 'Release binary identity does not match its directory.'
    [ "$(sha256 "$release/agmi")" = "${expected_id#r-}" ] || fail 'Release binary checksum mismatch.'
    [ "$(metadata build_format "$release/MANIFEST")" = 1 ] || fail 'Unsupported build manifest format.'
    commit=$(metadata commit "$release/MANIFEST")
    [ "${#commit}" -eq 40 ] || fail 'Release requires a known build commit; build from its own Git checkout.'
    case $commit in *[!0-9a-f]*) fail 'Invalid build commit identity.' ;; esac
    case $(metadata source_dirty "$release/MANIFEST") in
        clean|dirty) ;;
        *) fail 'Release requires a known build-time source dirty marker.' ;;
    esac
    [ "$(metadata journal_schema "$release/MANIFEST")" = 2 ] || fail 'This installer requires journal schema 2.'
    [ "$(metadata stop_timeout "$release/MANIFEST")" = infinity ] || fail 'Incompatible shutdown policy.'
    embedded=$("$release/agmi" build-info --manifest) || fail 'Cannot read embedded binary identity.'
    expected=$(printf '%s\nrelease_id=%s\nbinary_sha256=%s\n' "$embedded" "$expected_id" "${expected_id#r-}")
    [ "$(cat "$release/MANIFEST")" = "$expected" ] || fail 'Manifest does not match the embedded build identity.'
)

status() {
    if [ -L "$root/current" ]; then
        installed=$(readlink "$root/current")
        printf 'installed_release=%s\n' "$installed"
        if valid_id "$installed" && [ -f "$root/$installed/MANIFEST" ]; then
            cat "$root/$installed/MANIFEST"
            printf 'installed_binary_sha256=%s\n' "$(sha256 "$root/$installed/agmi")"
        fi
    else
        printf '%s\n' 'installed_release=unversioned_or_absent'
    fi
    for unit in $units; do
        printf 'loaded_unit=%s\n' "$unit"
        systemctl --user show "$unit" --property=Description --property=LoadState \
            --property=ActiveState --property=SubState --property=MainPID \
            --property=InvocationID --property=ExecMainStartTimestamp --property=TimeoutStopUSec \
            || printf '%s\n' 'loaded_identity=unavailable'
    done
    pid=$(systemctl --user show agmi.service --property=MainPID --value 2>/dev/null) || pid=0
    case $pid in ''|0|*[!0-9]*) printf '%s\n' 'running_binary_sha256=none_or_unavailable' ;;
        *)
            if [ -r "/proc/$pid/exe" ]; then
                running=$(sha256 "/proc/$pid/exe") || running=unavailable
                printf 'running_pid=%s\nrunning_binary_sha256=%s\n' "$pid" "$running"
                if [ -L "$root/current" ] && [ "$running" = "${installed#r-}" ]; then
                    printf '%s\n' 'running_matches_installed=true'
                else
                    printf '%s\n' 'running_matches_installed=false'
                fi
            else
                printf '%s\n' 'running_binary_sha256=unavailable'
            fi ;;
    esac
    printf '%s\n' 'identity_evidence=checksums_and_build_labels_not_signed_source_provenance'
}
if [ "$1" = status ]; then status; exit 0; fi

for command in sha256sum systemctl systemd-analyze df du sync mktemp sed readlink install; do
    command -v "$command" >/dev/null 2>&1 || fail "Required Linux command is missing: $command"
done
stop_units() (
    failed=0
    for unit in agmi-health.timer agmi-health.service agmi.service; do
        load_state=$(systemctl --user show "$unit" --property=LoadState --value) || { failed=1; continue; }
        [ "$load_state" = not-found ] && continue
        systemctl --user stop "$unit" || failed=1
    done
    exit "$failed"
)
mkdir -p -- "$root" "$bin_dir" "$unit_dir"
[ ! -L "$root" ] || fail 'The releases directory must not be a symlink.'
lock=$root/.install-lock
mkdir -- "$lock" 2>/dev/null || fail "Another installer or an interrupted installation owns $lock; inspect its owner before removing that lock directory."
printf '%s\n' "$$" > "$lock/owner"
staging=
link_temp=
activation=0
cleanup() {
    result=$?
    trap - 0 HUP INT TERM
    if [ "$activation" -eq 1 ] && [ "$result" -ne 0 ]; then
        printf '%s\n' 'Activation failed: stopping agmi units; current is NOT reverted and the journal is NOT restored.' >&2
        stop_units || printf '%s\n' 'STOP FAILED: operator must stop the runtime before any repair or activation.' >&2
    fi
    if [ -n "$staging" ]; then rm -rf -- "$staging"; fi
    if [ -n "$link_temp" ]; then rm -f -- "$link_temp"; fi
    rm -f -- "$lock/owner"
    rmdir -- "$lock" || :
    exit "$result"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

existing_parent() {
    path=$1
    while [ ! -d "$path" ]; do
        [ "$path" != / ] || fail 'Cannot locate filesystem for state.'
        path=$(dirname -- "$path")
    done
    printf '%s\n' "$path"
}
free_kib() {
    df -Pk -- "$1" | {
        IFS= read -r header
        read -r filesystem blocks used available capacity mounted
        case $available in ''|*[!0-9]*) exit 1 ;; esac
        printf '%s\n' "$available"
    }
}
size_kib() {
    du -sk -- "$1" | { read -r size rest; printf '%s\n' "$size"; }
}
space_at() {
    path=$1
    required=$2
    label=$3
    available=$(free_kib "$path") || fail "Cannot measure free space for $label."
    printf 'space_%s_available_kib=%s required_kib=%s\n' "$label" "$available" "$required" >&2
    [ "$available" -ge "$required" ] || fail "Insufficient $label space; retain the journal/history and free unrelated capacity manually."
}
legacy_size() {
    total=0
    for file in "$bin_dir/agmi" "$unit_dir/agmi.service" "$unit_dir/agmi-health.service" "$unit_dir/agmi-health.timer"; do
        if [ -f "$file" ] && [ ! -L "$file" ]; then total=$((total + $(size_kib "$file"))); fi
    done
    printf '%s\n' "$total"
}
space_checks() {
    binary=$1
    incoming=$2
    state_dir=$("$binary" --config "$config" config state-path) || fail 'Cannot read configured state path (no state was opened).'
    case $state_dir in /*) ;; *) fail 'Configured state path must be absolute.' ;; esac
    state_parent=$(existing_parent "$state_dir")
    canonical_state=$(readlink -m -- "$state_dir")
    canonical_releases=$(readlink -f -- "$root")
    case $canonical_state in
        "$canonical_releases"|"$canonical_releases"/*) fail 'Participation state must remain outside the releases directory.' ;;
    esac
    retained=$(size_kib "$root")
    legacy=$(legacy_size)
    printf 'retained_release_kib=%s incoming_release_kib=%s legacy_backup_kib=%s journal_wal_reserve_kib=%s\n' \
        "$retained" "$incoming" "$legacy" "$reserve_kib" >&2
    # Existing retained releases already consume df space. A same-filesystem
    # staging rename does not require a second copy. Never prune to make room.
    space_at "$root" "$((incoming + legacy + reserve_kib + margin_kib))" releases
    space_at "$state_parent" "$((reserve_kib + margin_kib))" state
    space_at "$HOME" "$((reserve_kib + margin_kib))" binding
    space_at "$bin_dir" "$((reserve_kib + margin_kib))" cli
    space_at "$unit_dir" "$((reserve_kib + margin_kib))" units
}

if [ "$1" = stage ]; then
    binary=$2
    [ -f "$binary" ] && [ -x "$binary" ] && [ ! -L "$binary" ] || fail 'Supply a regular executable binary, not a symlink.'
    binary=$(readlink -f -- "$binary")
    binary_hash=$(sha256 "$binary")
    release_id=r-$binary_hash
    release=$root/$release_id
    if [ -e "$release" ]; then
        validate_release "$release" "$release_id"
        systemd-analyze --user verify "$release/agmi.service" "$release/agmi-health.service" "$release/agmi-health.timer"
        printf 'staged_release=%s\n' "$release_id"
        exit 0
    fi
    incoming=$(size_kib "$binary")
    for unit in $units; do
        [ -f "$source_dir/$unit" ] || fail "Missing unit template: $unit"
        incoming=$((incoming + $(size_kib "$source_dir/$unit")))
    done
    space_checks "$binary" "$incoming"
    staging=$(mktemp -d "$root/.stage.XXXXXX")
    install -m 0755 -- "$binary" "$staging/agmi"
    "$staging/agmi" build-info --manifest > "$staging/MANIFEST"
    [ "$(metadata build_format "$staging/MANIFEST")" = 1 ] || fail 'Unsupported binary build identity.'
    for unit in $units; do
        case $unit in
            agmi.service) key=unit_agmi_service_sha256 ;;
            agmi-health.service) key=unit_agmi_health_service_sha256 ;;
            agmi-health.timer) key=unit_agmi_health_timer_sha256 ;;
        esac
        [ "$(sha256 "$source_dir/$unit")" = "$(metadata "$key" "$staging/MANIFEST")" ] \
            || fail "Unit template does not match this binary's build: $unit"
        sed "s/@AGMI_RELEASE_ID@/$release_id/g" "$source_dir/$unit" > "$staging/$unit"
        chmod 0644 "$staging/$unit"
    done
    printf 'release_id=%s\nbinary_sha256=%s\n' "$release_id" "$binary_hash" >> "$staging/MANIFEST"
    release_checksums "$staging" > "$staging/SHA256SUMS"
    validate_release "$staging" "$release_id"
    sync -f "$staging"
    mv -T -- "$staging" "$release"
    staging=
    sync -f "$root"
    # ExecStart is release-pinned, so verification happens after the complete
    # directory is in its final location, but before it is current/activatable.
    systemd-analyze --user verify "$release/agmi.service" "$release/agmi-health.service" "$release/agmi-health.timer"
    printf 'staged_release=%s\n' "$release_id"
    printf '%s\n' 'No pointer, loaded unit, running process, state, credential or pause setting changed.'
    exit 0
fi

release_id=$2
valid_id "$release_id" || fail 'Invalid release ID.'
release=$root/$release_id
validate_release "$release" "$release_id"
space_checks "$release/agmi" 0
systemd-analyze --user verify "$release/agmi.service" "$release/agmi-health.service" "$release/agmi-health.timer"
if [ -L "$root/current" ]; then
    previous=$(readlink "$root/current")
    valid_id "$previous" || fail 'Current is not a versioned release pointer.'
    validate_release "$root/$previous" "$previous"
    [ "$(metadata journal_schema "$root/$previous/MANIFEST")" = "$(metadata journal_schema "$release/MANIFEST")" ] \
        || fail 'Journal schema changed; use an explicitly reviewed roll-forward migration, not binary rollback.'
    printf 'retained_previous_release=%s\n' "$previous"
elif [ -e "$root/current" ]; then
    fail 'Current exists but is not a release symlink.'
fi
for unit in $units; do
    [ ! -d "$unit_dir/$unit.d" ] || fail "Review and remove unsupported unit overrides before activation: $unit.d"
done
activation=1
stop_units
pid=$(systemctl --user show agmi.service --property=MainPID --value)
pid=${pid:-0}
[ "$pid" = 0 ] || fail 'The previous runtime did not stop; activation is blocked.'

# Keep the unversioned pilot artifacts for inspection only. They are not a
# compatible rollback release and are never offered as an activation target.
legacy=
for file in "$bin_dir/agmi" "$unit_dir/agmi.service" "$unit_dir/agmi-health.service" "$unit_dir/agmi-health.timer"; do
    if [ -e "$file" ] && [ ! -L "$file" ]; then
        if [ -z "$legacy" ]; then
            legacy=$(mktemp -d "$root/legacy-unversioned.XXXXXX")
            printf '%s\n' 'Inspection only: predates journal schema 2; never activate or restore its journal.' > "$legacy/INCOMPATIBLE"
        fi
        cp -p -- "$file" "$legacy/$(basename -- "$file")"
    fi
done
if [ -n "$legacy" ]; then sync -f "$legacy"; fi

# During initial cutover, install indirections while stopped and before current
# exists: an interruption fails closed instead of rebooting an unsafe old binary.
for name in agmi $units; do
    if [ "$name" = agmi ]; then destination=$bin_dir/agmi; else destination=$unit_dir/$name; fi
    target=$root/current/$name
    if [ -L "$destination" ] && [ "$(readlink "$destination")" = "$target" ]; then continue; fi
    link_temp=$destination.install.$$
    ln -s -- "$target" "$link_temp"
    mv -Tf -- "$link_temp" "$destination"
    link_temp=
done
sync -f "$bin_dir"
sync -f "$unit_dir"
# This is the only release-selection pointer. Loaded units pin their own binary
# until daemon-reload; the old executable cannot silently become the new one.
link_temp=$root/.current.$$
ln -s -- "$release_id" "$link_temp"
mv -Tf -- "$link_temp" "$root/current"
link_temp=
sync -f "$root"
systemctl --user daemon-reload
for unit in $units; do
    description=$(systemctl --user show "$unit" --property=Description --value)
    case $description in *"[release=$release_id]") ;; *) fail "Loaded unit identity mismatch: $unit" ;; esac
    dropins=$(systemctl --user show "$unit" --property=DropInPaths --value)
    [ -z "$dropins" ] || fail "Loaded unit has unsupported overrides: $unit"
done
stop_timeout=$(systemctl --user show agmi.service --property=TimeoutStopUSec --value)
[ "$stop_timeout" = infinity ] || fail 'Loaded stop deadline would truncate configured shutdown policy.'
if [ "${3-}" = --stopped ]; then
    activation=0
    status
    printf '%s\n' 'Activated and daemon-reloaded, remaining stopped for explicit journal migration.' \
        'No journal or pause state was changed; activate this release again to restart afterward.'
    exit 0
fi
systemctl --user restart agmi.service agmi-health.timer
systemctl --user is-active --quiet agmi.service agmi-health.timer
pid=$(systemctl --user show agmi.service --property=MainPID --value)
case $pid in ''|0|*[!0-9]*) fail 'No running runtime identity after activation.' ;; esac
[ "$(sha256 "/proc/$pid/exe")" = "${release_id#r-}" ] || fail 'Running binary does not match the activated release.'
activation=0
status
printf '%s\n' 'Activated without changing pause/admission, credentials, native harnesses, or journal history.' \
    'Units were not enabled; retain the existing enablement policy.' \
    'After one-way state migration, use compatible releases, roll forward, or stop; never restore an older journal.'
