#!/bin/sh
# Install shared artifacts only. Never start, resume, initialize or replace state.
set -eu

usage() {
    printf '%s\n' 'Usage: sh deploy/install-user.sh /path/to/built/agmi' \
        'Installs ~/.local/bin/agmi and shared user-systemd units; does not activate them.'
}
if [ "${1-}" = '--help' ]; then
    usage
    exit 0
fi
if [ "$#" -ne 1 ]; then
    usage >&2
    exit 2
fi
case ${HOME-} in
    /*) ;;
    *) printf '%s\n' 'HOME must be an absolute per-user directory.' >&2; exit 2 ;;
esac
if [ ! -f "$1" ] || [ ! -x "$1" ]; then
    printf '%s\n' 'The supplied binary must be a regular executable file.' >&2
    exit 2
fi
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bin_dir=$HOME/.local/bin
unit_dir=$HOME/.config/systemd/user
for unit in agmi.service agmi-health.service agmi-health.timer; do
    if [ ! -f "$source_dir/$unit" ]; then
        printf '%s\n' 'Shared service files are missing beside the installer.' >&2
        exit 2
    fi
done
umask 077
mkdir -p "$bin_dir" "$unit_dir"
staging=
trap 'if [ -n "$staging" ]; then rm -f -- "$staging"; fi' EXIT HUP INT TERM
# Rename rather than overwrite a running executable. Existing processes keep
# their old inode until the operator explicitly restarts the service.
staging=$(mktemp "$bin_dir/.agmi-install.XXXXXX")
install -m 0755 -- "$1" "$staging"
mv -f -- "$staging" "$bin_dir/agmi"
staging=
for unit in agmi.service agmi-health.service agmi-health.timer; do
    staging=$(mktemp "$unit_dir/.agmi-install.XXXXXX")
    install -m 0644 -- "$source_dir/$unit" "$staging"
    mv -f -- "$staging" "$unit_dir/$unit"
    staging=
done
printf '%s\n' \
    'Installed shared binary and units. No config, credentials, identity, locks or state were changed.' \
    'No service was started, resumed, enabled or restarted.' \
    'Operator next steps:' \
    '  systemctl --user daemon-reload' \
    '  Review ~/.config/agmi/config.toml and existing state bindings.' \
    '  Use agmi config init only for a genuinely new installation; never replace an existing config.' \
    '  Explicitly authorize participation with: ~/.local/bin/agmi --config ~/.config/agmi/config.toml resume' \
    '  Start after review: systemctl --user enable --now agmi.service agmi-health.timer' \
    '  For an existing running service, explicitly restart it to load the new binary.' \
    '  Inspect: systemctl --user status agmi.service agmi-health.service agmi-health.timer' \
    '  Inspect: journalctl --user --user-unit=agmi-health.service' \
    'Health failures remain local exit status and journal records; agmi sends no external notifications.' \
    'Agents may read structured health/events/warnings and forward findings through existing native channels.'
