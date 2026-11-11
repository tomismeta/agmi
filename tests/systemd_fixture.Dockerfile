# Disposable acceptance environment only; never mount a host home, bus or cgroup tree.
FROM ubuntu:24.04
ENV container=docker
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus-user-session python3 ca-certificates coreutils util-linux strace \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 17321 --create-home --shell /bin/sh agmi-systemd-fixture \
    && chmod 0700 /home/agmi-systemd-fixture \
    && printf '%s\n' agmi-isolated-systemd-acceptance > /etc/agmi-systemd-fixture
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
