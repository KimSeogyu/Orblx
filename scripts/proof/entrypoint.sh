#!/bin/sh
# Start the DNS resolver, then run orblx.
# The node sets resolvectl on the TUN device.
# This script does not print secrets.

set -u

if [ -x /usr/lib/systemd/systemd-resolved ]; then
  # A container restart keeps /run. A stale socket makes resolvectl fail.
  rm -rf /run/dbus /run/systemd/resolve
  mkdir -p /run/systemd /run/dbus || true
  dbus-daemon --system --fork || true
  /usr/lib/systemd/systemd-resolved >/tmp/systemd-resolved.log 2>&1 &
  i=0
  while [ "$i" -lt 50 ]; do
    if resolvectl status >/dev/null 2>&1; then
      break
    fi
    if [ ! -S /run/dbus/system_bus_socket ]; then
      dbus-daemon --system --fork || true
    fi
    i=$((i + 1))
    sleep 0.2
  done
fi

if [ -f /etc/nsswitch.conf ]; then
  # files is first. /etc/hosts wins over systemd-resolved and DNS.
  if grep -q '^hosts:' /etc/nsswitch.conf; then
    sed -i 's/^hosts:.*/hosts: files resolve [!UNAVAIL=return] dns/' /etc/nsswitch.conf || true
  else
    echo 'hosts: files resolve [!UNAVAIL=return] dns' >> /etc/nsswitch.conf || true
  fi
fi

exec /usr/local/bin/orblx "$@"
