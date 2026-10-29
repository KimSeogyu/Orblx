#!/bin/sh
# Start the DNS resolver, then run orblx.
# The node sets resolvectl on the TUN device.
# This script does not print secrets.

set -u

if [ -x /usr/lib/systemd/systemd-resolved ]; then
  mkdir -p /run/systemd /run/dbus || true
  rm -rf /run/systemd/resolve
  if [ ! -S /run/dbus/system_bus_socket ]; then
    dbus-daemon --system --fork || true
  fi
  if [ ! -S /run/systemd/resolve/io.systemd.Resolve ]; then
    /usr/lib/systemd/systemd-resolved >/tmp/systemd-resolved.log 2>&1 &
  fi
  i=0
  while [ "$i" -lt 30 ]; do
    if resolvectl status >/dev/null 2>&1; then
      break
    fi
    i=$((i + 1))
    sleep 0.1
  done
fi

if [ -f /etc/nsswitch.conf ]; then
  if grep -q '^hosts:' /etc/nsswitch.conf; then
    sed -i 's/^hosts:.*/hosts: resolve [!UNAVAIL=return] files dns/' /etc/nsswitch.conf || true
  else
    echo 'hosts: resolve [!UNAVAIL=return] files dns' >> /etc/nsswitch.conf || true
  fi
fi

exec /usr/local/bin/orblx "$@"
