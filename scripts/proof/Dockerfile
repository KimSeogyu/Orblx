FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN printf '%s\n' '#!/bin/sh' 'exit 101' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        iptables \
        curl \
        python3 \
        ca-certificates \
        dbus \
        systemd-resolved \
        libnss-resolve \
    && rm -rf /var/lib/apt/lists/*

COPY orblx /usr/local/bin/orblx
COPY entrypoint.sh /usr/local/bin/orblx-entrypoint
RUN chmod 755 /usr/local/bin/orblx /usr/local/bin/orblx-entrypoint

ENTRYPOINT ["/usr/local/bin/orblx-entrypoint"]
