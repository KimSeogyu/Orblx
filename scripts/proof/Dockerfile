FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY orblx /usr/local/bin/orblx
RUN chmod 755 /usr/local/bin/orblx

ENTRYPOINT ["/usr/local/bin/orblx"]
