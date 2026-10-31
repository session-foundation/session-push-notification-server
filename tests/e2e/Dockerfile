FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 && curl -fsSL https://deb.oxen.io/pub.gpg -o /etc/apt/trusted.gpg.d/oxen.gpg \
 && echo "deb https://deb.oxen.io trixie main" > /etc/apt/sources.list.d/oxen.list \
 && apt-get update && apt-get install -y --no-install-recommends \
    g++ cmake make pkg-config ccache python3-dev python3-nacl python3-coloredlogs procps \
    libsodium-dev liboxenc-dev liboxenmq-dev liboxen-quic-dev libfmt-dev liboxen-logging-dev \
    nlohmann-json3-dev libsystemd-dev libpq-dev libzmq3-dev postgresql \
 && rm -rf /var/lib/apt/lists/*
