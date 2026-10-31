# Built by run.sh with the repository's contrib/ directory as the context, for the apt key.
FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
COPY deb.session.foundation.gpg /etc/apt/trusted.gpg.d/
# The base image cannot follow the repository's redirect to https without ca-certificates.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && echo "deb https://deb.session.foundation trixie main" > /etc/apt/sources.list.d/session.list \
 && apt-get update && apt-get install -y --no-install-recommends \
    g++ cmake make pkg-config ccache python3-dev python3-nacl python3-coloredlogs python3-psycopg \
    procps libsodium-dev liboxenc-dev liboxenmq-dev liboxen-quic-dev libfmt-dev liboxen-logging-dev \
    nlohmann-json3-dev libsystemd-dev libpq-dev libzmq3-dev postgresql \
 && rm -rf /var/lib/apt/lists/*
# A throwaway server for the harness, shaped like a real deployment: an unprivileged role that owns
# its database, which run.sh connects as.  Local connections need no password; run.sh starts the
# cluster.
RUN v=$(ls /usr/lib/postgresql) \
 && sed -i 's/^\(local\s\+all\s\+\S\+\s\+\)peer$/\1trust/' /etc/postgresql/$v/main/pg_hba.conf \
 && pg_ctlcluster $v main start \
 && su postgres -c 'createuser spns && createdb -O spns spns_e2e' \
 && pg_ctlcluster $v main stop
