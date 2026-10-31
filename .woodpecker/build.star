# Builds the hivemind, then builds and runs the end-to-end scenarios (the e2e target; see tests/e2e)
# against a Postgres service.

registry = "registry.session.codes/"

events = ["push", "pull_request", "tag", "manual"]

apt_get = "apt-get -o=Dpkg::Use-Pty=0 -q"

# What the hivemind and the fakes build against, from Debian plus the Session repository, and what
# the harness needs to drive them.
deps = [
    "g++",
    "cmake",
    "make",
    "pkg-config",
    "ccache",
    "python3-dev",
    "python3-nacl",
    "python3-coloredlogs",
    "python3-psycopg",
    "postgresql-client",
    "procps",
    "libsodium-dev",
    "liboxenc-dev",
    "liboxenmq-dev",
    "liboxen-quic-dev",
    "libfmt-dev",
    "liboxen-logging-dev",
    "nlohmann-json3-dev",
    "libsystemd-dev",
    "libpq-dev",
    "libzmq3-dev",
]

def e2e(name, image, codename, target, when = events, env = {}):
    return {
        "name": name,
        "labels": {"platform": "linux/amd64", "backend": "docker"},
        "when": [{"event": when}],
        "services": [{
            "name": "postgres",
            "image": "docker.io/postgres:18",
            "environment": {"POSTGRES_HOST_AUTH_METHOD": "trust"},
        }],
        "steps": [{
            "name": "build and test",
            "image": registry + image,
            "pull": True,
            # The harness finds the server through libpq's environment, and runs as an
            # unprivileged role that owns its database, as a real deployment does.
            "environment": dict({"PGHOST": "postgres", "PGUSER": "spns"}, **env),
            "commands": [
                'echo "Building on $${CI_MACHINE}"',
                'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                apt_get + " update",
                apt_get + " install -y eatmydata",
                "eatmydata " + apt_get + " dist-upgrade -y",
                "cp contrib/deb.session.foundation.gpg /etc/apt/trusted.gpg.d",
                "echo deb http://deb.session.foundation " + codename + " main >/etc/apt/sources.list.d/session.list",
                "eatmydata " + apt_get + " update",
                "eatmydata " + apt_get + " install --no-install-recommends -y " + " ".join(deps),
                "cmake -S . -B build -DCMAKE_BUILD_TYPE=Release",
                "make -C build -j6",
                "until pg_isready -q -U postgres; do sleep 1; done",
                "createuser -U postgres spns",
                "createdb -U postgres -O spns spns_e2e",
                "make -C build " + target,
            ],
        }],
    }

def main(ctx):
    return [
        e2e("Debian stable e2e", "debian-stable", "stable", "e2e-fast"),
        # The slow scenarios take a quarter of an hour at full length, so not on pull requests,
        # whose "All builds" check waits for every workflow; and the sustained stream is cut to
        # three minutes, long enough for its duplicate filter to rotate several times.
        e2e(
            "Debian stable e2e slow",
            "debian-stable",
            "stable",
            "e2e-slow",
            when = ["push", "tag", "manual", "cron"],
            env = {"E2E_SUSTAINED_MINUTES": "3"},
        ),
    ]
