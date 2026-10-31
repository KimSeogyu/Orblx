"""W25-35: a docker stand-in for the proof lock tests.

The sampler of proof-lock.sh counts the other orblx containers with "docker ps". When it cannot
count them, the run is not valid and proof_lock_end exits with status 3. The tests use this
stand-in, so the result does not depend on the docker of the host.
"""

import os
import tempfile

# "docker ps" prints no names: 0 other containers.
EMPTY = "#!/bin/sh\nexit 0\n"
# "docker ps" fails (no access to the docker socket).
FAILS = '#!/bin/sh\necho "permission denied while trying to connect to the docker API" >&2\nexit 1\n'
# The stand-in for "sudo -n CMD": it runs CMD with FAKE_VIA_SUDO=1.
SUDO = '#!/bin/sh\n[ "$1" = "-n" ] && shift\nFAKE_VIA_SUDO=1 exec "$@"\n'
SUDO_FAILS = '#!/bin/sh\necho "sudo: a password is required" >&2\nexit 1\n'


def with_fake_docker(env, docker=EMPTY, sudo=None):
    """Return a copy of env with the stand-in docker (and sudo, if given) first in PATH."""
    bin_dir = tempfile.mkdtemp()
    for name, body in (("docker", docker), ("sudo", sudo)):
        if body is None:
            continue
        path = os.path.join(bin_dir, name)
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, 0o755)
    return dict(env, PATH=bin_dir + os.pathsep + env.get("PATH", ""))


def fake_cargo_home(docker=EMPTY):
    """Return a temp CARGO_HOME with the stand-in docker in its bin dir.

    release-sweep.sh sets PATH to "$CARGO_HOME/bin" and the system dirs for each proof, so the
    stand-in in PATH is not used there. Its bin dir is first in that PATH. The sweep does not run
    cargo in test mode.
    """
    home = tempfile.mkdtemp()
    bin_dir = os.path.join(home, "bin")
    os.mkdir(bin_dir)
    path = os.path.join(bin_dir, "docker")
    with open(path, "w") as f:
        f.write(docker)
    os.chmod(path, 0o755)
    return home
