"""W25-44: scripts/check-version-not-tagged.sh fails when the workspace version is a release tag."""
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, "..", "..", "check-version-not-tagged.sh")


def git(repo, *args):
    subprocess.run(["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   check=True, capture_output=True)


class VersionNotTaggedTest(unittest.TestCase):
    def repo(self, version, tags):
        d = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ["rm", "-rf", d])
        with open(os.path.join(d, "Cargo.toml"), "w") as f:
            f.write('[workspace]\nmembers = []\n\n[workspace.package]\nedition = "2021"\nversion = "%s"\n' % version)
        git(d, "init", "-q")
        git(d, "add", "Cargo.toml")
        git(d, "commit", "-q", "-m", "x")
        for t in tags:
            git(d, "tag", t)
        return d

    def run_check(self, d):
        return subprocess.run(["bash", CHECK, d], capture_output=True, text=True)

    def test_a_tagged_version_fails(self):
        out = self.run_check(self.repo("0.1.0-rc.2", ["v0.1.0-rc.1", "v0.1.0-rc.2"]))
        self.assertEqual(out.returncode, 1)
        self.assertIn("is the release tag v0.1.0-rc.2", out.stderr)

    def test_a_dev_version_passes(self):
        out = self.run_check(self.repo("0.1.0-rc.3-dev", ["v0.1.0-rc.1", "v0.1.0-rc.2"]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("version_check ok: workspace version 0.1.0-rc.3-dev", out.stdout)

    def test_no_tags_fails(self):
        out = self.run_check(self.repo("0.1.0-rc.3-dev", []))
        self.assertEqual(out.returncode, 1)
        self.assertIn("no tags", out.stderr)

    def test_main_is_not_a_release_tag(self):
        repo = os.path.join(HERE, "..", "..", "..")
        tags = subprocess.run(["git", "-C", repo, "tag", "--list"], capture_output=True, text=True).stdout
        if not tags.strip():
            self.skipTest("this checkout has no tags; the CI step fetches them and runs the check")
        out = self.run_check(repo)
        self.assertEqual(out.returncode, 0, out.stderr)


if __name__ == "__main__":
    unittest.main()
