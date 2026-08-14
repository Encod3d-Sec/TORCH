"""T4.1: SessionStart surfaces when the framework repo is behind its upstream, so a stale
campaign.py/hook set is caught (road ran a driver 26 commits behind main and it cascaded)."""
import importlib.util
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    os.environ.setdefault("CLAUDEBRAIN_VAULT", ROOT)
    spec = importlib.util.spec_from_file_location(
        "ei", os.path.join(ROOT, "skills", "hooks", "engagement-init.py"))
    ei = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ei)
    return ei


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


def _repo_behind(tmp_path, n):
    """A clone whose local HEAD is n commits behind its tracked upstream."""
    remote = tmp_path / "remote"
    remote.mkdir()
    _git(str(remote), "init", "-q", "-b", "main")
    for i in range(n + 1):
        (remote / "f").write_text(str(i))
        _git(str(remote), "add", "f")
        _git(str(remote), "commit", "-qm", "c%d" % i)
    clone = tmp_path / "clone"
    _git(str(tmp_path), "clone", "-q", str(remote), str(clone))
    _git(str(clone), "reset", "--hard", "-q", "HEAD~%d" % n)   # local now n behind @{u}
    return str(clone)


def test_reports_commits_behind(tmp_path):
    ei = _load()
    assert ei._driver_behind(_repo_behind(tmp_path, 6)) == 6


def test_zero_when_up_to_date(tmp_path):
    ei = _load()
    assert ei._driver_behind(_repo_behind(tmp_path, 0)) == 0


def test_zero_when_not_a_repo(tmp_path):
    ei = _load()
    assert ei._driver_behind(str(tmp_path)) == 0
