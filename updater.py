"""Self-update for the Amazon Quick SE demo kit, from the kit's GitHub repo (default branch: main).

  git clone   -> `git pull --ff-only` (refuses if you have local edits)
  any other   -> download the branch zip, back up the current copy to ~/.quick-se-kit/previous, copy the new files
                 over this folder. `rollback` copies the backup back.

The version is the VERSION line in quick_kit.py; "what's new" comes from CHANGELOG.md.
"""
from __future__ import annotations

import io
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import zipfile

import requests

DEFAULT_REPO = "Paulie631/se-demo-swift"
DEFAULT_REF = "main"
EXECUTABLE = ("quick-kit", "Install Quick Kit.command", "aws/deploy.sh", "aws/build.py")
SKIP = {".git", "__pycache__", ".DS_Store"}
MAX_ZIP = 20 * 1024 * 1024


class UpdateError(Exception):
    pass


def parse(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "0")[:3]) or (0,)


def version_in(text: str) -> str:
    m = re.search(r'^VERSION = "([^"]+)"', text, re.M)
    return m.group(1) if m else ""


def _get(url: str, verify=True) -> requests.Response:
    try:
        r = requests.get(url, timeout=30, verify=verify)
    except requests.RequestException as e:
        raise UpdateError(f"Couldn't reach GitHub ({e.__class__.__name__}). Check this laptop's connection.")
    if r.status_code == 404:
        raise UpdateError(f"GitHub says {url.split('/', 3)[-1]} doesn't exist. Most likely the repo is private: the "
                          "kit downloads updates without signing in, so the repo must be public (GitHub › Settings › "
                          "General › Change visibility). Or the branch name under Advanced is wrong.")
    if r.status_code != 200:
        raise UpdateError(f"GitHub returned HTTP {r.status_code} for {url.split('/', 3)[-1]}. If your web policy "
                          "blocks GitHub, ask IT to allow raw.githubusercontent.com and codeload.github.com.")
    if r.text[:200].lower().lstrip().startswith(("<!doctype", "<html")) and not url.endswith(".zip"):
        raise UpdateError("GitHub's reply looks like a web page, so a web policy may have blocked the download.")
    return r


def notes_since(changelog: str, current: str) -> str:
    """CHANGELOG.md sections ('## 0.3.0 ...') newer than `current`."""
    out, keep = [], False
    for line in changelog.splitlines():
        m = re.match(r"^##\s+v?(\d+\.\d+\.\d+)", line)
        if m:
            keep = parse(m.group(1)) > parse(current)
        if keep:
            out.append(line)
    return "\n".join(out).strip()


def mode(here: pathlib.Path) -> str:
    return "git" if (here / ".git").exists() else "copy"


def _git_file(here: pathlib.Path, ref: str, path: str) -> str:
    """Read a file from the remote branch of a git checkout: git fetch is authoritative, with no CDN cache."""
    f = subprocess.run(["git", "-C", str(here), "fetch", "--quiet", "origin", ref], capture_output=True, text=True,
                       timeout=60)
    if f.returncode:
        raise UpdateError(f"git fetch failed: {(f.stderr or f.stdout).strip()[-200:]}")
    r = subprocess.run(["git", "-C", str(here), "show", f"origin/{ref}:{path}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def _latest_file(repo: str, ref: str, path: str, verify=True) -> str:
    """GitHub's contents API first (current immediately), then raw.githubusercontent.com (cached for ~5 minutes)."""
    try:
        r = requests.get(f"https://api.github.com/repos/{repo}/contents/{path}", params={"ref": ref},
                         headers={"Accept": "application/vnd.github.raw+json"}, timeout=20, verify=verify)
        if r.status_code == 200 and not r.text.lstrip().startswith("<"):
            return r.text
    except requests.RequestException:
        pass
    return _get(f"https://raw.githubusercontent.com/{repo}/{ref}/{path}", verify).text


def check(current: str, here: pathlib.Path, repo=DEFAULT_REPO, ref=DEFAULT_REF, verify=True,
          backup: pathlib.Path | None = None) -> dict:
    if mode(here) == "git":
        src = _git_file(here, ref, "quick_kit.py")
        latest = version_in(src)
        if latest:
            prev = backup / "quick_kit.py" if backup else None
            return {"current": current, "latest": latest, "available": parse(latest) > parse(current),
                    "notes": notes_since(_git_file(here, ref, "CHANGELOG.md"), current), "mode": "git",
                    "repo": repo, "ref": ref, "rollback": ""}
    latest = version_in(_latest_file(repo, ref, "quick_kit.py", verify))
    if not latest:
        raise UpdateError("Couldn't read the latest version from GitHub.")
    try:
        notes = notes_since(_latest_file(repo, ref, "CHANGELOG.md", verify), current)
    except UpdateError:
        notes = ""
    prev = backup / "quick_kit.py" if backup else None
    return {"current": current, "latest": latest, "available": parse(latest) > parse(current), "notes": notes,
            "mode": mode(here), "repo": repo, "ref": ref,
            "rollback": version_in(prev.read_text(encoding="utf-8")) if prev and prev.exists() else ""}


def _copytree(src: pathlib.Path, dst: pathlib.Path) -> None:
    for p in src.rglob("*"):
        rel = p.relative_to(src)
        if any(part in SKIP for part in rel.parts):
            continue
        t = dst / rel
        if p.is_dir():
            t.mkdir(parents=True, exist_ok=True)
        else:
            t.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, t)


def _chmod(here: pathlib.Path) -> None:
    if os.name == "nt":
        return
    for f in EXECUTABLE:
        p = here / f
        if p.exists():
            p.chmod(p.stat().st_mode | 0o111)


def apply(here: pathlib.Path, backup: pathlib.Path, expected: str, repo=DEFAULT_REPO, ref=DEFAULT_REF,
          verify=True, log=print) -> str:
    """Install the latest version into `here`. Returns the installed version."""
    if mode(here) == "git":
        dirty = subprocess.run(["git", "-C", str(here), "status", "--porcelain", "--untracked-files=no"],
                               capture_output=True, text=True)
        if dirty.returncode:
            raise UpdateError(f"git isn't working in {here}: {dirty.stderr.strip()[:200]}")
        if dirty.stdout.strip():
            raise UpdateError("This git checkout has local changes, so the kit won't overwrite them. Commit or stash "
                              f"them, then update (or run: git -C \"{here}\" pull).")
        r = subprocess.run(["git", "-C", str(here), "pull", "--ff-only"], capture_output=True, text=True, timeout=120)
        if r.returncode:
            raise UpdateError(f"git pull failed: {(r.stderr or r.stdout).strip()[-300:]}")
        log(f"git pull: {r.stdout.strip().splitlines()[-1] if r.stdout.strip() else 'done'}")
        _chmod(here)
        return version_in((here / "quick_kit.py").read_text(encoding="utf-8"))

    r = _get(f"https://codeload.github.com/{repo}/zip/{ref}", verify)
    if len(r.content) > MAX_ZIP:
        raise UpdateError("The download is far larger than expected, so it was stopped.")
    try:
        z = zipfile.ZipFile(io.BytesIO(r.content))
    except zipfile.BadZipFile:
        raise UpdateError("The download isn't a valid zip (a web policy may have replaced it).")
    with tempfile.TemporaryDirectory() as td:
        for n in z.namelist():
            p = pathlib.PurePosixPath(n)
            if p.is_absolute() or ".." in p.parts:
                raise UpdateError(f"Unexpected file in the update: {n}")
        z.extractall(td)
        tops = [p for p in pathlib.Path(td).iterdir() if p.is_dir()]
        if len(tops) != 1 or not (tops[0] / "quick_kit.py").exists():
            raise UpdateError("Unexpected layout in the update zip.")
        new = tops[0]
        got = version_in((new / "quick_kit.py").read_text(encoding="utf-8"))
        if expected and got != expected:
            raise UpdateError(f"Downloaded version {got} doesn't match the expected {expected}; try again.")
        if backup.exists():
            shutil.rmtree(backup)
        backup.mkdir(parents=True)
        _copytree(here, backup)
        log(f"Backed up the current version to {backup}")
        _copytree(new, here)
    _chmod(here)
    log(f"Installed {got}")
    return got


def rollback(here: pathlib.Path, backup: pathlib.Path, log=print) -> str:
    if mode(here) == "git":
        raise UpdateError("This is a git checkout: roll back with git (for example: git checkout <commit>).")
    if not (backup / "quick_kit.py").exists():
        raise UpdateError("There's no previous version to roll back to.")
    v = version_in((backup / "quick_kit.py").read_text(encoding="utf-8"))
    _copytree(backup, here)
    _chmod(here)
    log(f"Rolled back to {v}")
    return v
