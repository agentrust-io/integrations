"""Report integration ownership and compatibility freshness without mutating state."""

from __future__ import annotations

from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml


ROOT = Path(__file__).resolve().parents[1]
MAX_AGE_DAYS = 60


def github(path: str) -> object:
    request = Request(f"https://api.github.com{path}", headers={"Accept": "application/vnd.github+json"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urlopen(request, timeout=20) as response:  # noqa: S310 - fixed API host
        return json.load(response)


def report(root: Path = ROOT) -> list[str]:
    findings: list[str] = []
    today = date.today()
    for manifest in sorted(root.rglob("integration.yaml")):
        relative = manifest.relative_to(root)
        if any(part.startswith((".", "_")) for part in relative.parts[:-1]):
            continue
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        login = data["maintainer"]["github"]
        try:
            github(f"/users/{login}")
        except HTTPError as exc:
            findings.append(f"{relative}: maintainer @{login} lookup failed ({exc.code})")
        except URLError as exc:
            findings.append(f"{relative}: maintainer lookup unavailable ({exc.reason})")

        repository = data["repository"]
        marker = "github.com/"
        if marker not in repository:
            continue
        slug = repository.split(marker, 1)[1].split("/tree/", 1)[0].rstrip("/")
        try:
            repo = github(f"/repos/{slug}")
            pushed = datetime.fromisoformat(repo["pushed_at"].replace("Z", "+00:00")).date()
            age = (today - pushed).days
            if repo.get("archived"):
                findings.append(f"{relative}: repository {slug} is archived")
            elif age > MAX_AGE_DAYS:
                findings.append(f"{relative}: repository {slug} has no push for {age} days")
        except (HTTPError, URLError) as exc:
            findings.append(f"{relative}: repository lookup failed ({exc})")
    return findings


if __name__ == "__main__":
    print(f"maintenance report generated {datetime.now(timezone.utc).isoformat()}")
    findings = report()
    for finding in findings:
        print(f"NOTICE {finding}")
    print(f"{len(findings)} notice(s); no repository state was changed")
