"""Per-target workspace and session state."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from .models import Artifact, Finding


def default_root() -> Path:
    return Path.home() / ".centurion" / "workspaces"


def _slugify(name: str) -> str:
    slug = "".join(c if (c.isalnum() or c in "-_") else "-" for c in name.lower())
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


@dataclass
class Session:
    target: str
    platform: str
    device: str | None = None
    runs: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    processes: list[dict[str, Any]] = field(default_factory=list)


class Workspace:
    def __init__(self, root: Path, target: str, platform: str = "android") -> None:
        self.root = Path(root)
        self.slug = _slugify(target)
        self.dir = self.root / self.slug
        self.artifacts_dir = self.dir / "artifacts"
        self.session_file = self.dir / "session.json"
        self._target = target
        self._platform = platform

    def create(self) -> Session:
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        if self.session_file.exists():
            return self.load()
        session = Session(target=self._target, platform=self._platform)
        self.save(session)
        return session

    def load(self) -> Session:
        # NOTE: unlocked read-modify-write of session.json. Safe for the stdio
        # MCP server (one request at a time) and the CLI; concurrent writers would
        # race. Upgrade path: fcntl.flock around load/save if parallel drivers appear.
        data = json.loads(self.session_file.read_text())
        known = {f.name for f in fields(Session)}
        data = {k: v for k, v in data.items() if k in known}
        return Session(**data)

    def save(self, session: Session) -> None:
        self.session_file.write_text(json.dumps(asdict(session), indent=2))

    def record_run(
        self,
        tool: str,
        command: list[str],
        status: str,
        output: str | None = None,
    ) -> None:
        session = self.load()
        output_path = None
        preview = ""
        if output is not None:
            runs_dir = self.artifacts_dir / "runs"
            runs_dir.mkdir(parents=True, exist_ok=True)
            output_path = f"{len(session.runs):03d}-{tool}.txt"
            (runs_dir / output_path).write_text(output)
            preview = output[:2048]
        session.runs.append({
            "tool": tool,
            "command": command,
            "status": status,
            "output_path": output_path,
            "preview": preview,
        })
        self.save(session)

    def add_artifact(self, artifact: Artifact) -> None:
        session = self.load()
        session.artifacts.append(artifact.to_dict())
        self.save(session)

    def add_finding(self, finding: Finding) -> None:
        session = self.load()
        session.findings.append(finding.to_dict())
        self.save(session)
