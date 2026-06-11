"""Per-target workspace and session state."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from .models import Artifact


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
        data = json.loads(self.session_file.read_text())
        known = {f.name for f in fields(Session)}
        data = {k: v for k, v in data.items() if k in known}
        return Session(**data)

    def save(self, session: Session) -> None:
        self.session_file.write_text(json.dumps(asdict(session), indent=2))

    def record_run(self, tool: str, command: list[str], status: str) -> None:
        session = self.load()
        session.runs.append({"tool": tool, "command": command, "status": status})
        self.save(session)

    def add_artifact(self, artifact: Artifact) -> None:
        session = self.load()
        session.artifacts.append(artifact.to_dict())
        self.save(session)
