#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from task_branch_publisher import (
    ALLOWED_REPOSITORY,
    Publisher,
    preflight_concurrency,
)
from publisher_runtime_backend import PublisherRuntimeBackend


def _event(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_output(values: dict[str, str]) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        for key, value in values.items():
            print(f"{key}={value}")
        return
    with open(output, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in {"preflight", "publish"}:
        print("usage: run_task_branch_publisher.py {preflight|publish} EVENT_JSON", file=sys.stderr)
        return 2
    event = _event(argv[2])
    if argv[1] == "preflight":
        _write_output(preflight_concurrency(event))
        return 0

    # Read the job-scoped GITHUB_TOKEN once, then remove it from the inherited
    # environment before any Git subprocess is created. The backend keeps the
    # token only in process memory and a temporary mode-0600 askpass file.
    token = os.environ.pop("HWM_PUBLISHER_TOKEN", None)
    if not token:
        print("publisher job token is unavailable", file=sys.stderr)
        return 2

    repository = ((event.get("repository") or {}).get("full_name"))
    if repository != ALLOWED_REPOSITORY:
        print("event repository is not bootstrap-v1 allowlisted", file=sys.stderr)
        return 2

    backend = PublisherRuntimeBackend(token=token, repository=repository)
    result = Publisher(backend).handle_event(event)
    if result is None:
        return 0
    issue_number = (event.get("issue") or {}).get("number")
    if not isinstance(issue_number, int):
        print("event does not identify an Issue", file=sys.stderr)
        return 2
    backend.post_result(issue_number, result)
    print(f"publish_status={result['status']} request_id={result['request_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
