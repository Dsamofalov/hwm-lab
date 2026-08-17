"""Runtime bridge between an accepted Git CAS and eventually consistent REST ref reads."""
from __future__ import annotations

from publisher_backend import GitHubAPIBackend


class PublisherRuntimeBackend(GitHubAPIBackend):
    """Treat an exit-0 exact Git lease push as authoritative for one immediate ref read.

    GitHub's Git server can accept an exact `--force-with-lease` update before the
    REST ref endpoint reflects that write. The publisher already has an atomic
    success/failure result from Git itself. Cache only that accepted `(branch,
    new_head)` and consume it on the immediate post-CAS verification performed by
    the policy layer. Subsequent reads return to the REST API, and exact CI run
    association remains the final proof that workflow_dispatch used `new_head`.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._accepted_git_heads: dict[str, str] = {}

    def compare_and_set_branch(self, branch: str, expected_head: str, new_head: str) -> bool:
        accepted = super().compare_and_set_branch(branch, expected_head, new_head)
        if accepted:
            self._accepted_git_heads[branch] = new_head
        return accepted

    def get_branch_head(self, branch: str) -> str:
        accepted = self._accepted_git_heads.pop(branch, None)
        if accepted is not None:
            return accepted
        return super().get_branch_head(branch)
