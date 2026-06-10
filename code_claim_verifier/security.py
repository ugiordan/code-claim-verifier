import os


def safe_path(claim_path: str, repo_path: str) -> str | None:
    """Resolve a claim's file path safely within the repo.
    Returns None if the path escapes the repo (path traversal)."""
    abs_repo = os.path.realpath(repo_path)
    resolved = os.path.realpath(os.path.join(repo_path, claim_path))
    if not resolved.startswith(abs_repo + os.sep):
        return None
    return resolved
