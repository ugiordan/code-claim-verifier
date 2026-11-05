"""Offline version comparison: SemVer, PEP 440, Go pseudo-versions, RPM NEVRA.

Pure functions, no I/O, no LLM. Deterministic range checks that run before
any network or model call, usable in air-gapped environments.

Ecosystems:
- semver (default; also npm, cargo): X.Y.Z with optional prerelease
- python (PEP 440): epochs, a/b/rc, post, dev, local versions
- go: SemVer with ``v`` prefix, pseudo-versions (v0.0.0-YYYYMMDDHHMMSS-hash)
  ordered by their prerelease timestamp, and ``+incompatible`` builds
- rpm (NEVRA): [epoch:]version[-release] compared with rpmvercmp semantics
  (numeric segments dominate alphabetic, ``~`` pre-release sorts first,
  ``^`` sorts after the base version)

Known limitation: an RPM backport with a different version string may
contain the fix even when the comparator says "older". Version math cannot
verify patch content; callers must check the actual patch for backports.
"""
from __future__ import annotations

import re

ECOSYSTEM_ALIASES = {
    "semver": "semver", "npm": "semver", "node": "semver", "javascript": "semver",
    "js": "semver", "cargo": "semver", "rust": "semver", "maven": "semver",
    "python": "python", "pypi": "python", "pip": "python",
    "go": "go", "golang": "go",
    "rpm": "rpm", "redhat": "rpm", "ubi": "rpm", "rhel": "rpm",
}

_SEMVER_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
_PEP440_PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "rc": 2, "c": 2}
_PEP440_RE = re.compile(
    r"^v?(\d+!)?(\d+(?:\.\d+)*)(?:(a|alpha|b|beta|rc|c)(\d+))?"
    r"(?:\.post(\d+))?(?:\.dev(\d+))?(?:\+[a-z0-9.]+)?$"
)
_RPM_PSEUDO_RE = re.compile(r"^0\.0\.0-(\d{14})-[0-9a-f]+$")


def normalize_ecosystem(name: str | None) -> str:
    """Map an ecosystem or language name to a comparator family."""
    if not name:
        return "semver"
    key = name.strip().lower()
    return ECOSYSTEM_ALIASES.get(key, "semver")


# --------------------------------------------------------------------------
# Keys: map each version to a tuple that compares correctly with Python's
# element-wise tuple ordering.
# --------------------------------------------------------------------------

def _semver_key(version: str) -> tuple:
    text = version.strip()
    if text.endswith("+incompatible"):
        text = text[: -len("+incompatible")]
    match = _SEMVER_RE.match(text)
    if not match:
        raise ValueError(f"not a SemVer version: {version!r}")
    # Advisories freely mix 1, 2, and 3 component versions; zero-pad so
    # "1.2" == "1.2.0".
    parts = tuple(int(match.group(i) or 0) for i in (1, 2, 3))
    major, minor, patch = parts
    if match.group(4) is None:
        pre = (1,)
    else:
        ids = []
        for ident in match.group(4).split("."):
            if ident.isdigit():
                ids.append((0, int(ident), ""))
            else:
                ids.append((1, 0, ident))
        # A prerelease sorts before the release; shorter identifier lists
        # sort first when one is a prefix of the other.
        pre = (0, tuple(ids))
    return (major, minor, patch, pre)


def _pep440_key(version: str) -> tuple:
    match = _PEP440_RE.match(version.strip().lower())
    if not match:
        raise ValueError(f"not a PEP 440 version: {version!r}")
    epoch = int(match.group(1)[:-1]) if match.group(1) else 0
    release = tuple(int(part) for part in match.group(2).split("."))
    while release and release[-1] == 0:
        release = release[:-1]  # 1.0 == 1.0.0
    if match.group(3):
        rank = _PEP440_PRE[match.group(3)]
        pre = (1, rank, int(match.group(4)))
    elif match.group(6):
        pre = (0,)  # a dev-only version sorts before any pre-release
    else:
        pre = (2,)  # final sorts after any pre-release
    post = (1, int(match.group(5))) if match.group(5) else (0,)
    dev = (0, int(match.group(6))) if match.group(6) else (1,)
    # PEP 440 ordering: dev < a < b < rc < final < post; local ignored for
    # ordering (a local version sorts after the same public version).
    return (epoch, release, pre, post, dev)


def _rpmvercmp(a: str, b: str) -> int:
    """The RPM version comparison algorithm (version or release strings)."""
    i = j = 0
    while i < len(a) or j < len(b):
        # Skip separators (anything that is not alphanumeric, ~, or ^).
        while i < len(a) and not (a[i].isalnum() or a[i] in "~^"):
            i += 1
        while j < len(b) and not (b[j].isalnum() or b[j] in "~^"):
            j += 1

        a_tilde = i < len(a) and a[i] == "~"
        b_tilde = j < len(b) and b[j] == "~"
        if a_tilde and not b_tilde:
            return -1
        if b_tilde and not a_tilde:
            return 1
        if a_tilde and b_tilde:
            i += 1
            j += 1
            continue

        a_caret = i < len(a) and a[i] == "^"
        b_caret = j < len(b) and b[j] == "^"
        if a_caret or b_caret:
            if a_caret and b_caret:
                i += 1
                j += 1
                continue
            # ^ sorts after end-of-string but before any other character.
            if a_caret:
                return 1 if j >= len(b) else -1
            return -1 if i >= len(a) else 1

        if i >= len(a) or j >= len(b):
            break

        # Collect one segment: digits or letters.
        a_isdigit = a[i].isdigit()
        b_isdigit = b[j].isdigit()
        a_start, b_start = i, j
        while i < len(a) and a[i].isdigit() == a_isdigit and a[i].isalnum():
            i += 1
        while j < len(b) and b[j].isdigit() == b_isdigit and b[j].isalnum():
            j += 1
        a_seg, b_seg = a[a_start:i], b[b_start:j]

        if a_isdigit and b_isdigit:
            a_num, b_num = int(a_seg), int(b_seg)
            if a_num != b_num:
                return -1 if a_num < b_num else 1
        elif a_isdigit != b_isdigit:
            return 1 if a_isdigit else -1  # numeric segments dominate
        elif a_seg != b_seg:
            return -1 if a_seg < b_seg else 1

    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def _rpm_key(version: str) -> tuple:
    """[epoch:]version[-release] -> comparable (epoch, version, release)."""
    text = version.strip()
    epoch = 0
    if ":" in text:
        head, _, rest = text.rpartition(":")
        if head.isdigit():
            epoch = int(head)
            text = rest
        else:
            raise ValueError(f"non-numeric epoch in RPM version: {version!r}")
    if "-" in text:
        ver, _, release = text.partition("-")
    else:
        ver, release = text, ""
    return (epoch, _RpmCmp(ver), _RpmCmp(release))


class _RpmCmp:
    """Wraps a string so tuples of them compare via rpmvercmp."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _RpmCmp) and _rpmvercmp(self.text, other.text) == 0

    def __lt__(self, other: "_RpmCmp") -> bool:
        return _rpmvercmp(self.text, other.text) < 0

    def __hash__(self) -> int:  # pragma: no cover - comparison-only wrapper
        return hash(self.text)


_KEYS = {
    "semver": _semver_key,
    "python": _pep440_key,
    "go": _semver_key,
    "rpm": _rpm_key,
}


def _key(version: str, ecosystem: str) -> tuple:
    try:
        return _KEYS[ecosystem](version)
    except KeyError:
        raise ValueError(f"unknown ecosystem: {ecosystem!r}") from None


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def compare(version_a: str, version_b: str, ecosystem: str = "semver") -> int:
    """Compare two versions: -1 if a < b, 0 if equal, 1 if a > b."""
    eco = normalize_ecosystem(ecosystem)
    key_a, key_b = _key(version_a, eco), _key(version_b, eco)
    if key_a == key_b:
        return 0
    return -1 if key_a < key_b else 1


_CONSTRAINT_RE = re.compile(r"^(>=|<=|!=|==|>|<|=)\s*(.+)$")


def _matches(version: str, operator: str, target: str, eco: str) -> bool:
    cmp = compare(version, target, eco)
    if operator in (">=",):
        return cmp >= 0
    if operator in ("<=",):
        return cmp <= 0
    if operator in (">",):
        return cmp > 0
    if operator in ("<",):
        return cmp < 0
    if operator in ("!=",):
        return cmp != 0
    return cmp == 0  # = and ==


def in_range(version: str, range_spec: str, ecosystem: str = "semver") -> bool:
    """Evaluate a comma-separated conjunction of version constraints.

    Constraints: ``< x``, ``> x``, ``<= x``, ``>= x``, ``!= x``, ``= x``,
    ``1.2.*`` wildcards, or a bare version for exact equality. All
    constraints must hold. Raises ValueError for an empty or unparsable
    spec; callers decide how to surface that.
    """
    eco = normalize_ecosystem(ecosystem)
    spec = range_spec.strip()
    if not spec:
        raise ValueError("empty range specification")
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if token.endswith(".*"):
            prefix = token[:-2]
            if not version.startswith(prefix + ".") and version != prefix:
                return False
            continue
        match = _CONSTRAINT_RE.match(token)
        if match:
            operator, target = match.group(1), match.group(2).strip()
            if not _matches(version, operator, target, eco):
                return False
            continue
        # Bare version: exact equality.
        if compare(version, token, eco) != 0:
            return False
    return True


def fixes(upgrade: str, fixed_in: str, ecosystem: str = "semver") -> bool:
    """Whether upgrading to ``upgrade`` reaches the fixed version."""
    return compare(upgrade, fixed_in, ecosystem) >= 0
