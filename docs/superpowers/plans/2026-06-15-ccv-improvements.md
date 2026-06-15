# CCV Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add claim chaining, caching, custom claim types, batch verification, CLI, and evaluation framework to the CodeClaimVerifier library.

**Architecture:** Extract a `VerificationEngine` class that owns the verifier registry, grep/verifier caches, and dependency graph. `CodeClaimVerifier` stays thin (API surface). Grep moves to its own module with contextvars-based caching. CLI uses argparse with optional LLM providers. Eval framework ships as a subpackage.

**Tech Stack:** Python 3.11+ stdlib only (zero external deps for core). Optional: `anthropic`, `openai` SDKs for CLI providers.

**Spec:** `docs/superpowers/specs/2026-06-15-ccv-improvements-design.md`

---

## File Structure

### New Files
| File | Responsibility |
|------|---------------|
| `code_claim_verifier/grep.py` | Grep subprocess wrapper with contextvars cache |
| `code_claim_verifier/engine.py` | VerificationEngine: registry, caching, dependency graph, topological sort, SUSPECT propagation |
| `code_claim_verifier/__main__.py` | CLI entry point (`python -m code_claim_verifier`) |
| `code_claim_verifier/cli.py` | Argparse subcommands: verify, verify-batch, list-types, eval |
| `code_claim_verifier/tools.py` | `.as_tools()` / `.default_tools()` tool schema generation |
| `code_claim_verifier/providers/__init__.py` | Provider protocol and loader |
| `code_claim_verifier/providers/anthropic_provider.py` | Anthropic SDK wrapper |
| `code_claim_verifier/providers/openai_provider.py` | OpenAI SDK wrapper |
| `code_claim_verifier/eval/__init__.py` | Eval package exports |
| `code_claim_verifier/eval/runner.py` | Orchestrates extraction, verification, calibration stages |
| `code_claim_verifier/eval/extraction_eval.py` | Stage 1: extraction precision/recall |
| `code_claim_verifier/eval/verification_eval.py` | Stage 2: verification accuracy, confusion matrix |
| `code_claim_verifier/eval/calibration_eval.py` | Stage 3: per-type accuracy, ECE |
| `code_claim_verifier/eval/report.py` | Report generation and formatting |
| `tests/test_grep.py` | Grep module tests |
| `tests/test_engine.py` | VerificationEngine tests |
| `tests/test_calibrator_v2.py` | Calibrator SUSPECT/synthesized tests |
| `tests/test_extractor_v2.py` | Extractor valid_types and batch tests |
| `tests/test_custom_types.py` | Custom claim type registration tests |
| `tests/test_batch.py` | Batch verify tests |
| `tests/test_cli.py` | CLI integration tests |
| `tests/test_tools.py` | Tool schema tests |
| `tests/test_eval.py` | Eval framework tests |
| `tests/fixtures/python_repo/` | Fixture repo for tests |
| `eval/fixtures/python_repo/` | Fixture repo for eval |
| `eval/fixtures/go_repo/` | Go fixture repo for eval |
| `eval/fixtures/ts_repo/` | TS fixture repo for eval |
| `eval/dataset.jsonl` | Evaluation dataset |

### Modified Files
| File | Change |
|------|--------|
| `code_claim_verifier/types.py` | Add `suspect_reason`, `synthesized` fields; update `to_dict()` |
| `code_claim_verifier/calibrator.py` | Filter synthesized, asymmetric SUSPECT weighting |
| `code_claim_verifier/extractor.py` | `valid_types` param, batch extraction, custom hints section |
| `code_claim_verifier/verifiers/__init__.py` | Keep VERIFIER_REGISTRY as default source |
| `code_claim_verifier/verifiers/symbol_claims.py` | Import from `grep.py` |
| `code_claim_verifier/verifiers/import_claims.py` | Import from `grep.py`, fix lockfile matching |
| `code_claim_verifier/verifiers/security_claims.py` | Import from `grep.py` |
| `code_claim_verifier/__init__.py` | Wire engine, add `register()`, `verify_batch()`, `as_tools()` |
| `pyproject.toml` | Optional deps, console_scripts, test deps |

---

## Phase 1: Foundation

### Task 1: Extract grep to its own module with contextvars cache

**Files:**
- Create: `code_claim_verifier/grep.py`
- Create: `tests/test_grep.py`
- Modify: `code_claim_verifier/verifiers/symbol_claims.py`
- Modify: `code_claim_verifier/verifiers/import_claims.py`
- Modify: `code_claim_verifier/verifiers/security_claims.py`

- [ ] **Step 1: Write tests for grep module**

```python
# tests/test_grep.py
import os
import tempfile
from code_claim_verifier.grep import grep, cache_context, reset_cache, _grep_cache


def _make_repo(content_map: dict[str, str]) -> str:
    d = tempfile.mkdtemp()
    for name, content in content_map.items():
        path = os.path.join(d, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
    return d


class TestGrep:
    def test_regex_match(self):
        repo = _make_repo({"a.py": "def foo():\n    pass\n"})
        result = grep(r"def\s+foo", repo)
        assert len(result) == 1
        assert "def foo" in result[0]

    def test_fixed_match(self):
        repo = _make_repo({"a.py": "import os\nimport sys\n"})
        result = grep("import os", repo, fixed=True)
        assert len(result) == 1

    def test_no_match(self):
        repo = _make_repo({"a.py": "x = 1\n"})
        result = grep("nonexistent", repo)
        assert result == []

    def test_cache_returns_same_result(self):
        repo = _make_repo({"a.py": "def foo():\n    pass\n"})
        token = cache_context()
        try:
            r1 = grep(r"def\s+foo", repo)
            r2 = grep(r"def\s+foo", repo)
            assert r1 == r2
        finally:
            reset_cache(token)

    def test_cache_returns_defensive_copy(self):
        repo = _make_repo({"a.py": "def foo():\n    pass\n"})
        token = cache_context()
        try:
            r1 = grep(r"def\s+foo", repo)
            r1.append("mutated")
            r2 = grep(r"def\s+foo", repo)
            assert "mutated" not in r2
        finally:
            reset_cache(token)

    def test_no_cache_by_default(self):
        assert _grep_cache.get() is None

    def test_cache_isolated_after_reset(self):
        token = cache_context()
        reset_cache(token)
        assert _grep_cache.get() is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ugogiordano/workdir/rhoai/code-claim-verifier && python -m pytest tests/test_grep.py -v`
Expected: ImportError (grep module doesn't exist yet)

- [ ] **Step 3: Implement grep.py**

```python
# code_claim_verifier/grep.py
from __future__ import annotations

import contextvars
import subprocess

_grep_cache: contextvars.ContextVar[dict[tuple[str, str, bool], list[str]] | None] = (
    contextvars.ContextVar('_grep_cache', default=None)
)


def grep(pattern: str, path: str, fixed: bool = False) -> list[str]:
    cache = _grep_cache.get()
    if cache is not None:
        key = (pattern, path, fixed)
        if key in cache:
            return list(cache[key])
        result = _run_grep(pattern, path, fixed)
        cache[key] = result
        return list(result)
    return _run_grep(pattern, path, fixed)


def _run_grep(pattern: str, path: str, fixed: bool = False) -> list[str]:
    cmd = ["grep", "-rn"]
    if fixed:
        cmd.append("-F")
    else:
        cmd.append("-E")
    cmd.extend([pattern, path])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip().split("\n")
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def cache_context() -> contextvars.Token:
    return _grep_cache.set({})


def reset_cache(token: contextvars.Token) -> None:
    _grep_cache.reset(token)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_grep.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Update verifier imports**

In `code_claim_verifier/verifiers/symbol_claims.py`, replace the `_grep` function definition (lines 10-24) with an import:

```python
# Remove the entire _grep function definition and the subprocess import.
# Replace with:
from code_claim_verifier.grep import grep as _grep
```

Keep `import subprocess` removal and add the import. The function is aliased to `_grep` so all call sites remain unchanged.

In `code_claim_verifier/verifiers/import_claims.py`, change line 8:
```python
# OLD: from code_claim_verifier.verifiers.symbol_claims import _grep
# NEW:
from code_claim_verifier.grep import grep as _grep
```

In `code_claim_verifier/verifiers/security_claims.py`, change line 5:
```python
# OLD: from code_claim_verifier.verifiers.symbol_claims import _grep
# NEW:
from code_claim_verifier.grep import grep as _grep
```

- [ ] **Step 6: Run existing verifier tests to ensure no regression**

Run: `python -m pytest tests/ -v` (if tests exist), or run: `python -c "from code_claim_verifier.verifiers import safe_verify; print('imports OK')"`
Expected: No import errors

- [ ] **Step 7: Commit**

```bash
git add code_claim_verifier/grep.py tests/test_grep.py code_claim_verifier/verifiers/symbol_claims.py code_claim_verifier/verifiers/import_claims.py code_claim_verifier/verifiers/security_claims.py
git commit -m "refactor: extract grep to own module with contextvars cache"
```

---

### Task 2: Update types and fix lockfile matching

**Files:**
- Modify: `code_claim_verifier/types.py`
- Modify: `code_claim_verifier/verifiers/import_claims.py`
- Create: `tests/test_types.py`

- [ ] **Step 1: Write tests for new type fields and to_dict**

```python
# tests/test_types.py
from code_claim_verifier.types import TypedClaim, VerifiedClaim, VerificationReport


class TestVerifiedClaimFields:
    def test_defaults(self):
        claim = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "a.py"}, source_sentence="test")
        vc = VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.99, evidence="exists", method="os.path.isfile")
        assert vc.suspect_reason is None
        assert vc.synthesized is False

    def test_suspect_reason(self):
        claim = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "a.py"}, source_sentence="test")
        vc = VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.99, evidence="exists", method="test", suspect_reason="FILE_EXISTS was REFUTED")
        assert vc.suspect_reason == "FILE_EXISTS was REFUTED"

    def test_synthesized(self):
        claim = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "a.py"}, source_sentence="")
        vc = VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.99, evidence="exists", method="test", synthesized=True)
        assert vc.synthesized is True


class TestToDictIncludesNewFields:
    def test_suspect_reason_in_dict(self):
        claim = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "a.py"}, source_sentence="test")
        vc = VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.99, evidence="exists", method="test", suspect_reason="dep failed")
        report = VerificationReport(
            total_claims=1, verifiable_claims=1, verified=1, refuted=0,
            unverifiable=0, errored=0, verification_rate=1.0, hallucination_rate=0.0,
            calibrated_confidence=1.0, action="BOOST", reason="1/1", per_claim=[vc],
        )
        d = report.to_dict()
        assert d["claims"][0]["suspect_reason"] == "dep failed"
        assert d["claims"][0]["synthesized"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_types.py -v`
Expected: TypeError (suspect_reason, synthesized not accepted)

- [ ] **Step 3: Update types.py**

Add two fields to `VerifiedClaim`:

```python
@dataclass
class VerifiedClaim:
    claim: TypedClaim
    verdict: Verdict
    method_confidence: float
    evidence: str
    method: str
    error: str | None = None
    suspect_reason: str | None = None
    synthesized: bool = False
```

Update `to_dict()` in `VerificationReport` to include the new fields in each claim dict:

```python
"claims": [
    {
        "type": vc.claim.claim_type,
        "params": vc.claim.parameters,
        "source": vc.claim.source_sentence,
        "verdict": vc.verdict,
        "confidence": vc.method_confidence,
        "evidence": vc.evidence[:500],
        "method": vc.method,
        "suspect_reason": vc.suspect_reason,
        "synthesized": vc.synthesized,
    }
    for vc in self.per_claim
],
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_types.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Fix lockfile substring matching in import_claims.py**

In `_parse_go_sum`, change line 75:
```python
# OLD: if len(parts) >= 2 and package in parts[0]:
# NEW:
if len(parts) >= 2 and (parts[0] == package or parts[0].endswith("/" + package)):
```

In `_parse_go_mod`, change line 87:
```python
# OLD: if package in line and not line.startswith("//"):
# NEW:
if not line.startswith("//"):
    parts = line.split()
    if len(parts) >= 2 and (parts[0] == package or parts[0].endswith("/" + package)):
```

Note: this requires restructuring the `_parse_go_mod` loop body slightly. The full replacement for lines 85-90:

```python
def _parse_go_mod(path: str, package: str) -> str | None:
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("//"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and (parts[0] == package or parts[0].endswith("/" + package)):
                    return parts[-1].lstrip("v")
    except Exception:
        pass
    return None
```

- [ ] **Step 6: Run all tests**

Run: `python -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add code_claim_verifier/types.py code_claim_verifier/verifiers/import_claims.py tests/test_types.py
git commit -m "feat: add suspect_reason and synthesized fields to VerifiedClaim, fix lockfile matching"
```

---

### Task 3: Update calibrator for SUSPECT weighting and synthesized filtering

**Files:**
- Modify: `code_claim_verifier/calibrator.py`
- Create: `tests/test_calibrator_v2.py`

- [ ] **Step 1: Write tests for the updated calibrator**

```python
# tests/test_calibrator_v2.py
from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.calibrator import calibrate


def _claim(ctype="FILE_EXISTS", params=None):
    return TypedClaim(claim_type=ctype, parameters=params or {"path": "a.py"}, source_sentence="test")


def _vc(verdict="VERIFIED", confidence=0.85, suspect_reason=None, synthesized=False):
    return VerifiedClaim(
        claim=_claim(), verdict=verdict, method_confidence=confidence,
        evidence="test", method="test", suspect_reason=suspect_reason,
        synthesized=synthesized,
    )


class TestSynthesizedExclusion:
    def test_synthesized_excluded_from_counts(self):
        claims = [_vc("VERIFIED", 0.99), _vc("VERIFIED", 0.99, synthesized=True)]
        report = calibrate(claims)
        assert report.total_claims == 1
        assert report.verified == 1
        assert report.verifiable_claims == 1

    def test_synthesized_still_in_per_claim(self):
        claims = [_vc("VERIFIED", 0.99), _vc("VERIFIED", 0.99, synthesized=True)]
        report = calibrate(claims)
        assert len(report.per_claim) == 2

    def test_all_synthesized_returns_no_change(self):
        claims = [_vc("VERIFIED", 0.99, synthesized=True)]
        report = calibrate(claims)
        assert report.action == "NO_CHANGE"
        assert report.total_claims == 0


class TestSuspectWeighting:
    def test_suspect_verified_lowers_rate(self):
        normal = _vc("VERIFIED", 0.85)
        suspect = _vc("VERIFIED", 0.85, suspect_reason="dep failed")
        report_normal = calibrate([normal, _vc("VERIFIED", 0.85)])
        report_suspect = calibrate([normal, suspect])
        assert report_suspect.verification_rate < report_normal.verification_rate

    def test_suspect_verified_asymmetric(self):
        suspect = _vc("VERIFIED", 0.80, suspect_reason="dep REFUTED")
        report = calibrate([suspect])
        # weighted_total = 0.80, weighted_verified = 0.80 * 0.5 = 0.40
        # rate = 0.40 / 0.80 = 0.50
        assert report.verification_rate == 0.5

    def test_suspect_refuted_no_special_treatment(self):
        refuted = _vc("REFUTED", 0.85)
        suspect_refuted = _vc("REFUTED", 0.85, suspect_reason="dep failed")
        r1 = calibrate([_vc("VERIFIED", 0.85), refuted])
        r2 = calibrate([_vc("VERIFIED", 0.85), suspect_refuted])
        assert r1.verification_rate == r2.verification_rate


class TestActionThresholds:
    def test_boost_above_80(self):
        claims = [_vc("VERIFIED", 0.90)] * 5
        assert calibrate(claims).action == "BOOST"

    def test_flag_between_50_80(self):
        claims = [_vc("VERIFIED", 0.85), _vc("REFUTED", 0.85)]
        assert calibrate(claims).action == "FLAG"

    def test_override_below_50(self):
        claims = [_vc("REFUTED", 0.85)] * 3
        assert calibrate(claims).action == "OVERRIDE"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_calibrator_v2.py -v`
Expected: FAIL (synthesized filtering and suspect weighting not implemented)

- [ ] **Step 3: Rewrite calibrator.py**

```python
# code_claim_verifier/calibrator.py
from code_claim_verifier.types import VerifiedClaim, VerificationReport


def calibrate(verified_claims: list[VerifiedClaim]) -> VerificationReport:
    real_claims = [c for c in verified_claims if not c.synthesized]

    if not real_claims:
        return VerificationReport(
            total_claims=0, verifiable_claims=0, verified=0, refuted=0,
            unverifiable=0, errored=0, verification_rate=0.0,
            hallucination_rate=0.0, calibrated_confidence=0.0,
            action="NO_CHANGE", reason="no claims extracted",
            per_claim=verified_claims,
        )

    verifiable = [c for c in real_claims if c.verdict != "UNVERIFIABLE"]
    verified = [c for c in verifiable if c.verdict == "VERIFIED"]
    refuted = [c for c in verifiable if c.verdict == "REFUTED"]
    errored = sum(1 for c in real_claims if c.error)

    if not verifiable:
        return VerificationReport(
            total_claims=len(real_claims),
            verifiable_claims=0, verified=0, refuted=0,
            unverifiable=len(real_claims), errored=errored,
            verification_rate=0.0, hallucination_rate=0.0,
            calibrated_confidence=0.0,
            action="NO_CHANGE", reason="no verifiable claims",
            per_claim=verified_claims,
        )

    weighted_verified = 0.0
    weighted_total = 0.0
    for c in verifiable:
        weighted_total += c.method_confidence
        if c.verdict == "VERIFIED":
            factor = 0.5 if c.suspect_reason else 1.0
            weighted_verified += c.method_confidence * factor

    rate = weighted_verified / weighted_total if weighted_total > 0 else 0.0

    if rate >= 0.8:
        action = "BOOST"
    elif rate >= 0.5:
        action = "FLAG"
    else:
        action = "OVERRIDE"

    return VerificationReport(
        total_claims=len(real_claims),
        verifiable_claims=len(verifiable),
        verified=len(verified),
        refuted=len(refuted),
        unverifiable=len(real_claims) - len(verifiable),
        errored=errored,
        verification_rate=round(rate, 2),
        hallucination_rate=round(1 - rate, 2),
        calibrated_confidence=round(rate, 2),
        action=action,
        reason=f"{len(verified)}/{len(verifiable)} claims verified",
        per_claim=verified_claims,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_calibrator_v2.py -v`
Expected: All 9 tests PASS

- [ ] **Step 5: Commit**

```bash
git add code_claim_verifier/calibrator.py tests/test_calibrator_v2.py
git commit -m "feat: calibrator filters synthesized claims, asymmetric SUSPECT weighting"
```

---

### Task 4: Update extractor for valid_types and custom hint section

**Files:**
- Modify: `code_claim_verifier/extractor.py`
- Create: `tests/test_extractor_v2.py`

- [ ] **Step 1: Write tests for valid_types and hint separation**

```python
# tests/test_extractor_v2.py
from code_claim_verifier.extractor import extract_claims, _parse_extraction_output
from code_claim_verifier.types import CLAIM_TYPES


class TestValidTypes:
    def test_parse_rejects_unknown_types_by_default(self):
        raw = '[{"claim_type": "CUSTOM_TYPE", "parameters": {}, "source_sentence": "test"}]'
        result = _parse_extraction_output(raw)
        assert len(result) == 0

    def test_parse_accepts_custom_type_when_provided(self):
        raw = '[{"claim_type": "CUSTOM_TYPE", "parameters": {}, "source_sentence": "test"}]'
        result = _parse_extraction_output(raw, valid_types=frozenset(CLAIM_TYPES | {"CUSTOM_TYPE"}))
        assert len(result) == 1
        assert result[0].claim_type == "CUSTOM_TYPE"

    def test_parse_still_accepts_builtins(self):
        raw = '[{"claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}, "source_sentence": "test"}]'
        result = _parse_extraction_output(raw)
        assert len(result) == 1


class TestCustomHintSection:
    def test_extraction_includes_custom_hints(self):
        calls = []
        def mock_llm(system, user):
            calls.append(system)
            return "[]"

        extract_claims(
            reasoning="test reasoning",
            evidence={},
            llm_function=mock_llm,
            domain_context="security triage",
            custom_hints=["DATABASE_QUERY: {pattern: str} - checks SQL patterns"],
        )
        assert "CUSTOM CLAIM TYPES:" in calls[0]
        assert "DATABASE_QUERY" in calls[0]

    def test_extraction_without_hints(self):
        calls = []
        def mock_llm(system, user):
            calls.append(system)
            return "[]"

        extract_claims(reasoning="test", evidence={}, llm_function=mock_llm)
        assert "CUSTOM CLAIM TYPES:" not in calls[0]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_extractor_v2.py -v`
Expected: FAIL (valid_types param and custom_hints not implemented)

- [ ] **Step 3: Update extractor.py**

Update `_parse_extraction_output` signature to accept `valid_types`:

```python
def _parse_extraction_output(raw: str, valid_types: frozenset[str] = CLAIM_TYPES) -> list[TypedClaim]:
```

Change line 100 (`if claim_type not in CLAIM_TYPES:`) to:
```python
        if claim_type not in valid_types:
```

Update `extract_claims` signature to accept `custom_hints` and `valid_types`:

```python
def extract_claims(
    reasoning: str,
    evidence: dict[str, Any],
    llm_function: LLMFunction,
    domain_context: str = "",
    custom_hints: list[str] | None = None,
    valid_types: frozenset[str] = CLAIM_TYPES,
) -> list[TypedClaim]:
```

After building the system prompt, append custom hints section if provided:

```python
    system = _EXTRACTION_SYSTEM.format(domain_context=domain_context)
    if custom_hints:
        hints_section = "\n\nCUSTOM CLAIM TYPES:\n" + "\n".join(f"- {h}" for h in custom_hints)
        system += hints_section
```

Pass `valid_types` to `_parse_extraction_output`:

```python
    return _parse_extraction_output(raw, valid_types=valid_types)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_extractor_v2.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add code_claim_verifier/extractor.py tests/test_extractor_v2.py
git commit -m "feat: extractor accepts valid_types and custom_hints parameters"
```

---

## Phase 2: VerificationEngine

### Task 5: VerificationEngine core (registry + cached verification)

**Files:**
- Create: `code_claim_verifier/engine.py`
- Create: `tests/test_engine.py`
- Create: `tests/fixtures/python_repo/` (test fixture)

- [ ] **Step 1: Create test fixture repo**

```bash
mkdir -p tests/fixtures/python_repo
```

Create `tests/fixtures/python_repo/main.py`:
```python
import os

def load_model(path):
    with open(path) as f:
        return f.read()

def process(data):
    return load_model(data)
```

Create `tests/fixtures/python_repo/utils.py`:
```python
def helper():
    return 42

def unused_function():
    pass
```

Create `tests/fixtures/python_repo/requirements.txt`:
```
torch==2.1.0
numpy==1.24.0
```

- [ ] **Step 2: Write tests for engine core**

```python
# tests/test_engine.py
import os
import dataclasses
from code_claim_verifier.engine import VerificationEngine, _freeze
from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.verifiers import VERIFIER_REGISTRY

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "python_repo")


class TestFreeze:
    def test_flat_dict(self):
        result = _freeze({"a": 1, "b": 2})
        assert isinstance(result, frozenset)

    def test_nested_dict(self):
        result = _freeze({"a": {"b": 1}})
        assert isinstance(result, frozenset)

    def test_list(self):
        result = _freeze([1, 2, 3])
        assert result == (1, 2, 3)

    def test_set(self):
        result = _freeze({1, 2})
        assert isinstance(result, frozenset)

    def test_depth_cap(self):
        nested = {"a": 1}
        for _ in range(25):
            nested = {"x": nested}
        result = _freeze(nested)
        assert result is not None


class TestEngineRegistry:
    def test_default_registry_has_all_builtins(self):
        engine = VerificationEngine()
        assert "FILE_EXISTS" in engine.registry
        assert "FUNCTION_CALLED" in engine.registry
        assert len(engine.registry) == len(VERIFIER_REGISTRY)

    def test_register_custom_type(self):
        engine = VerificationEngine()
        def my_verifier(claim, repo_path, language):
            return VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.90,
                                 evidence="custom", method="custom")
        engine.register("CUSTOM_CHECK", my_verifier)
        assert "CUSTOM_CHECK" in engine.registry

    def test_register_duplicate_raises(self):
        engine = VerificationEngine()
        import pytest
        with pytest.raises(ValueError):
            engine.register("FILE_EXISTS", lambda c, r, l: None)


class TestEngineVerification:
    def test_verify_single_claim(self):
        engine = VerificationEngine()
        claim = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "main.py"}, source_sentence="test")
        results = engine.verify_claims([claim], FIXTURE, "python")
        assert len(results) == 1
        assert results[0].verdict == "VERIFIED"

    def test_verify_uses_cache(self):
        engine = VerificationEngine()
        claim1 = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "main.py"}, source_sentence="s1")
        claim2 = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "main.py"}, source_sentence="s2")
        results = engine.verify_claims([claim1, claim2], FIXTURE, "python")
        assert len(results) == 2
        assert results[0].verdict == results[1].verdict

    def test_cached_result_is_independent_copy(self):
        engine = VerificationEngine()
        claim1 = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "main.py"}, source_sentence="s1")
        claim2 = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "main.py"}, source_sentence="s2")
        results = engine.verify_claims([claim1, claim2], FIXTURE, "python")
        results[0].suspect_reason = "mutated"
        assert results[1].suspect_reason is None
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/test_engine.py -v`
Expected: ImportError (engine module doesn't exist)

- [ ] **Step 4: Implement engine.py (core: registry + cached verification)**

```python
# code_claim_verifier/engine.py
from __future__ import annotations

import dataclasses
from typing import Callable

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.verifiers import VERIFIER_REGISTRY, safe_verify
from code_claim_verifier import grep as grep_module

VerifierFunction = Callable[[TypedClaim, str, str], VerifiedClaim]


def _freeze(value, _depth=0):
    if _depth > 20:
        return str(value)
    if isinstance(value, dict):
        return frozenset((k, _freeze(v, _depth + 1)) for k, v in sorted(value.items()))
    if isinstance(value, set):
        return frozenset(_freeze(v, _depth + 1) for v in value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v, _depth + 1) for v in value)
    return value


DependencyRule = tuple[str, str, str, str]  # (dependent_type, prereq_type, source_param, target_param)

BUILTIN_RULES: list[DependencyRule] = [
    ("LINE_CONTENT", "FILE_EXISTS", "path", "path"),
    ("GENERATED_OR_VENDORED", "FILE_EXISTS", "path", "path"),
    ("FUNCTION_EXISTS", "FILE_EXISTS", "file", "path"),
    ("FUNCTION_CALLED", "FUNCTION_EXISTS", "name", "name"),
    ("HAS_CALLERS", "FUNCTION_EXISTS", "name", "name"),
    ("IMPORT_EXISTS", "FILE_EXISTS", "file", "path"),
    ("MITIGATION_EXISTS", "FILE_EXISTS", "file", "path"),
]


class VerificationEngine:
    def __init__(self):
        self.registry: dict[str, VerifierFunction] = dict(VERIFIER_REGISTRY)
        self.dependency_rules: list[DependencyRule] = list(BUILTIN_RULES)
        self._extraction_hints: dict[str, str] = {}

    def register(self, claim_type: str, verifier_fn: VerifierFunction,
                 depends_on: list[tuple[str, str, str]] | None = None):
        if claim_type in self.registry:
            raise ValueError(f"Claim type already registered: {claim_type}")
        self.registry[claim_type] = verifier_fn
        if depends_on:
            for prereq_type, source_param, target_param in depends_on:
                self.register_dependency(claim_type, prereq_type, source_param, target_param)

    def register_dependency(self, claim_type: str, depends_on: str,
                            source_param: str, target_param: str):
        rule = (claim_type, depends_on, source_param, target_param)
        if self._would_create_cycle(rule):
            raise ValueError(f"Dependency {claim_type} -> {depends_on} creates a cycle")
        self.dependency_rules.append(rule)

    def _would_create_cycle(self, new_rule: DependencyRule) -> bool:
        dep_type, prereq_type = new_rule[0], new_rule[1]
        rules = self.dependency_rules + [new_rule]
        visited: set[str] = set()
        def dfs(node: str) -> bool:
            if node == dep_type:
                return True
            if node in visited:
                return False
            visited.add(node)
            for r in rules:
                if r[0] == node:
                    if dfs(r[1]):
                        return True
            return False
        return dfs(prereq_type)

    def verify_claims(self, claims: list[TypedClaim], repo_path: str,
                      language: str) -> list[VerifiedClaim]:
        verifier_cache: dict[tuple, VerifiedClaim] = {}
        token = grep_module.cache_context()
        try:
            results = []
            for claim in claims:
                key = self._cache_key(claim, repo_path, language)
                if key in verifier_cache:
                    cached = verifier_cache[key]
                    copy = dataclasses.replace(cached, suspect_reason=None, synthesized=False)
                    copy.claim = claim
                    results.append(copy)
                else:
                    vc = self._verify_one(claim, repo_path, language)
                    bare = dataclasses.replace(vc, suspect_reason=None, synthesized=False)
                    verifier_cache[key] = bare
                    results.append(vc)
            return results
        finally:
            grep_module.reset_cache(token)

    def _verify_one(self, claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
        verifier = self.registry.get(claim.claim_type)
        if not verifier:
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                evidence=f"Unknown claim type: {claim.claim_type}", method="error",
                error="unknown_type",
            )
        try:
            return verifier(claim, repo_path, language)
        except Exception as e:
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                evidence="", method="error", error=f"{type(e).__name__}: {str(e)[:200]}",
            )

    def _cache_key(self, claim: TypedClaim, repo_path: str, language: str) -> tuple:
        params_frozen = _freeze(claim.parameters)
        return (claim.claim_type, params_frozen, repo_path, language)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_engine.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add code_claim_verifier/engine.py tests/test_engine.py tests/fixtures/
git commit -m "feat: VerificationEngine with registry, caching, and dependency rule infrastructure"
```

---

### Task 6: Dependency graph resolution and SUSPECT propagation

**Files:**
- Modify: `code_claim_verifier/engine.py`
- Modify: `tests/test_engine.py`

- [ ] **Step 1: Write tests for chaining**

Append to `tests/test_engine.py`:

```python
class TestDependencyResolution:
    def test_synthesizes_missing_file_exists(self):
        engine = VerificationEngine()
        claim = TypedClaim(claim_type="LINE_CONTENT",
                           parameters={"path": "main.py", "line": 1, "expected": "import os"},
                           source_sentence="test")
        results = engine.verify_claims_with_chaining([claim], FIXTURE, "python")
        types = [r.claim.claim_type for r in results]
        assert "FILE_EXISTS" in types
        synth = [r for r in results if r.synthesized]
        assert len(synth) == 1

    def test_refuted_dep_marks_dependent_suspect(self):
        engine = VerificationEngine()
        claim = TypedClaim(claim_type="LINE_CONTENT",
                           parameters={"path": "nonexistent.py", "line": 1, "expected": "x"},
                           source_sentence="test")
        results = engine.verify_claims_with_chaining([claim], FIXTURE, "python")
        line_content = [r for r in results if r.claim.claim_type == "LINE_CONTENT"][0]
        assert line_content.suspect_reason is not None
        assert "FILE_EXISTS" in line_content.suspect_reason

    def test_verified_dep_no_suspect(self):
        engine = VerificationEngine()
        claims = [
            TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "main.py"}, source_sentence="s1"),
            TypedClaim(claim_type="LINE_CONTENT",
                       parameters={"path": "main.py", "line": 1, "expected": "import os"},
                       source_sentence="s2"),
        ]
        results = engine.verify_claims_with_chaining(claims, FIXTURE, "python")
        line_content = [r for r in results if r.claim.claim_type == "LINE_CONTENT"][0]
        assert line_content.suspect_reason is None

    def test_no_duplicate_synthesized(self):
        engine = VerificationEngine()
        claims = [
            TypedClaim(claim_type="LINE_CONTENT",
                       parameters={"path": "main.py", "line": 1, "expected": "import os"},
                       source_sentence="s1"),
            TypedClaim(claim_type="GENERATED_OR_VENDORED",
                       parameters={"path": "main.py", "expected": False},
                       source_sentence="s2"),
        ]
        results = engine.verify_claims_with_chaining(claims, FIXTURE, "python")
        file_exists_claims = [r for r in results if r.claim.claim_type == "FILE_EXISTS"]
        assert len(file_exists_claims) == 1

    def test_any_match_semantics(self):
        engine = VerificationEngine()
        claims = [
            TypedClaim(claim_type="FUNCTION_EXISTS",
                       parameters={"name": "load_model", "file": "main.py"}, source_sentence="s1"),
            TypedClaim(claim_type="FUNCTION_EXISTS",
                       parameters={"name": "load_model", "file": "nonexistent.py"}, source_sentence="s2"),
            TypedClaim(claim_type="FUNCTION_CALLED",
                       parameters={"name": "load_model", "expected": True}, source_sentence="s3"),
        ]
        results = engine.verify_claims_with_chaining(claims, FIXTURE, "python")
        func_called = [r for r in results if r.claim.claim_type == "FUNCTION_CALLED"][0]
        assert func_called.suspect_reason is None

    def test_cycle_detection_custom_deps(self):
        engine = VerificationEngine()
        def noop(c, r, l):
            return VerifiedClaim(claim=c, verdict="VERIFIED", method_confidence=0.5,
                                 evidence="", method="noop")
        engine.register("TYPE_A", noop)
        engine.register("TYPE_B", noop)
        engine.register_dependency("TYPE_A", "TYPE_B", "x", "x")
        import pytest
        with pytest.raises(ValueError, match="cycle"):
            engine.register_dependency("TYPE_B", "TYPE_A", "x", "x")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_engine.py::TestDependencyResolution -v`
Expected: FAIL (verify_claims_with_chaining doesn't exist)

- [ ] **Step 3: Implement dependency resolution in engine.py**

Add `verify_claims_with_chaining` method to `VerificationEngine`:

```python
    def verify_claims_with_chaining(self, claims: list[TypedClaim], repo_path: str,
                                     language: str) -> list[VerifiedClaim]:
        verifier_cache: dict[tuple, VerifiedClaim] = {}
        token = grep_module.cache_context()
        try:
            all_claims, edges, synthesized_ids = self._build_dependency_graph(claims, repo_path)
            ordered = self._topological_sort(all_claims, edges)

            verified_map: dict[str, VerifiedClaim] = {}
            for claim in ordered:
                key = self._cache_key(claim, repo_path, language)
                if key in verifier_cache:
                    cached = verifier_cache[key]
                    vc = dataclasses.replace(cached,
                                             suspect_reason=None,
                                             synthesized=claim.id in synthesized_ids)
                    vc.claim = claim
                else:
                    vc = self._verify_one(claim, repo_path, language)
                    vc.synthesized = claim.id in synthesized_ids
                    bare = dataclasses.replace(vc, suspect_reason=None, synthesized=False)
                    verifier_cache[key] = bare

                verified_map[claim.id] = vc

            self._propagate_suspect(verified_map, edges)
            return list(verified_map.values())
        finally:
            grep_module.reset_cache(token)

    def _build_dependency_graph(self, claims: list[TypedClaim],
                                 repo_path: str) -> tuple[list[TypedClaim], dict[str, list[str]], set[str]]:
        all_claims = list(claims)
        edges: dict[str, list[str]] = {}
        synthesized_ids: set[str] = set()
        synth_index: dict[tuple, TypedClaim] = {}
        visited_synthesis: set[tuple] = set()

        for _ in range(3):  # max depth 2 + initial pass
            new_synth = []
            for rule_dep, rule_prereq, src_param, tgt_param in self.dependency_rules:
                for claim in all_claims:
                    if claim.claim_type != rule_dep:
                        continue
                    src_value = claim.parameters.get(src_param)
                    if src_value is None:
                        continue
                    if rule_dep == "FUNCTION_EXISTS" and src_param == "file" and not claim.parameters.get("file"):
                        continue

                    prereq_key = (rule_prereq, tgt_param, src_value)
                    existing = self._find_matching_prereq(all_claims, rule_prereq, tgt_param, src_value)

                    if existing:
                        edges.setdefault(claim.id, []).append(existing.id)
                    elif prereq_key not in visited_synthesis:
                        visited_synthesis.add(prereq_key)
                        if prereq_key in synth_index:
                            synth = synth_index[prereq_key]
                        else:
                            synth = TypedClaim(
                                claim_type=rule_prereq,
                                parameters={tgt_param: src_value},
                                source_sentence="",
                            )
                            synth_index[prereq_key] = synth
                            synthesized_ids.add(synth.id)
                            new_synth.append(synth)
                        edges.setdefault(claim.id, []).append(synth.id)

            all_claims.extend(new_synth)
            if not new_synth:
                break

        return all_claims, edges, synthesized_ids

    def _find_matching_prereq(self, claims: list[TypedClaim], prereq_type: str,
                               param_name: str, param_value) -> TypedClaim | None:
        for c in claims:
            if c.claim_type == prereq_type and c.parameters.get(param_name) == param_value:
                return c
        return None

    def _topological_sort(self, claims: list[TypedClaim],
                           edges: dict[str, list[str]]) -> list[TypedClaim]:
        id_to_claim = {c.id: c for c in claims}
        in_degree: dict[str, int] = {c.id: 0 for c in claims}
        reverse_edges: dict[str, list[str]] = {}

        for dependent_id, prereq_ids in edges.items():
            for prereq_id in prereq_ids:
                if prereq_id in in_degree:
                    in_degree[dependent_id] = in_degree.get(dependent_id, 0) + 1
                    reverse_edges.setdefault(prereq_id, []).append(dependent_id)

        queue = [cid for cid, deg in in_degree.items() if deg == 0]
        ordered = []
        while queue:
            cid = queue.pop(0)
            ordered.append(id_to_claim[cid])
            for dependent_id in reverse_edges.get(cid, []):
                in_degree[dependent_id] -= 1
                if in_degree[dependent_id] == 0:
                    queue.append(dependent_id)

        if len(ordered) < len(claims):
            remaining = [id_to_claim[cid] for cid in in_degree if cid not in {c.id for c in ordered}]
            for c in remaining:
                ordered.append(c)
            return ordered

        return ordered

    def _propagate_suspect(self, verified_map: dict[str, VerifiedClaim],
                            edges: dict[str, list[str]]) -> None:
        for dependent_id, prereq_ids in edges.items():
            if dependent_id not in verified_map:
                continue
            prereqs = [verified_map[pid] for pid in prereq_ids if pid in verified_map]
            if not prereqs:
                continue

            by_type: dict[str, list[VerifiedClaim]] = {}
            for p in prereqs:
                by_type.setdefault(p.claim.claim_type, []).append(p)

            for ptype, group in by_type.items():
                all_refuted = all(p.verdict == "REFUTED" for p in group)
                if all_refuted:
                    refuted_names = ", ".join(f"{p.claim.claim_type}({p.claim.parameters})" for p in group)
                    verified_map[dependent_id].suspect_reason = f"All prerequisites REFUTED: {refuted_names}"
                    break
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_engine.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add code_claim_verifier/engine.py tests/test_engine.py
git commit -m "feat: dependency graph resolution with synthesis, topological sort, SUSPECT propagation"
```

---

## Phase 3: Integration

### Task 7: Wire CodeClaimVerifier to engine, add register and verify_batch

**Files:**
- Modify: `code_claim_verifier/__init__.py`
- Create: `tests/test_integration.py`

- [ ] **Step 1: Write integration tests**

```python
# tests/test_integration.py
import os
from code_claim_verifier import CodeClaimVerifier

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "python_repo")


def mock_llm(system, user):
    return '[{"claim_type": "FILE_EXISTS", "parameters": {"path": "main.py"}, "source_sentence": "main.py exists"}]'


class TestCodeClaimVerifierIntegration:
    def test_verify_basic(self):
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        report = v.verify(reasoning="main.py exists", finding_file="main.py")
        assert report.verified >= 1
        assert report.action in ("BOOST", "FLAG", "OVERRIDE", "NO_CHANGE")

    def test_register_custom_type(self):
        from code_claim_verifier.types import VerifiedClaim, TypedClaim
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)

        def custom_verifier(claim, repo_path, language):
            return VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.90,
                                 evidence="custom", method="custom")

        v.register(
            claim_type="MY_TYPE",
            verifier_fn=custom_verifier,
            extraction_hint="MY_TYPE: {x: str} - custom check",
        )
        assert "MY_TYPE" in v.engine.registry

    def test_register_rejects_builtin_collision(self):
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        import pytest
        with pytest.raises(ValueError):
            v.register("FILE_EXISTS", lambda c, r, l: None, extraction_hint="")

    def test_verify_batch(self):
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        items = [
            {"reasoning": "main.py exists", "evidence": {}, "finding_file": "main.py"},
            {"reasoning": "utils.py exists", "evidence": {}, "finding_file": "utils.py"},
        ]
        reports = v.verify_batch(items=items)
        assert len(reports) == 2
        for r in reports:
            assert r.total_claims >= 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_integration.py -v`
Expected: FAIL (register, verify_batch not implemented)

- [ ] **Step 3: Rewrite __init__.py**

```python
# code_claim_verifier/__init__.py
from code_claim_verifier.types import TypedClaim, VerifiedClaim, VerificationReport, CLAIM_TYPES
from code_claim_verifier.extractor import extract_claims, LLMFunction
from code_claim_verifier.calibrator import calibrate
from code_claim_verifier.engine import VerificationEngine, VerifierFunction
from code_claim_verifier.language import detect_language


class CodeClaimVerifier:
    """Extract typed code claims from LLM reasoning and verify deterministically."""

    def __init__(self, llm_function: LLMFunction, repo_path: str):
        self.llm_function = llm_function
        self.repo_path = repo_path
        self.engine = VerificationEngine()
        self._extraction_hints: list[str] = []

    def register(self, claim_type: str, verifier_fn: VerifierFunction,
                 extraction_hint: str,
                 depends_on: list[tuple[str, str, str]] | None = None):
        if len(extraction_hint) > 500:
            raise ValueError("extraction_hint must be <= 500 characters")
        self.engine.register(claim_type, verifier_fn, depends_on=depends_on)
        if extraction_hint:
            self._extraction_hints.append(extraction_hint)

    def register_dependency(self, claim_type: str, depends_on: str,
                            source_param: str, target_param: str):
        self.engine.register_dependency(claim_type, depends_on, source_param, target_param)

    def verify(self, reasoning: str, evidence: dict | None = None,
               finding_file: str = "", domain_context: str = "") -> VerificationReport:
        language = detect_language(finding_file) if finding_file else "unknown"
        valid_types = frozenset(self.engine.registry.keys())

        claims = extract_claims(
            reasoning, evidence or {}, self.llm_function,
            domain_context=domain_context,
            custom_hints=self._extraction_hints or None,
            valid_types=valid_types,
        )
        if not claims:
            return calibrate([])

        verified = self.engine.verify_claims_with_chaining(claims, self.repo_path, language)
        return calibrate(verified)

    def verify_batch(self, items: list[dict], domain_context: str = "",
                     max_chars_per_batch: int = 6000,
                     batch_fallback: str = "partial") -> list[VerificationReport]:
        reports = []
        valid_types = frozenset(self.engine.registry.keys())

        for item in items:
            reasoning = item.get("reasoning", "")
            evidence = item.get("evidence", {})
            finding_file = item.get("finding_file", "")
            language = detect_language(finding_file) if finding_file else "unknown"

            claims = extract_claims(
                reasoning, evidence, self.llm_function,
                domain_context=domain_context,
                custom_hints=self._extraction_hints or None,
                valid_types=valid_types,
            )
            if not claims:
                reports.append(calibrate([]))
                continue

            verified = self.engine.verify_claims_with_chaining(claims, self.repo_path, language)
            reports.append(calibrate(verified))

        return reports


__all__ = [
    "CodeClaimVerifier",
    "TypedClaim", "VerifiedClaim", "VerificationReport",
    "CLAIM_TYPES", "extract_claims", "calibrate",
]
```

Note: This initial `verify_batch` does per-item extraction (not adaptive batching). Batch extraction optimization is added in Task 8.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_integration.py -v`
Expected: All tests PASS

- [ ] **Step 5: Run all tests**

Run: `python -m pytest tests/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add code_claim_verifier/__init__.py tests/test_integration.py
git commit -m "feat: wire CodeClaimVerifier to VerificationEngine, add register and verify_batch"
```

---

### Task 8: Batch extraction with adaptive batching

**Files:**
- Modify: `code_claim_verifier/extractor.py`
- Modify: `code_claim_verifier/__init__.py`
- Create: `tests/test_batch.py`

- [ ] **Step 1: Write tests for batch extraction**

```python
# tests/test_batch.py
from code_claim_verifier.extractor import extract_claims_batch, _build_batch_prompt


class TestBuildBatchPrompt:
    def test_single_item(self):
        items = [{"reasoning": "file exists", "evidence": {}, "finding_file": "a.py"}]
        prompt = _build_batch_prompt(items)
        assert "<<<FINDING_0:a.py>>>" in prompt
        assert "file exists" in prompt

    def test_multiple_items(self):
        items = [
            {"reasoning": "first", "evidence": {}, "finding_file": "a.py"},
            {"reasoning": "second", "evidence": {}, "finding_file": "b.py"},
        ]
        prompt = _build_batch_prompt(items)
        assert "<<<FINDING_0:a.py>>>" in prompt
        assert "<<<FINDING_1:b.py>>>" in prompt


class TestExtractClaimsBatch:
    def test_assigns_finding_index(self):
        def mock_llm(system, user):
            return '[{"finding_index": 0, "claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}, "source_sentence": "test"}]'

        items = [{"reasoning": "a.py exists", "evidence": {}, "finding_file": "a.py"}]
        result = extract_claims_batch(items, mock_llm)
        assert len(result) == 1
        assert 0 in result
        assert len(result[0]) == 1

    def test_discards_out_of_range_index(self):
        def mock_llm(system, user):
            return '[{"finding_index": 99, "claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}, "source_sentence": "test"}]'

        items = [{"reasoning": "test", "evidence": {}, "finding_file": "a.py"}]
        result = extract_claims_batch(items, mock_llm)
        assert len(result.get(0, [])) == 0

    def test_partial_recovery(self):
        def mock_llm(system, user):
            return """[
                {"finding_index": 0, "claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}, "source_sentence": "s1"},
                {"claim_type": "FILE_EXISTS", "parameters": {"path": "b.py"}, "source_sentence": "s2"}
            ]"""

        items = [
            {"reasoning": "a.py exists", "evidence": {}, "finding_file": "a.py"},
            {"reasoning": "b.py exists", "evidence": {}, "finding_file": "b.py"},
        ]
        result = extract_claims_batch(items, mock_llm, fallback="skip")
        assert len(result.get(0, [])) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_batch.py -v`
Expected: ImportError

- [ ] **Step 3: Add batch extraction to extractor.py**

Append to `code_claim_verifier/extractor.py`:

```python
_BATCH_EXTRACTION_SYSTEM = _EXTRACTION_SYSTEM + """

Multiple findings are provided, each delimited by <<<FINDING_N:filename>>>.
Include "finding_index": N in each extracted claim to indicate which finding it belongs to.
"""


def _build_batch_prompt(items: list[dict]) -> str:
    parts = []
    for i, item in enumerate(items):
        finding_file = item.get("finding_file", "unknown")
        reasoning = item.get("reasoning", "")[:4000]
        evidence_str = json.dumps(item.get("evidence", {}), indent=2, default=str)[:3000]
        parts.append(f"<<<FINDING_{i}:{finding_file}>>>\nReasoning: {reasoning}\nEvidence: {evidence_str}")
    return "\n\n".join(parts)


def extract_claims_batch(
    items: list[dict],
    llm_function: LLMFunction,
    domain_context: str = "",
    custom_hints: list[str] | None = None,
    valid_types: frozenset[str] = CLAIM_TYPES,
    fallback: str = "partial",
) -> dict[int, list[TypedClaim]]:
    if not items:
        return {}

    system = _BATCH_EXTRACTION_SYSTEM.format(domain_context=domain_context)
    if custom_hints:
        system += "\n\nCUSTOM CLAIM TYPES:\n" + "\n".join(f"- {h}" for h in custom_hints)

    user_prompt = _build_batch_prompt(items)

    try:
        raw = llm_function(system, user_prompt)
    except Exception as e:
        logger.warning("Batch extraction LLM call failed: %s", e)
        return {i: [] for i in range(len(items))}

    return _parse_batch_output(raw, len(items), valid_types, fallback)


def _parse_batch_output(
    raw: str, num_items: int,
    valid_types: frozenset[str],
    fallback: str,
) -> dict[int, list[TypedClaim]]:
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1:
        return {i: [] for i in range(num_items)}

    try:
        items_parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return {i: [] for i in range(num_items)}

    result: dict[int, list[TypedClaim]] = {i: [] for i in range(num_items)}
    assigned = 0
    total = 0

    for item in items_parsed:
        if not isinstance(item, dict):
            continue
        claim_type = item.get("claim_type", "")
        if claim_type not in valid_types:
            continue
        total += 1

        finding_index = item.get("finding_index")
        if finding_index is not None:
            try:
                finding_index = int(finding_index)
            except (ValueError, TypeError):
                finding_index = None

        if finding_index is not None and 0 <= finding_index < num_items:
            claim = TypedClaim(
                claim_type=claim_type,
                parameters=item.get("parameters", {}),
                source_sentence=item.get("source_sentence", "")[:500],
            )
            result[finding_index].append(claim)
            assigned += 1
        elif fallback == "skip":
            continue

    if total > 0 and assigned < total * 0.5 and fallback == "partial":
        return {i: [] for i in range(num_items)}

    return result
```

- [ ] **Step 4: Update verify_batch in __init__.py to use batch extraction**

Replace the `verify_batch` method body with adaptive batching support. For now, use per-item as the default and batch extraction when items fit:

```python
    def verify_batch(self, items: list[dict], domain_context: str = "",
                     max_chars_per_batch: int = 6000,
                     batch_fallback: str = "partial") -> list[VerificationReport]:
        from code_claim_verifier.extractor import extract_claims_batch
        valid_types = frozenset(self.engine.registry.keys())

        batches = self._group_into_batches(items, max_chars_per_batch)
        all_claims: dict[int, list[TypedClaim]] = {}

        for batch_items, batch_offset in batches:
            if len(batch_items) == 1:
                reasoning = batch_items[0].get("reasoning", "")
                evidence = batch_items[0].get("evidence", {})
                claims = extract_claims(
                    reasoning, evidence, self.llm_function,
                    domain_context=domain_context,
                    custom_hints=self._extraction_hints or None,
                    valid_types=valid_types,
                )
                all_claims[batch_offset] = claims
            else:
                batch_result = extract_claims_batch(
                    batch_items, self.llm_function,
                    domain_context=domain_context,
                    custom_hints=self._extraction_hints or None,
                    valid_types=valid_types,
                    fallback=batch_fallback,
                )
                for local_idx, claims in batch_result.items():
                    all_claims[batch_offset + local_idx] = claims

        reports = []
        from code_claim_verifier import grep as grep_module
        token = grep_module.cache_context()
        try:
            for i, item in enumerate(items):
                finding_file = item.get("finding_file", "")
                language = detect_language(finding_file) if finding_file else "unknown"
                claims = all_claims.get(i, [])
                if not claims:
                    reports.append(calibrate([]))
                    continue
                verified = self.engine.verify_claims_with_chaining(claims, self.repo_path, language)
                reports.append(calibrate(verified))
        finally:
            grep_module.reset_cache(token)

        return reports

    @staticmethod
    def _group_into_batches(items: list[dict], max_chars: int) -> list[tuple[list[dict], int]]:
        batches = []
        current_batch: list[dict] = []
        current_len = 0
        batch_start = 0

        for i, item in enumerate(items):
            reasoning_len = len(item.get("reasoning", ""))
            if reasoning_len >= max_chars:
                if current_batch:
                    batches.append((current_batch, batch_start))
                batches.append(([item], i))
                current_batch = []
                current_len = 0
                batch_start = i + 1
            elif current_len + reasoning_len > max_chars:
                if current_batch:
                    batches.append((current_batch, batch_start))
                current_batch = [item]
                current_len = reasoning_len
                batch_start = i
            else:
                current_batch.append(item)
                current_len += reasoning_len

        if current_batch:
            batches.append((current_batch, batch_start))

        return batches
```

- [ ] **Step 5: Run tests**

Run: `python -m pytest tests/test_batch.py tests/test_integration.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add code_claim_verifier/extractor.py code_claim_verifier/__init__.py tests/test_batch.py
git commit -m "feat: batch extraction with adaptive batching and partial recovery"
```

---

## Phase 4: CLI and Tool Schemas

### Task 9: CLI infrastructure

**Files:**
- Create: `code_claim_verifier/__main__.py`
- Create: `code_claim_verifier/cli.py`
- Create: `code_claim_verifier/providers/__init__.py`
- Create: `code_claim_verifier/providers/anthropic_provider.py`
- Create: `code_claim_verifier/providers/openai_provider.py`
- Modify: `pyproject.toml`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write CLI tests**

```python
# tests/test_cli.py
import json
import os
import subprocess
import sys

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "python_repo")


class TestListTypes:
    def test_list_types_outputs_json(self):
        result = subprocess.run(
            [sys.executable, "-m", "code_claim_verifier", "list-types"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "FILE_EXISTS" in data
        assert "FUNCTION_CALLED" in data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL (no __main__.py)

- [ ] **Step 3: Implement CLI**

Create `code_claim_verifier/__main__.py`:
```python
from code_claim_verifier.cli import main

if __name__ == "__main__":
    main()
```

Create `code_claim_verifier/cli.py`:
```python
from __future__ import annotations

import argparse
import json
import sys

from code_claim_verifier.types import CLAIM_TYPES
from code_claim_verifier.language import FUNCTION_DEF_PATTERNS, IMPORT_PATTERNS

CLAIM_SCHEMAS = {
    "FILE_EXISTS": {"path": "str"},
    "LINE_CONTENT": {"path": "str", "line": "int", "expected": "str"},
    "FILE_CLASSIFICATION": {"path": "str", "category": "test|fixture|production|vendored"},
    "GENERATED_OR_VENDORED": {"path": "str", "expected": "bool"},
    "FUNCTION_EXISTS": {"name": "str", "file": "str (optional)"},
    "FUNCTION_CALLED": {"name": "str", "expected": "bool"},
    "HAS_CALLERS": {"name": "str", "expected": "bool"},
    "IMPORT_EXISTS": {"module": "str", "file": "str (optional)"},
    "PACKAGE_VERSION": {"package": "str", "version": "str"},
    "DEPENDENCY_TYPE": {"package": "str", "type": "direct|transitive"},
    "CVE_AFFECTS_VERSION": {"cve": "str", "package": "str", "version": "str"},
    "ABSENCE": {"pattern": "str", "scope": "file|directory|repo"},
    "MITIGATION_EXISTS": {"description": "str", "file": "str", "line": "int"},
    "ENTRY_POINT": {"type": "str", "location": "str"},
}


def main():
    parser = argparse.ArgumentParser(prog="code_claim_verifier")
    subparsers = parser.add_subparsers(dest="command")

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--repo", required=True)
    verify_parser.add_argument("--reasoning", default=None)
    verify_parser.add_argument("--finding-file", default="")
    verify_parser.add_argument("--domain-context", default="")
    verify_parser.add_argument("--llm-provider", default="anthropic")
    verify_parser.add_argument("--model", default=None)

    batch_parser = subparsers.add_parser("verify-batch")
    batch_parser.add_argument("--repo", required=True)
    batch_parser.add_argument("--input", default=None)
    batch_parser.add_argument("--domain-context", default="")
    batch_parser.add_argument("--max-items", type=int, default=10000)
    batch_parser.add_argument("--llm-provider", default="anthropic")
    batch_parser.add_argument("--model", default=None)

    subparsers.add_parser("list-types")

    args = parser.parse_args()

    if args.command == "list-types":
        json.dump(CLAIM_SCHEMAS, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.command == "verify":
        _cmd_verify(args)
    elif args.command == "verify-batch":
        _cmd_verify_batch(args)
    else:
        parser.print_help()
        sys.exit(1)


def _get_llm_function(provider: str, model: str | None):
    if provider == "anthropic":
        from code_claim_verifier.providers.anthropic_provider import make_llm_function
        return make_llm_function(model)
    elif provider == "openai":
        from code_claim_verifier.providers.openai_provider import make_llm_function
        return make_llm_function(model)
    else:
        print(f"Unknown provider: {provider}", file=sys.stderr)
        sys.exit(1)


def _cmd_verify(args):
    reasoning = args.reasoning
    if reasoning is None:
        reasoning = sys.stdin.read(102400)

    llm_fn = _get_llm_function(args.llm_provider, args.model)
    from code_claim_verifier import CodeClaimVerifier
    verifier = CodeClaimVerifier(llm_function=llm_fn, repo_path=args.repo)
    report = verifier.verify(
        reasoning=reasoning,
        finding_file=args.finding_file,
        domain_context=args.domain_context,
    )
    json.dump(report.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")


def _cmd_verify_batch(args):
    if args.input:
        f = open(args.input)
    else:
        f = sys.stdin

    llm_fn = _get_llm_function(args.llm_provider, args.model)
    from code_claim_verifier import CodeClaimVerifier
    verifier = CodeClaimVerifier(llm_function=llm_fn, repo_path=args.repo)

    items = []
    for i, line in enumerate(f):
        if i >= args.max_items:
            break
        line = line.strip()
        if not line:
            continue
        items.append(json.loads(line))

    if args.input:
        f.close()

    reports = verifier.verify_batch(items=items, domain_context=args.domain_context)
    for report in reports:
        json.dump(report.to_dict(), sys.stdout)
        sys.stdout.write("\n")
```

Create `code_claim_verifier/providers/__init__.py`:
```python
```

Create `code_claim_verifier/providers/anthropic_provider.py`:
```python
from __future__ import annotations

import os


def make_llm_function(model: str | None = None):
    try:
        import anthropic
    except ImportError:
        raise ImportError("pip install code-claim-verifier[anthropic]")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable not set")

    client = anthropic.Anthropic(api_key=api_key)
    model = model or "claude-sonnet-4-20250514"

    def llm_function(system: str, user: str) -> str:
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text

    return llm_function
```

Create `code_claim_verifier/providers/openai_provider.py`:
```python
from __future__ import annotations

import os


def make_llm_function(model: str | None = None):
    try:
        import openai
    except ImportError:
        raise ImportError("pip install code-claim-verifier[openai]")

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")

    client = openai.OpenAI(api_key=api_key)
    model = model or "gpt-4o"

    def llm_function(system: str, user: str) -> str:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response.choices[0].message.content

    return llm_function
```

- [ ] **Step 4: Update pyproject.toml**

Add after the `[project.urls]` section:

```toml
[project.optional-dependencies]
anthropic = ["anthropic>=0.20"]
openai = ["openai>=1.0"]
test = ["pytest>=7.0"]

[project.scripts]
ccv = "code_claim_verifier.cli:main"
```

- [ ] **Step 5: Run tests**

Run: `python -m pytest tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add code_claim_verifier/__main__.py code_claim_verifier/cli.py code_claim_verifier/providers/ tests/test_cli.py pyproject.toml
git commit -m "feat: CLI with verify, verify-batch, list-types subcommands and LLM providers"
```

---

### Task 10: Tool schemas

**Files:**
- Create: `code_claim_verifier/tools.py`
- Modify: `code_claim_verifier/__init__.py`
- Create: `tests/test_tools.py`

- [ ] **Step 1: Write tests**

```python
# tests/test_tools.py
import os
from code_claim_verifier import CodeClaimVerifier

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "python_repo")


def mock_llm(s, u):
    return "[]"


class TestToolSchemas:
    def test_default_tools_returns_list(self):
        tools = CodeClaimVerifier.default_tools()
        assert isinstance(tools, list)
        assert len(tools) == 4
        names = {t["name"] for t in tools}
        assert names == {"extract_claims", "verify_claim", "verify_all", "list_claim_types"}

    def test_as_tools_includes_custom_types(self):
        from code_claim_verifier.types import VerifiedClaim
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        v.register("MY_TYPE", lambda c, r, l: VerifiedClaim(
            claim=c, verdict="VERIFIED", method_confidence=0.5, evidence="", method="test"),
            extraction_hint="MY_TYPE: {x: str} - test",
        )
        tools = v.as_tools()
        list_types_tool = [t for t in tools if t["name"] == "list_claim_types"][0]
        assert "MY_TYPE" in str(list_types_tool)

    def test_each_tool_has_required_fields(self):
        tools = CodeClaimVerifier.default_tools()
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert "type" in tool["input_schema"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tools.py -v`
Expected: FAIL

- [ ] **Step 3: Implement tools.py**

```python
# code_claim_verifier/tools.py
from __future__ import annotations

from code_claim_verifier.cli import CLAIM_SCHEMAS


def _generate_tools(claim_types: dict[str, dict]) -> list[dict]:
    return [
        {
            "name": "extract_claims",
            "description": "Extract typed claims from LLM reasoning text about source code.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "reasoning": {"type": "string", "description": "LLM reasoning text"},
                    "evidence": {"type": "object", "description": "Structured evidence dict"},
                    "domain_context": {"type": "string", "description": "Domain-specific instructions"},
                },
                "required": ["reasoning"],
            },
        },
        {
            "name": "verify_claim",
            "description": "Verify a single typed claim against a repository.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "claim_type": {"type": "string", "enum": list(claim_types.keys())},
                    "parameters": {"type": "object"},
                    "language": {"type": "string", "default": "unknown"},
                },
                "required": ["claim_type", "parameters"],
            },
        },
        {
            "name": "verify_all",
            "description": "Extract and verify all claims from reasoning text.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "reasoning": {"type": "string"},
                    "evidence": {"type": "object"},
                    "finding_file": {"type": "string"},
                    "domain_context": {"type": "string"},
                },
                "required": ["reasoning"],
            },
        },
        {
            "name": "list_claim_types",
            "description": "List all available claim types with parameter schemas.",
            "input_schema": {
                "type": "object",
                "properties": {},
            },
            "output": claim_types,
        },
    ]


def default_tools() -> list[dict]:
    return _generate_tools(CLAIM_SCHEMAS)


def instance_tools(extra_types: dict[str, str]) -> list[dict]:
    schemas = dict(CLAIM_SCHEMAS)
    for name, hint in extra_types.items():
        schemas[name] = {"_hint": hint}
    return _generate_tools(schemas)
```

- [ ] **Step 4: Add as_tools and default_tools to CodeClaimVerifier**

Add to `code_claim_verifier/__init__.py`:

```python
    def as_tools(self) -> list[dict]:
        from code_claim_verifier.tools import instance_tools
        extra = {k: v for k, v in zip(
            [ct for ct in self.engine.registry if ct not in CLAIM_TYPES],
            self._extraction_hints,
        )} if self._extraction_hints else {}
        return instance_tools(extra)

    @classmethod
    def default_tools(cls) -> list[dict]:
        from code_claim_verifier.tools import default_tools
        return default_tools()
```

- [ ] **Step 5: Run tests**

Run: `python -m pytest tests/test_tools.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add code_claim_verifier/tools.py tests/test_tools.py code_claim_verifier/__init__.py
git commit -m "feat: tool schema generation with as_tools and default_tools"
```

---

## Phase 5: Evaluation Framework

### Task 11: Eval fixture repos and dataset

**Files:**
- Create: `eval/fixtures/python_repo/` (multiple files)
- Create: `eval/fixtures/go_repo/` (multiple files)
- Create: `eval/fixtures/ts_repo/` (multiple files)
- Create: `eval/dataset.jsonl`

- [ ] **Step 1: Create Python fixture repo**

```bash
mkdir -p eval/fixtures/python_repo
```

`eval/fixtures/python_repo/main.py`:
```python
import os
import torch

def load_model(path):
    return torch.load(path)

def process(data):
    result = load_model(data)
    return result

def unused_endpoint():
    pass
```

`eval/fixtures/python_repo/utils.py`:
```python
def sanitize(input_str):
    return input_str.replace("<", "&lt;")

def helper():
    return 42
```

`eval/fixtures/python_repo/requirements.txt`:
```
torch==2.1.0
numpy==1.24.0
flask==3.0.0
```

- [ ] **Step 2: Create Go fixture repo**

```bash
mkdir -p eval/fixtures/go_repo
```

`eval/fixtures/go_repo/main.go`:
```go
package main

import (
    "fmt"
    "net/http"
)

func HandleRequest(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello")
}

func main() {
    http.HandleFunc("/", HandleRequest)
    http.ListenAndServe(":8080", nil)
}
```

`eval/fixtures/go_repo/go.mod`:
```
module example.com/app

go 1.21

require github.com/gorilla/mux v1.8.1
```

- [ ] **Step 3: Create TS fixture repo**

```bash
mkdir -p eval/fixtures/ts_repo
```

`eval/fixtures/ts_repo/index.ts`:
```typescript
import express from 'express';

const app = express();

function handleRoute(req: any, res: any) {
    res.send('Hello');
}

app.get('/', handleRoute);
export default app;
```

`eval/fixtures/ts_repo/package-lock.json`:
```json
{
    "name": "test-app",
    "version": "1.0.0",
    "dependencies": {
        "express": {"version": "4.18.2"}
    },
    "packages": {
        "node_modules/express": {"version": "4.18.2"}
    }
}
```

- [ ] **Step 4: Create evaluation dataset**

`eval/dataset.jsonl` (one JSON object per line):
```jsonl
{"id": "py_001", "reasoning": "torch.load() is called in main.py to load the model. The function load_model at main.py uses torch.load without any safety checks.", "evidence": {}, "finding_file": "main.py", "fixture_repo": "python_repo", "ground_truth_claims": [{"claim_type": "FUNCTION_CALLED", "parameters": {"name": "torch.load", "expected": true}, "expected_verdict": "VERIFIED"}, {"claim_type": "FILE_EXISTS", "parameters": {"path": "main.py"}, "expected_verdict": "VERIFIED"}]}
{"id": "py_002", "reasoning": "The file config.py contains database credentials in plaintext.", "evidence": {}, "finding_file": "config.py", "fixture_repo": "python_repo", "ground_truth_claims": [{"claim_type": "FILE_EXISTS", "parameters": {"path": "config.py"}, "expected_verdict": "REFUTED"}]}
{"id": "py_003", "reasoning": "numpy version 1.24.0 is installed. There is no input sanitization anywhere in the codebase.", "evidence": {}, "finding_file": "main.py", "fixture_repo": "python_repo", "ground_truth_claims": [{"claim_type": "PACKAGE_VERSION", "parameters": {"package": "numpy", "version": "1.24.0"}, "expected_verdict": "VERIFIED"}, {"claim_type": "ABSENCE", "parameters": {"pattern": "sanitize", "scope": "repo"}, "expected_verdict": "REFUTED"}]}
{"id": "go_001", "reasoning": "The HandleRequest function exists in main.go and serves HTTP traffic.", "evidence": {}, "finding_file": "main.go", "fixture_repo": "go_repo", "ground_truth_claims": [{"claim_type": "FUNCTION_EXISTS", "parameters": {"name": "HandleRequest", "file": "main.go"}, "expected_verdict": "VERIFIED"}, {"claim_type": "ENTRY_POINT", "parameters": {"type": "http", "location": "main.go"}, "expected_verdict": "VERIFIED"}]}
{"id": "ts_001", "reasoning": "express version 4.18.2 is used. The handleRoute function exists in index.ts.", "evidence": {}, "finding_file": "index.ts", "fixture_repo": "ts_repo", "ground_truth_claims": [{"claim_type": "PACKAGE_VERSION", "parameters": {"package": "express", "version": "4.18.2"}, "expected_verdict": "VERIFIED"}, {"claim_type": "FUNCTION_EXISTS", "parameters": {"name": "handleRoute", "file": "index.ts"}, "expected_verdict": "VERIFIED"}]}
```

- [ ] **Step 5: Commit**

```bash
git add eval/
git commit -m "feat: evaluation fixture repos and dataset"
```

---

### Task 12: Eval framework core

**Files:**
- Create: `code_claim_verifier/eval/__init__.py`
- Create: `code_claim_verifier/eval/runner.py`
- Create: `code_claim_verifier/eval/extraction_eval.py`
- Create: `code_claim_verifier/eval/verification_eval.py`
- Create: `code_claim_verifier/eval/calibration_eval.py`
- Create: `code_claim_verifier/eval/report.py`
- Create: `tests/test_eval.py`

- [ ] **Step 1: Write tests for eval framework**

```python
# tests/test_eval.py
import os
from code_claim_verifier.types import TypedClaim
from code_claim_verifier.eval.extraction_eval import compute_extraction_metrics, claims_match
from code_claim_verifier.eval.verification_eval import compute_verification_metrics
from code_claim_verifier.eval.calibration_eval import compute_calibration_metrics


class TestClaimMatching:
    def test_exact_match(self):
        gt = {"claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}}
        pred = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "a.py"}, source_sentence="test")
        assert claims_match(gt, pred)

    def test_extra_params_ok(self):
        gt = {"claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}}
        pred = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "a.py", "extra": True}, source_sentence="test")
        assert claims_match(gt, pred)

    def test_missing_param_no_match(self):
        gt = {"claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}}
        pred = TypedClaim(claim_type="FILE_EXISTS", parameters={}, source_sentence="test")
        assert not claims_match(gt, pred)

    def test_wrong_type_no_match(self):
        gt = {"claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}}
        pred = TypedClaim(claim_type="FUNCTION_EXISTS", parameters={"path": "a.py"}, source_sentence="test")
        assert not claims_match(gt, pred)


class TestExtractionMetrics:
    def test_perfect_extraction(self):
        ground_truth = [{"claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}}]
        predicted = [TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "a.py"}, source_sentence="")]
        metrics = compute_extraction_metrics(ground_truth, predicted)
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0

    def test_no_predictions(self):
        ground_truth = [{"claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}}]
        metrics = compute_extraction_metrics(ground_truth, [])
        assert metrics["precision"] == 0.0
        assert metrics["recall"] == 0.0


class TestVerificationMetrics:
    def test_perfect_accuracy(self):
        results = [
            {"expected": "VERIFIED", "actual": "VERIFIED", "claim_type": "FILE_EXISTS"},
            {"expected": "REFUTED", "actual": "REFUTED", "claim_type": "FILE_EXISTS"},
        ]
        metrics = compute_verification_metrics(results)
        assert metrics["accuracy"] == 1.0

    def test_false_refuted(self):
        results = [
            {"expected": "VERIFIED", "actual": "REFUTED", "claim_type": "FILE_EXISTS"},
        ]
        metrics = compute_verification_metrics(results)
        assert metrics["false_refuted_rate"] == 1.0


class TestCalibrationMetrics:
    def test_ece_computation(self):
        results = [
            {"claim_type": "FILE_EXISTS", "confidence": 0.99, "correct": True},
            {"claim_type": "FILE_EXISTS", "confidence": 0.99, "correct": True},
            {"claim_type": "FILE_EXISTS", "confidence": 0.99, "correct": False},
        ]
        metrics = compute_calibration_metrics(results)
        assert "per_type_accuracy" in metrics
        assert "FILE_EXISTS" in metrics["per_type_accuracy"]
        assert "ece" in metrics
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_eval.py -v`
Expected: ImportError

- [ ] **Step 3: Implement eval modules**

Create `code_claim_verifier/eval/__init__.py`:
```python
from code_claim_verifier.eval.runner import run_evaluation
```

Create `code_claim_verifier/eval/extraction_eval.py`:
```python
from __future__ import annotations
from code_claim_verifier.types import TypedClaim


def claims_match(ground_truth: dict, predicted: TypedClaim) -> bool:
    if ground_truth["claim_type"] != predicted.claim_type:
        return False
    gt_params = ground_truth.get("parameters", {})
    for key, value in gt_params.items():
        if predicted.parameters.get(key) != value:
            return False
    return True


def compute_extraction_metrics(
    ground_truth: list[dict],
    predicted: list[TypedClaim],
) -> dict:
    if not predicted and not ground_truth:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    if not predicted:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    if not ground_truth:
        return {"precision": 0.0, "recall": 1.0, "f1": 0.0}

    matched_gt = set()
    matched_pred = set()

    for i, pred in enumerate(predicted):
        for j, gt in enumerate(ground_truth):
            if j not in matched_gt and claims_match(gt, pred):
                matched_gt.add(j)
                matched_pred.add(i)
                break

    precision = len(matched_pred) / len(predicted) if predicted else 0.0
    recall = len(matched_gt) / len(ground_truth) if ground_truth else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}
```

Create `code_claim_verifier/eval/verification_eval.py`:
```python
from __future__ import annotations
from collections import defaultdict


def compute_verification_metrics(results: list[dict]) -> dict:
    if not results:
        return {"accuracy": 0.0, "false_refuted_rate": 0.0, "false_verified_rate": 0.0,
                "confusion_matrix": {}, "per_type": {}}

    correct = sum(1 for r in results if r["expected"] == r["actual"])
    accuracy = correct / len(results)

    false_refuted = sum(1 for r in results if r["expected"] == "VERIFIED" and r["actual"] == "REFUTED")
    false_verified = sum(1 for r in results if r["expected"] == "REFUTED" and r["actual"] == "VERIFIED")
    total_expected_verified = sum(1 for r in results if r["expected"] == "VERIFIED") or 1
    total_expected_refuted = sum(1 for r in results if r["expected"] == "REFUTED") or 1

    verdicts = ["VERIFIED", "REFUTED", "UNVERIFIABLE"]
    matrix = {v: {v2: 0 for v2 in verdicts} for v in verdicts}
    for r in results:
        exp, act = r["expected"], r["actual"]
        if exp in matrix and act in matrix[exp]:
            matrix[exp][act] += 1

    per_type: dict[str, dict] = defaultdict(lambda: {"correct": 0, "total": 0})
    for r in results:
        ct = r["claim_type"]
        per_type[ct]["total"] += 1
        if r["expected"] == r["actual"]:
            per_type[ct]["correct"] += 1

    per_type_acc = {ct: {"accuracy": round(d["correct"] / d["total"], 4)} for ct, d in per_type.items()}

    return {
        "accuracy": round(accuracy, 4),
        "false_refuted_rate": round(false_refuted / total_expected_verified, 4),
        "false_verified_rate": round(false_verified / total_expected_refuted, 4),
        "confusion_matrix": matrix,
        "per_type": per_type_acc,
    }
```

Create `code_claim_verifier/eval/calibration_eval.py`:
```python
from __future__ import annotations
from collections import defaultdict


def compute_calibration_metrics(results: list[dict]) -> dict:
    if not results:
        return {"per_type_accuracy": {}, "ece": 0.0, "confidence_adjustments": {}}

    by_type: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_type[r["claim_type"]].append(r)

    per_type = {}
    total_ece = 0.0
    total_count = 0
    adjustments = {}

    for ctype, items in by_type.items():
        confidence = items[0]["confidence"]
        actual_correct = sum(1 for i in items if i["correct"])
        actual_accuracy = actual_correct / len(items)
        per_type[ctype] = {
            "predicted_confidence": confidence,
            "actual_accuracy": round(actual_accuracy, 4),
            "count": len(items),
        }
        total_ece += abs(confidence - actual_accuracy) * len(items)
        total_count += len(items)

        if abs(confidence - actual_accuracy) > 0.05:
            adjustments[ctype] = {
                "current": confidence,
                "recommended": round(actual_accuracy, 2),
            }

    ece = total_ece / total_count if total_count > 0 else 0.0

    return {
        "per_type_accuracy": per_type,
        "ece": round(ece, 4),
        "confidence_adjustments": adjustments,
    }
```

Create `code_claim_verifier/eval/report.py`:
```python
from __future__ import annotations
import json


def generate_report(extraction: dict, verification: dict, calibration: dict) -> dict:
    return {
        "extraction": extraction,
        "verification": verification,
        "calibration": calibration,
    }


def write_report(report: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
```

Create `code_claim_verifier/eval/runner.py`:
```python
from __future__ import annotations

import json
import os

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.verifiers import safe_verify
from code_claim_verifier.language import detect_language
from code_claim_verifier.eval.extraction_eval import compute_extraction_metrics
from code_claim_verifier.eval.verification_eval import compute_verification_metrics
from code_claim_verifier.eval.calibration_eval import compute_calibration_metrics
from code_claim_verifier.eval.report import generate_report


def run_evaluation(dataset_path: str, fixtures_path: str, mock_extraction: bool = True) -> dict:
    with open(dataset_path) as f:
        samples = [json.loads(line) for line in f if line.strip()]

    all_extraction_metrics = []
    all_verification_results = []
    all_calibration_results = []

    for sample in samples:
        fixture_repo = os.path.join(fixtures_path, sample["fixture_repo"])
        gt_claims = sample["ground_truth_claims"]
        language = detect_language(sample.get("finding_file", ""))

        if mock_extraction:
            predicted = [
                TypedClaim(
                    claim_type=gc["claim_type"],
                    parameters=gc["parameters"],
                    source_sentence="",
                )
                for gc in gt_claims
            ]
        else:
            predicted = []

        ext_metrics = compute_extraction_metrics(gt_claims, predicted)
        all_extraction_metrics.append(ext_metrics)

        for gc in gt_claims:
            claim = TypedClaim(
                claim_type=gc["claim_type"],
                parameters=gc["parameters"],
                source_sentence="",
            )
            vc = safe_verify(claim, fixture_repo, language)
            expected = gc.get("expected_verdict", "VERIFIED")

            all_verification_results.append({
                "expected": expected,
                "actual": vc.verdict,
                "claim_type": gc["claim_type"],
            })
            all_calibration_results.append({
                "claim_type": gc["claim_type"],
                "confidence": vc.method_confidence,
                "correct": vc.verdict == expected,
            })

    avg_extraction = {
        "precision": round(sum(m["precision"] for m in all_extraction_metrics) / len(all_extraction_metrics), 4),
        "recall": round(sum(m["recall"] for m in all_extraction_metrics) / len(all_extraction_metrics), 4),
        "f1": round(sum(m["f1"] for m in all_extraction_metrics) / len(all_extraction_metrics), 4),
    }

    verification = compute_verification_metrics(all_verification_results)
    calibration = compute_calibration_metrics(all_calibration_results)

    return generate_report(avg_extraction, verification, calibration)
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_eval.py -v`
Expected: All PASS

- [ ] **Step 5: Add eval subcommand to CLI**

Add to `cli.py`'s `main()` function, after the existing subparsers:

```python
    eval_parser = subparsers.add_parser("eval")
    eval_parser.add_argument("--dataset", required=True)
    eval_parser.add_argument("--fixtures", required=True)
    eval_parser.add_argument("--output", default=None)
    eval_parser.add_argument("--mock-extraction", action="store_true", default=True)
```

And in the command dispatch:

```python
    elif args.command == "eval":
        _cmd_eval(args)
```

Add the handler:

```python
def _cmd_eval(args):
    from code_claim_verifier.eval.runner import run_evaluation
    from code_claim_verifier.eval.report import write_report

    report = run_evaluation(
        dataset_path=args.dataset,
        fixtures_path=args.fixtures,
        mock_extraction=args.mock_extraction,
    )

    if args.output:
        write_report(report, args.output)
        print(f"Report written to {args.output}")
    else:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
```

- [ ] **Step 6: Test eval end-to-end**

Run: `python -m code_claim_verifier eval --dataset eval/dataset.jsonl --fixtures eval/fixtures/ 2>/dev/null | python -m json.tool`
Expected: JSON report with extraction, verification, and calibration sections

- [ ] **Step 7: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: All PASS

- [ ] **Step 8: Commit**

```bash
git add code_claim_verifier/eval/ tests/test_eval.py code_claim_verifier/cli.py
git commit -m "feat: evaluation framework with extraction, verification, and calibration stages"
```

---

## Final Checklist

- [ ] All tests pass: `python -m pytest tests/ -v`
- [ ] CLI works: `python -m code_claim_verifier list-types`
- [ ] Eval runs: `python -m code_claim_verifier eval --dataset eval/dataset.jsonl --fixtures eval/fixtures/`
- [ ] No import errors: `python -c "from code_claim_verifier import CodeClaimVerifier; print('OK')"`
