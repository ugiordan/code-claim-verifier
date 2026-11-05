# Installation

## From PyPI

```bash
pip install code-claim-verifier
```

This installs the core library with no LLM provider dependencies. You'll need to install at least one provider to use the CLI or the built-in `LLMFunction` helpers.

## LLM provider extras

CCV supports Anthropic and OpenAI as extraction backends. Install the one you plan to use:

=== "Anthropic"

    ```bash
    pip install code-claim-verifier[anthropic]
    ```

    Requires `ANTHROPIC_API_KEY` in your environment.

=== "OpenAI"

    ```bash
    pip install code-claim-verifier[openai]
    ```

    Requires `OPENAI_API_KEY` in your environment.

=== "Both"

    ```bash
    pip install code-claim-verifier[anthropic,openai]
    ```

## From source

```bash
git clone https://github.com/ugiordan/code-claim-verifier.git
cd code-claim-verifier
pip install -e .
```

With test dependencies:

```bash
pip install -e ".[test]"
```

With a provider and tests:

```bash
pip install -e ".[anthropic,test]"
```

## Requirements

- Python 3.9+
- `grep` available on your `PATH` (ships with macOS and Linux, use Git Bash or WSL on Windows)

No other system dependencies. Most verification uses `grep` and local file reads. `CVE_AFFECTS_VERSION` also queries the OSV API unless its advisory response is supplied from a pinned cache. LLM extraction makes the configured provider call.

## Verify the installation

```bash
ccv list-types
```

This prints the JSON schemas for all 17 built-in claim types. If it works, you're good to go.
