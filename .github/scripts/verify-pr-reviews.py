#!/usr/bin/env python3
"""Verify LLM claims in PR review comments using CodeClaimVerifier.

Fetches PR review comments via GitHub CLI, runs CCV on each,
and posts verification results as a new PR comment.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys


def gh_api(endpoint: str, method: str = "GET", data: dict | None = None) -> dict | list:
    cmd = ["gh", "api", endpoint, "--method", method]
    if data:
        cmd.extend(["--input", "-"])
        result = subprocess.run(
            cmd, input=json.dumps(data), capture_output=True, text=True, timeout=30,
        )
    else:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        print(f"gh api error: {result.stderr}", file=sys.stderr)
        return []
    return json.loads(result.stdout) if result.stdout.strip() else {}


def get_pr_comments(repo: str, pr_number: str) -> list[dict]:
    comments = gh_api(f"repos/{repo}/pulls/{pr_number}/comments")
    if not isinstance(comments, list):
        return []
    return comments


def get_pr_review_bodies(repo: str, pr_number: str) -> list[dict]:
    reviews = gh_api(f"repos/{repo}/pulls/{pr_number}/reviews")
    if not isinstance(reviews, list):
        return []
    return [r for r in reviews if r.get("body", "").strip()]


def filter_comments(comments: list[dict], tag: str) -> list[dict]:
    filtered = []
    for c in comments:
        body = c.get("body", "")
        if f"<!-- {tag} -->" in body:
            continue
        if len(body.strip()) < 50:
            continue
        filtered.append(c)
    return filtered


def verify_comment(comment_body: str, repo_path: str, provider: str,
                   model: str, domain_context: str) -> dict | None:
    from code_claim_verifier import CodeClaimVerifier

    if provider == "anthropic":
        from code_claim_verifier.providers.anthropic_provider import make_llm_function
    elif provider == "openai":
        from code_claim_verifier.providers.openai_provider import make_llm_function
    else:
        print(f"Unknown provider: {provider}", file=sys.stderr)
        return None

    llm_fn = make_llm_function(model or None)
    verifier = CodeClaimVerifier(llm_function=llm_fn, repo_path=repo_path)
    report = verifier.verify(
        reasoning=comment_body[:4000],
        domain_context=domain_context,
    )
    return report.to_dict()


def format_results(reports: list[dict], tag: str) -> str:
    total_claims = sum(r.get("total_claims", 0) for r in reports)
    total_verified = sum(r.get("verified", 0) for r in reports)
    total_refuted = sum(r.get("refuted", 0) for r in reports)

    if total_claims == 0:
        return ""

    rate = total_verified / (total_verified + total_refuted) if (total_verified + total_refuted) > 0 else 0
    if rate >= 0.8:
        action = "BOOST"
        emoji = ":white_check_mark:"
    elif rate >= 0.5:
        action = "FLAG"
        emoji = ":warning:"
    else:
        action = "OVERRIDE"
        emoji = ":x:"

    lines = [
        f"<!-- {tag} -->",
        f"## {emoji} CCV Claim Verification",
        "",
        f"**{total_claims}** claims extracted from review comments. "
        f"**{total_verified}** verified, **{total_refuted}** refuted.",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Verification rate | {rate:.0%} |",
        f"| Action | **{action}** |",
        f"| Claims verified | {total_verified} |",
        f"| Claims refuted | {total_refuted} |",
        "",
    ]

    if total_refuted > 0:
        lines.append("### Refuted claims")
        lines.append("")
        for r in reports:
            for c in r.get("claims", []):
                if c.get("verdict") == "REFUTED":
                    lines.append(f"- **{c['type']}**(`{c.get('params', {})}`) : {c.get('evidence', '')[:150]}")
        lines.append("")

    lines.append("---")
    lines.append("*Verified by [CodeClaimVerifier](https://ugiordan.github.io/code-claim-verifier/). "
                 "Grep doesn't hallucinate.*")

    return "\n".join(lines)


def set_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT", "")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")
    else:
        print(f"::set-output name={name}::{value}")


def main():
    repo = os.environ.get("CCV_REPO_FULL_NAME", "")
    pr_number = os.environ.get("CCV_PR_NUMBER", "")
    repo_path = os.environ.get("CCV_REPO_PATH", ".")
    provider = os.environ.get("CCV_LLM_PROVIDER", "anthropic")
    model = os.environ.get("CCV_MODEL", "")
    domain_context = os.environ.get("CCV_DOMAIN_CONTEXT", "")
    comment_tag = os.environ.get("CCV_COMMENT_TAG", "ccv-verification")
    min_claims = int(os.environ.get("CCV_MIN_CLAIMS", "2"))
    dry_run = "--dry-run" in sys.argv

    if not repo or not pr_number:
        print("Missing CCV_REPO_FULL_NAME or CCV_PR_NUMBER", file=sys.stderr)
        if not dry_run:
            sys.exit(1)
        return

    print(f"Fetching comments for {repo}#{pr_number}...")
    review_comments = get_pr_comments(repo, pr_number)
    reviews = get_pr_review_bodies(repo, pr_number)

    all_bodies = [c.get("body", "") for c in filter_comments(review_comments, comment_tag)]
    all_bodies += [r.get("body", "") for r in filter_comments(reviews, comment_tag)]

    if not all_bodies:
        print("No review comments to verify.")
        set_output("verification-rate", "1.0")
        set_output("action", "NO_CHANGE")
        set_output("total-claims", "0")
        set_output("hallucination-rate", "0.0")
        return

    print(f"Found {len(all_bodies)} comments to verify.")

    reports = []
    for i, body in enumerate(all_bodies):
        print(f"  Verifying comment {i+1}/{len(all_bodies)}...")
        if dry_run:
            print(f"    [dry-run] Would verify: {body[:100]}...")
            continue
        report = verify_comment(body, repo_path, provider, model, domain_context)
        if report:
            reports.append(report)

    if dry_run:
        print("Dry run complete.")
        return

    total_claims = sum(r.get("total_claims", 0) for r in reports)
    if total_claims < min_claims:
        print(f"Only {total_claims} claims (min: {min_claims}). Skipping comment.")
        set_output("verification-rate", "1.0")
        set_output("action", "NO_CHANGE")
        set_output("total-claims", str(total_claims))
        set_output("hallucination-rate", "0.0")
        return

    summary = format_results(reports, comment_tag)
    if summary:
        print("Posting verification comment...")
        gh_api(
            f"repos/{repo}/issues/{pr_number}/comments",
            method="POST",
            data={"body": summary},
        )

    total_verified = sum(r.get("verified", 0) for r in reports)
    total_refuted = sum(r.get("refuted", 0) for r in reports)
    rate = total_verified / (total_verified + total_refuted) if (total_verified + total_refuted) > 0 else 1.0

    if rate >= 0.8:
        action = "BOOST"
    elif rate >= 0.5:
        action = "FLAG"
    else:
        action = "OVERRIDE"

    set_output("verification-rate", str(round(rate, 4)))
    set_output("action", action)
    set_output("total-claims", str(total_claims))
    set_output("hallucination-rate", str(round(1 - rate, 4)))

    print(f"Done: {total_claims} claims, {total_verified} verified, {total_refuted} refuted. Action: {action}")


if __name__ == "__main__":
    main()
