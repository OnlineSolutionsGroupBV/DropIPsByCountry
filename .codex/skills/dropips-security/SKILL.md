---
name: dropips-security
description: Use when investigating, hardening, or operating DropIPsByCountry security workflows, including Apache server-status incidents, UFW block planning, crawler allowlist auditing, Python 2 compatibility, and safe firewall automation.
---

# DropIPs Security

Use this skill for security or incident-response work in this repository.

## First Checks

1. Read `AGENTS.md`, then the relevant part of `README.md`.
2. Check the worktree with `git status --short`; do not revert user changes.
3. Prefer dry-runs before firewall changes: `APPLY=0`, `--dry-run`, or omitted `--apply`.
4. Keep Python 2 compatibility for production-facing scripts unless the user explicitly changes that requirement.
5. Treat UFW changes as production-impacting. Explain intended rules before running commands that apply or delete firewall rules.

## Common Workflows

Monitor Apache load:

```bash
PYTHON=python2 /usr/bin/python2 monitor_server_status_blocks.py \
  --url http://127.0.0.1/server-status \
  --threshold 200 \
  --dry-run
```

Prepare generic blocks from `input.txt`:

```bash
PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks.sh
```

Emergency broad snapshot review:

```bash
PYTHON=python2 POLICY_MODE=0 TARGET_PREFIX=16 MIN_HITS=1 APPLY=0 ./run_prepare_generiek_blocks.sh
```

Only apply after reviewing:

- `aggregated_generiek_subnets.json`
- `generiek_country_report.json`
- `provider_dangerous_subnets.txt`
- `ip_cache/allowlist_cidrs.json`

## Safety Boundaries

- Protected local markets are `BE`, `DE`, `FR`, and `NL` by default.
- Do not add blocks that overlap crawler allowlists for Google, Bing/Microsoft, or OpenAI.
- Do not widen prefixes based only on historical provider data unless the user asks for that risk.
- Do not run destructive commands such as UFW apply/delete, `rm`, or git reset without explicit approval.
- If SSL fails under Python 2, prefer local HTTP for server-status. Use `--insecure` only when the endpoint is trusted.

## Validation

Run focused tests after changes:

```bash
python3 -m unittest discover -s tests
```

For syntax compatibility checks:

```bash
python3 -m py_compile monitor_server_status_blocks.py cache_crawler_ips.py
```

If Python 2 is available, also run the changed script with `/usr/bin/python2` in dry-run mode.
