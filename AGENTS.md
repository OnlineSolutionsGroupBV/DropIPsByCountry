# Agent Guide

This repository automates firewall response for Apache-hosted job sites. Treat changes as security-sensitive because many scripts can prepare or apply UFW deny rules.

## Start Here

- Use the project skill `.codex/skills/dropips-security` for security, incident, UFW, crawler allowlist, or Apache server-status work.
- Read the relevant `README.md` section before editing operational scripts.
- Check `git status --short` first and do not revert existing user changes.
- Keep production-facing scripts compatible with Python 2 unless the user explicitly asks to drop it.

## Safe Default Workflow

Prefer read-only or dry-run commands first:

```bash
PYTHON=python2 /usr/bin/python2 monitor_server_status_blocks.py \
  --url http://127.0.0.1/server-status \
  --threshold 200 \
  --dry-run
```

```bash
PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks.sh
```

For emergency broad blocking, review first:

```bash
PYTHON=python2 POLICY_MODE=0 TARGET_PREFIX=16 MIN_HITS=1 APPLY=0 ./run_prepare_generiek_blocks.sh
```

Only switch to `APPLY=1` after reviewing generated subnets and explaining the blast radius.

## Files To Inspect During Incidents

- `input.txt`: raw Apache `/server-status` or log input.
- `output.txt`: parsed source IPs.
- `aggregated_generiek_subnets.json`: CIDRs planned for blocking.
- `generiek_country_report.json`: country/provider evidence.
- `provider_dangerous_subnets.txt`: broader provider candidates for review.
- `ip_cache/allowlist_cidrs.json`: crawler allowlist.
- `runs/<timestamp>/`: run snapshots.

## Security Guardrails

- Protected local markets are `BE`, `DE`, `FR`, and `NL`.
- Avoid blocks overlapping Google, Bing/Microsoft, or OpenAI crawler allowlists.
- Do not apply or delete UFW rules without explicit approval.
- Prefer local HTTP for `/server-status`; use `--insecure` only for trusted endpoints when old Python/OpenSSL cannot validate HTTPS.
- Broad `/16` blocking is an incident tool, not a normal default.

## Validation

Run focused tests for edited modules and then:

```bash
python3 -m unittest discover -s tests
```

If Python 2 is available on the target server, also run changed production scripts in dry-run mode with `/usr/bin/python2`.
