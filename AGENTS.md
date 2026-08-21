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
  --host-header www.nieuwejobs.com \
  --threshold 200 \
  --dry-run
```

```bash
PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks.sh
```

Fast opt-in incident workflow:

```bash
PYTHON=python2 APPLY=0 UFW_USER_RULES=/lib/ufw/user.rules ./run_prepare_generiek_blocks_fast_all.sh
```

`run_prepare_generiek_blocks_fast_all.sh` fetches live `server-status` into `input.txt` by default. Use `FETCH_SERVER_STATUS=0` when intentionally analyzing an already saved input file.
It also restarts Apache by default for manual incident runs; use `RESTART_APACHE=0` for previews or analysis.
The fast-all wrapper sets `FAST_UFW_BACKUP=0` by default so a repeated incident loop does not fill `/lib/ufw` with timestamped `user.rules.backup-*` files. Use `FAST_UFW_BACKUP=1` only when a backup is required for that run.

Continuous fast incident loop:

```bash
sudo env PYTHON=python2 /usr/bin/python2 monitor_fast_all_loop.py \
  --url http://127.0.0.1/server-status \
  --host-header www.nieuwejobs.com \
  --threshold 100 \
  --sleep-seconds 300 \
  --script ./run_prepare_generiek_blocks_fast_all.sh \
  --user-rules /lib/ufw/user.rules
```

Use this loop only for active extreme overload, not as the normal cron default. It checks `server-status` every 300 seconds, and when busy workers exceed the threshold it runs the fast-all cycle with these defaults:

- `POLICY_MODE=0`
- `TARGET_PREFIX=16`
- `MIN_HITS=1`
- `APPLY=1`
- `FAST_UFW_BACKUP=0`
- `UFW_USER_RULES=/lib/ufw/user.rules`

The fast-all cycle fetches the live status page again, uses local fast geo data, edits `user.rules` once, reloads UFW once, and restarts Apache to drop existing overloaded worker connections. For a safe one-shot test use `--once --dry-run`.

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
- `runs/<timestamp>/user.rules.preview`: fast UFW preview when `APPLY=0` and `FAST_UFW_APPLY=1`.

## Security Guardrails

- Protected local markets are `BE`, `DE`, `FR`, and `NL`.
- Avoid blocks overlapping Google, Bing/Microsoft, or OpenAI crawler allowlists.
- Do not apply or delete UFW rules without explicit approval.
- Fast UFW apply edits `user.rules` directly; inspect preview and ensure deny rules remain before 80/443 allow rules.
- Fast UFW `APPLY=1` must run as root, for example with `sudo env PYTHON=python2 APPLY=1 ...`.
- Prefer local HTTP for `/server-status`; use `--insecure` only for trusted endpoints when old Python/OpenSSL cannot validate HTTPS.
- For name-based Apache vhosts, pass `--host-header www.nieuwejobs.com` when fetching `http://127.0.0.1/server-status`.
- Treat `0` parsed IPs as a failed incident input unless `ALLOW_EMPTY_INPUT=1` was set deliberately for testing.
- Broad `/16` blocking is an incident tool, not a normal default.

## Validation

Run focused tests for edited modules and then:

```bash
python3 -m unittest discover -s tests
```

If Python 2 is available on the target server, also run changed production scripts in dry-run mode with `/usr/bin/python2`.
