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
  --host-header www.nieuwejobs.com \
  --threshold 200 \
  --dry-run
```

Prepare generic blocks from `input.txt`:

```bash
PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks.sh
```

Fast path preview from `input.txt`:

```bash
PYTHON=python2 APPLY=0 UFW_USER_RULES=/lib/ufw/user.rules ./run_prepare_generiek_blocks_fast_all.sh
```

The fast-all wrapper fetches live `server-status` into `input.txt` by default using `SERVER_STATUS_URL=http://127.0.0.1/server-status` and `SERVER_STATUS_HOST=www.nieuwejobs.com`. It also restarts Apache by default for manual incident runs. Set `FETCH_SERVER_STATUS=0` and `RESTART_APACHE=0` when intentionally analyzing a saved `input.txt`.
The fast-all wrapper disables timestamped `user.rules` backups by default with `FAST_UFW_BACKUP=0` so repeated incident loops do not fill `/lib/ufw`. Set `FAST_UFW_BACKUP=1` when a specific apply needs a backup.

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

Use the loop only for an active extreme overload where one-shot blocking does not stabilize Apache. The loop checks `server-status`, and when busy workers exceed the threshold it runs the fast-all cycle with `POLICY_MODE=0`, `TARGET_PREFIX=16`, `MIN_HITS=1`, `APPLY=1`, `FAST_UFW_BACKUP=0`, and `UFW_USER_RULES=/lib/ufw/user.rules`. The fast-all cycle fetches fresh status input, uses local fast geo data, edits UFW `user.rules` once, reloads UFW once, and restarts Apache to clear already established overloaded connections.

Safe one-shot test:

```bash
PYTHON=python2 /usr/bin/python2 monitor_fast_all_loop.py \
  --url http://127.0.0.1/server-status \
  --host-header www.nieuwejobs.com \
  --threshold 100 \
  --once \
  --dry-run
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
- `runs/<timestamp>/user.rules.preview` when using fast UFW apply

## Safety Boundaries

- Protected local markets are `BE`, `DE`, `FR`, and `NL` by default.
- Do not add blocks that overlap crawler allowlists for Google, Bing/Microsoft, or OpenAI.
- Do not widen prefixes based only on historical provider data unless the user asks for that risk.
- Do not run destructive commands such as UFW apply/delete, direct `user.rules` replacement, `rm`, or git reset without explicit approval.
- For fast UFW apply, inspect the preview and verify new deny rules are before port 80/443 allow rules.
- Fast UFW `APPLY=1` must run as root, for example with `sudo env PYTHON=python2 APPLY=1 UFW_USER_RULES=/lib/ufw/user.rules ./run_prepare_generiek_blocks_fast_all.sh`.
- If SSL fails under Python 2, prefer local HTTP for server-status. Use `--insecure` only when the endpoint is trusted.
- For Apache name-based vhosts, include `--host-header www.nieuwejobs.com` with the local `127.0.0.1` status URL.
- A production incident run with `0` parsed IPs is a failed input capture; do not continue unless `ALLOW_EMPTY_INPUT=1` is explicitly set for testing.

## Validation

Run focused tests after changes:

```bash
python3 -m unittest discover -s tests
```

For syntax compatibility checks:

```bash
python3 -m py_compile monitor_server_status_blocks.py monitor_fast_all_loop.py cache_crawler_ips.py fast_geo_lookup.py fast_apply_ufw_user_rules.py
```

If Python 2 is available, also run the changed script with `/usr/bin/python2` in dry-run mode.
