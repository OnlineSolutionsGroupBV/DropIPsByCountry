# Generic Subnet UFW Plan

## Goal

Make the existing server-status pipeline repeatable across servers:

```text
server-status/log data
  -> input.txt
  -> parse_ips.py
  -> get_ip_country.py
  -> aggregate_generiek_subnets.py
  -> block_generiek_subnet.py
  -> UFW deny rules
```

`block_generiek_subnet.py` must compare `aggregated_generiek_subnets.json` with the
current live UFW rules and only add subnet rules that are not already covered.

## What Already Exists

- `parse_ips.py` extracts IPv4 addresses from `input.txt` into `output.txt`.
- `get_ip_country.py` enriches `output.txt` into `geo_data.json`.
- `aggregate_generiek_subnets.py` filters configured country codes and writes
  `aggregated_generiek_subnets.json`.
- `find_bad_ufw_rules.py` detects UFW deny rules that block allowlisted crawler
  ranges such as OpenAI/Google.
- `clean_bad_ufw_rules.py` deletes detected bad rules after review.

The plan reuses those scripts instead of building a new end-to-end runner.

## Architecture

```text
aggregated_generiek_subnets.json
  |
  v
load + validate CIDRs
  |
  v
ufw status numbered -----> extract DENY IN CIDRs/IPs
  |                         |
  |                         v
  +-------------------- compare candidate covered by existing deny?
                            |
                            +-- yes -> skip
                            |
                            +-- no  -> ufw insert 1 deny from <cidr>
```

The blocker treats live UFW as source of truth. `blocked_generiek_ips.txt` remains a
human-readable tracking file, but it must not hide missing firewall rules on a new
server.

## Review Findings

### Scope Challenge

The minimum complete change is to refactor only `block_generiek_subnet.py`, add tests,
and document the command order. A separate orchestrator script would be useful later,
but it is not required for the current repeated-server workflow.

### Architecture Review

1. [P1] (confidence: 9/10) `block_generiek_subnet.py:28` stops in `pdb`, so production
   blocking cannot run unattended.
2. [P1] (confidence: 9/10) `block_generiek_subnet.py:19` trusts only
   `blocked_generiek_ips.txt`, so a copied repo on another server can skip rules that
   are not actually present in that server's UFW.
3. [P2] (confidence: 8/10) The current subprocess call uses `shell=True`; list-style
   subprocess calls are safer and easier to test.

Recommendation: complete fix in the existing blocker. This keeps the diff small while
solving the cross-server correctness problem.

### Code Quality Review

Use explicit functions for:

- JSON CIDR loading
- UFW status execution
- UFW rule parsing
- "already covered" comparison
- command execution

That avoids duplicating parsing logic in tests or future scripts.

### Test Review

```text
CODE PATHS                                             TEST PLAN
[+] load_candidate_networks()                          invalid JSON, invalid CIDR, valid CIDRs
[+] parse_ufw_denies()                                 numbered DENY IN lines, ALLOW lines skipped
[+] is_covered_by_existing_rule()                      exact match, broader subnet, unrelated subnet
[+] plan_new_rules()                                   live UFW wins over tracking file
[+] main dry-run                                       no UFW mutation

COVERAGE TARGET: blocker logic covered by unit tests; real UFW mutation remains manual.
```

### Performance Review

Subnet comparison is O(candidates * existing deny rules). For the current scale this is
acceptable and simpler than building interval indexes. If UFW grows to tens of
thousands of rules, group existing rules by IP version first.

## Failure Modes

- UFW is unavailable or permission denied: script exits with a clear error before
  modifying tracking files.
- `aggregated_generiek_subnets.json` is corrupt: script exits with a clear error.
- Existing UFW has a broader deny rule: candidate is skipped because it is already
  covered.
- `find_bad_ufw_rules.py` reports allowlist collisions: with `--check-bad-rules`, the
  blocker stops before adding more rules.
- Thousands of new rules are planned: dry-run previews only the first 50 by default
  and reports the hidden count; `--show-all` prints the full command list.

## NOT in Scope

- Rewriting the whole pipeline into one command. Existing scripts are kept.
- Automatic cleanup of bad UFW rules inside `block_generiek_subnet.py`. Cleanup remains
  an explicit review step through `clean_bad_ufw_rules.py`.
- Changing country-code selection in `aggregate_generiek_subnets.py`.
- Cron deployment or remote multi-server orchestration.

## Command Order

For each server:

```bash
vim input.txt
python parse_ips.py
python get_ip_country.py
python aggregate_generiek_subnets.py
python cache_crawler_ips.py --cache-dir ip_cache
python find_bad_ufw_rules.py --allowlist ip_cache/allowlist_cidrs.json --output bad_ufw_rules.json --sudo
python clean_bad_ufw_rules.py --input bad_ufw_rules.json --sudo --dry-run
sudo python block_generiek_subnet.py --sudo --check-bad-rules --dry-run
sudo python block_generiek_subnet.py --sudo --check-bad-rules
```

Remove `--dry-run` only after the planned additions look correct.

## Parallelization

Sequential implementation, no parallelization opportunity.
