# Fast Country Lookup Plan Eng Review

Date: 2026-08-21

Status: implemented as opt-in commands. The old workflow remains the default.

## Goal

Reduce incident-time country detection from minutes to seconds by replacing per-IP external API lookups with a local IP range lookup. The fast path is implemented as opt-in commands; the old runtime workflow remains the default.

Implemented opt-in files:

- `build_fast_geo_ranges.py`
- `fast_geo_lookup.py`
- `compare_geo_lookup.py`
- `fast_apply_ufw_user_rules.py`
- `restore_ufw_user_rules_backup.py`
- `refresh_fast_geo_data.sh`
- `run_prepare_generiek_blocks_fast_geo.sh`
- `run_prepare_generiek_blocks_fast_all.sh`

## Current Bottleneck

`run_prepare_generiek_blocks.sh` calls `get_ip_country.py` before subnet aggregation when `AGG_SOURCE=geo`.

Current flow:

```text
input.txt
  -> parse_ips.py
  -> output.txt
  -> get_ip_country.py
  -> geo_data.json
  -> aggregate_generiek_subnets.py
  -> block_generiek_subnet.py
```

`get_ip_country.py` currently:

- reads unique IPs from `output.txt`
- skips IPs already present in `geo_data.json`
- calls `http://ipinfo.io/<ip>?token=...` for every missing IP
- sleeps `1` second after each successful request

The sleep alone makes a cold lookup expensive:

```text
100 unknown IPs -> at least 100 seconds
500 unknown IPs -> at least 500 seconds
1000 unknown IPs -> at least 1000 seconds
```

During an active overload, this is too slow. If Apache already shows 500 busy connections, the firewall decision path must not depend on hundreds of network calls.

Local snapshot on this workstation:

```text
output.txt unique IPs: 513
geo_data.json cached IPs: 36354
output IPs missing from geo_data.json: 0
```

That means the current local run is fast only because the cache is warm. The design still fails under a cold or mostly-new attack snapshot.

## Existing Related Implementation

The related Vindazo application repos already have a local range design:

- `ipaddress_data/models.py`
  - `IpCountryRange(start_int, end_int, network, country_code, asn, as_name, ...)`
- `ipaddress_data/management/commands/import_ip_country_ranges.py`
  - imports `data/ipinfo_lite.csv`
  - converts CIDR ranges to integer start/end ranges
  - bulk inserts ranges in batches
- `data/ipinfo_lite.csv`
  - 5,262,415 rows
  - 418 MB
  - header: `network,country,country_code,continent,continent_code,asn,as_name,as_domain`

This is the right shape for an application database, but DropIPsByCountry is an incident tool. It should stay usable without Django, PostgreSQL, migrations, or a long-running service.

## Data Source Options

### IPinfo Lite CSV

Official IPinfo Lite downloads include free country and country+ASN databases in CSV, MMDB, and JSON formats. Their documented free country+ASN CSV download is:

```bash
curl -L "https://ipinfo.io/data/free/country_asn.csv.gz?token=$TOKEN" -o country_asn.csv.gz
```

Official docs: https://ipinfo.io/developers//ipinfo-lite-database

Fit:

- Best match to the existing local `ipinfo_lite.csv` shape.
- Country + ASN supports the existing safe-provider checks.
- Token-based download still exists, but it happens during refresh, not during the incident path.

Risk:

- License and redistribution rules need to be respected.
- The local file is large, so it should normally stay ignored and be refreshed on the server.

### MaxMind GeoLite2 Country

MaxMind offers GeoLite databases in MMDB and CSV formats. Their docs say MMDB is optimized for fast lookups at scale, while CSV is good for loading into an application or database. GeoLite downloads require an account/license key and must be kept up to date.

Official docs:

- https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/
- https://support.maxmind.com/knowledge-base/articles/download-and-update-maxmind-databases

Fit:

- Good if we choose MMDB lookup with a dedicated library.
- Strong ecosystem and update tooling.

Risk:

- Adds a runtime dependency if using MMDB.
- CSV schema differs from the current `geo_data.json` shape.
- Account/license/update requirements add operational overhead.

### DB-IP Lite

DB-IP Lite offers free IP-to-country CSV/MMDB downloads, updated monthly, under Creative Commons Attribution terms.

Official docs: https://db-ip.com/db/lite.php

Fit:

- Simple downloadable CSV/MMDB option.
- Monthly replacement fits a scheduled refresh command.

Risk:

- Attribution requirements matter.
- Reduced accuracy compared with paid data.
- ASN/provider data may require a separate file or product.

## File In Memory vs Pandas vs Database

### Recommendation

Use a generated compact local lookup file loaded into memory, not pandas and not PostgreSQL, for the DropIPsByCountry incident path.

Target design:

```text
download/update source CSV
  -> build compact sorted range file
  -> incident run loads compact file once
  -> binary-search each IP locally
  -> write geo_data.json-compatible rows
```

### Why Not Pandas

Pandas is the wrong default for this production path:

- It is a heavy dependency for a small Python 2-compatible incident script.
- Loading a 418 MB CSV into pandas can take significant memory.
- The operation needed here is not dataframe analysis. It is a sorted numeric interval lookup.
- Installing pandas on older production servers can be painful due to binary wheels and old Python.

Pandas can be useful offline to inspect or transform the dataset, but it should not be required during overload response.

### Why Not PostgreSQL For This Repo

A DB-backed range table is good inside the Vindazo Django apps, but less ideal here:

- DropIPsByCountry currently runs as standalone scripts.
- Incident response should not require Django settings or DB credentials.
- DB lookup still adds an external dependency during an overload.
- Keeping the local firewall tool self-contained makes it easier to copy to servers.

Use the database pattern in application repos. Use a local file in this firewall repo.

### Why A Compact File

A compact file can be generated once and used many times:

```json
[
  [16777216, 16777471, "AU", "AS13335", "Cloudflare, Inc."],
  [16777472, 16778239, "CN", "AS...", "..."]
]
```

For runtime:

- load the list once
- keep `start_int` values in a parallel list
- `bisect_right(starts, ip_int) - 1`
- verify `ip_int <= end_int`
- return country/provider

This gives O(log n) lookup per IP. For 500 IPs, lookup should be effectively instant compared with API calls.

## Proposed Architecture

Add a local country provider layer without changing aggregation behavior first.

```text
output.txt
  -> get_ip_country.py
       -> geo_data.json cache hit
       -> local range lookup hit
       -> optional API fallback miss
  -> geo_data.json
```

The output contract should stay compatible with existing code:

```json
{
  "1.2.3.4": {
    "country": "CN",
    "region": "Unknown",
    "city": "Unknown",
    "org": "AS123 Example Provider",
    "loc": "Unknown"
  }
}
```

This lets `aggregate_generiek_subnets.py`, `recommend_country_prefixes.py`, `recommend_provider_subnets.py`, and `audit_generiek_subnets.py` keep working.

## Implementation Plan

### Phase 1: Offline Dataset Support

Add a script such as `build_ip_country_ranges.py`:

- input: source CSV path
- output: `data/fast_geo_ranges.tsv` plus `data/fast_geo_ranges.tsv.meta.json`
- skip IPv6 in first version, because current blocking flow is IPv4-oriented
- store:
  - `start_int`
  - `end_int`
  - `country`
  - `asn`
  - `as_name`
  - `source`
  - `updated_at`
- validate sorted non-empty output

Add docs for how to refresh the source file on the server.

### Phase 2: Local Lookup Helper

Add a small module such as `local_ip_country.py`:

- `ipv4_to_int(ip)`
- `load_ranges(path)`
- `lookup_ip(ip, ranges)`
- no pandas
- no Django
- Python 2 compatible

The loader can cache the parsed ranges in-process. `get_ip_country.py` only needs one load per run.

### Phase 3: Integrate Into `get_ip_country.py`

Change lookup order:

1. `geo_data.json` exact cache hit
2. local range lookup
3. API fallback only if explicitly enabled or local dataset misses

Suggested defaults:

```text
LOCAL_GEO_DB=data/fast_geo_ranges.tsv
IPINFO_FALLBACK=0
```

During an attack, the default should avoid network calls. Missing IPs can be marked as:

```json
{
  "country": "Unknown",
  "region": "Unknown",
  "city": "Unknown",
  "org": "Unknown",
  "loc": "Unknown",
  "source": "local_miss"
}
```

Unknown countries should not be blocked by country policy.

### Phase 4: Add Operational Metrics

Print clear counts:

```text
Country lookup source:
  cache_hits=480
  local_hits=33
  api_hits=0
  misses=0
  elapsed=0.42s
```

This matters during incidents. The operator needs to see if the run is waiting on API fallback or using local data.

## Edge Cases

- Private/local IPs should become `Unknown` and never match target countries.
- IPv6 can be ignored initially if the rest of the blocking path is IPv4-only.
- Overlapping ranges should be detected during build and fail the build unless source semantics are known.
- Dataset age should be printed. A stale file is still faster, but confidence falls over time.
- Provider/org output should remain compatible with `is_safe_provider()`.
- If country is protected (`BE`, `DE`, `FR`, `NL`), the existing policy should continue to skip it.

## Performance Expectation

Current cold path:

```text
unknown_ips * (HTTP latency + 1 second sleep)
```

Proposed local path:

```text
load local range file once + unknown_ips * binary_search
```

For 500 active IPs, this should move country lookup from many minutes to seconds or less, depending mostly on file load time.

If the compact range file is still too slow to load, generate a Python-friendly binary or SQLite artifact later. That is a second optimization, not the first implementation.

## Decision

Recommended path:

1. Keep `geo_data.json` as the exact-IP cache and existing contract.
2. Add local range lookup before any external API.
3. Use IPinfo Lite country+ASN as the first source because it matches the current data shape.
4. Generate a compact sorted range artifact for this repo.
5. Disable API fallback by default during incident runs.

Do not use pandas in the live incident path. Do not require PostgreSQL for this standalone firewall repo.

## Open Questions

- Should `data/fast_geo_ranges.tsv` be committed, ignored, or server-local only?
- Which source should be canonical: IPinfo Lite, MaxMind GeoLite2, or DB-IP Lite?
- Do we need ASN/provider names for safe-provider logic, or is country-only enough for phase 1?
- Should `run_prepare_generiek_blocks.sh` fail when the local dataset is missing, or continue with API fallback?

## Suggested Next Review Before Coding

Before implementation, decide:

- source format: IPinfo Lite `country_asn.csv.gz` or existing `ipinfo_lite.csv`
- artifact path: `data/fast_geo_ranges.tsv`
- fallback policy: default no API during incident, opt-in API via env var
- first supported family: IPv4 only

After those decisions, implementation is small and testable.

## Additive Command Plan

This second-stage plan keeps the current workflow intact. The existing `get_ip_country.py` and `run_prepare_generiek_blocks.sh` remain available and keep their current behavior. The fast path is introduced through separate commands and wrapper scripts so production can switch one cron line at a time.

### Design Rule

`geo_data.json` remains the central shared cache.

Both flows write the same shape:

```json
{
  "123.201.10.20": {
    "country": "IN",
    "region": "Unknown",
    "city": "Unknown",
    "org": "AS12345 Example Network",
    "loc": "Unknown",
    "source": "local_range"
  }
}
```

Existing consumers should not care whether a row came from the old API command or the new local range command. The current code mostly reads only `country` and `org`, so extra metadata such as `source`, `network`, `range_source`, or `lookup_updated_at` is safe.

### New Commands

#### 1. `build_fast_geo_ranges.py`

Purpose: convert a provider CSV into a compact local lookup artifact.

Example:

```bash
python2 build_fast_geo_ranges.py \
  --input data/ipinfo_lite.csv \
  --output data/fast_geo_ranges.tsv
```

Responsibilities:

- read IPinfo Lite style CSV with either `network,country,country_code,...` or `start_ip,end_ip,country,...`
- skip IPv6 in phase 1
- convert IPv4 CIDRs to integer ranges
- write sorted ranges by `start_int`
- include enough provider data to fill `geo_data.json.org`
- write a small metadata file such as `data/fast_geo_ranges_meta.json`

Output shape:

```json
{
  "version": 1,
  "source": "ipinfo_lite_csv",
  "created_at": 1787318400,
  "ranges": [
    [2076766208, 2076831743, "IN", "AS12345", "Example Network", "123.201.0.0/16"]
  ]
}
```

Validation:

- fail if the output has zero ranges
- fail if ranges are not sorted
- warn on overlaps
- print row counts: `loaded`, `ipv4_ranges`, `skipped_ipv6`, `skipped_invalid`

Why separate: this can be slow and should run outside an incident. It does not touch `geo_data.json`.

#### 2. `fast_geo_lookup.py`

Purpose: update `geo_data.json` for IPs in `output.txt` using the local range artifact.

Example:

```bash
python2 fast_geo_lookup.py \
  --input output.txt \
  --geo-data geo_data.json \
  --ranges data/fast_geo_ranges.tsv
```

Responsibilities:

- load `geo_data.json`
- read unique IPs from `output.txt`
- skip exact IPs already present in `geo_data.json`
- load local ranges once
- binary-search each missing IPv4
- append local hits to `geo_data.json`
- do not call any external API
- do not sleep

Suggested default behavior:

```text
cache_hits=480
local_hits=33
local_misses=0
api_calls=0
elapsed=0.6s
```

Miss behavior:

- default: do not write unknown rows, so existing report logic can still show missing geo IPs
- optional: `--write-unknown` can write `country=Unknown` if we want explicit audit rows

Why separate: it can be inserted before the existing prepare flow or used manually without changing the old command.

#### 3. `run_prepare_generiek_blocks_fast_geo.sh`

Purpose: a wrapper that runs the fast local country update first, then runs the existing prepare script.

Example:

```bash
PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks_fast_geo.sh
```

Internal flow:

```text
parse_ips.py
  -> fast_geo_lookup.py
  -> run_prepare_generiek_blocks.sh with SKIP_GEO_FETCH=1
```

This needs one small compatibility hook later: `run_prepare_generiek_blocks.sh` should accept `SKIP_GEO_FETCH=1` and skip only the current `get_ip_country.py` call. Everything after that remains unchanged:

```text
recommend_country_prefixes.py
recommend_provider_subnets.py
aggregate_generiek_subnets.py
cache_crawler_ips.py
audit_generiek_subnets.py
block_generiek_subnet.py
```

Non-disruption rule:

- old command still works:
  - `PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks.sh`
- new command is opt-in:
  - `PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks_fast_geo.sh`

#### 4. `refresh_fast_geo_data.sh`

Purpose: operational refresh command for the source dataset and compact artifact.

Example:

```bash
IPINFO_TOKEN=... ./refresh_fast_geo_data.sh
```

Old servers with broken CA/OpenSSL can use explicit insecure curl mode:

```bash
CURL_INSECURE=1 IPINFO_TOKEN=... ./refresh_fast_geo_data.sh
```

Default behavior: reuse `data/country_asn.csv` when it is at least 1 MB and not older than 24 hours, then rebuild the compact TSV from that local file. Use `FORCE_DOWNLOAD=1` when a fresh download is required.

Responsibilities:

- download source CSV into `data/`
- keep old artifact until the new one validates
- build to a temp output
- atomically move temp output into `data/fast_geo_ranges.tsv`
- print dataset age and range count

This command must not run during incident blocking. Put it in a daily or weekly cron, not in `monitor_server_status_blocks.py`.

### Optional Command: `compare_geo_lookup.py`

Purpose: confidence check before switching cron.

Example:

```bash
python2 compare_geo_lookup.py \
  --input output.txt \
  --geo-data geo_data.json \
  --ranges data/fast_geo_ranges.tsv \
  --sample 100
```

Responsibilities:

- compare existing `geo_data.json` country with local range country for sampled IPs
- print mismatch count
- show examples
- do not write files

This gives a safe rollout check without waiting for the next attack.

## Recommended Rollout

### Phase A: Build Artifact Only

Implement:

- `build_fast_geo_ranges.py`
- tests for CIDR-to-range conversion
- tests for sorted output and invalid row handling

No production behavior changes.

### Phase B: Manual Fast Lookup

Implement:

- `fast_geo_lookup.py`
- tests for:
  - exact cache hit skip
  - local range hit writes `geo_data.json`
  - local miss does not block
  - protected country rows are still only data, not block decisions

Manual operator command:

```bash
python2 parse_ips.py
python2 fast_geo_lookup.py --input output.txt --geo-data geo_data.json --ranges data/fast_geo_ranges.tsv
PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks.sh
```

This phase still allows the old script to call `get_ip_country.py`, but it should have little or nothing left to fetch because `geo_data.json` was already warmed locally.

### Phase C: Add No-Fetch Hook

Add `SKIP_GEO_FETCH=1` to `run_prepare_generiek_blocks.sh`.

Behavior:

```bash
if [ "$AGG_SOURCE" = "geo" ] && [ "$SKIP_GEO_FETCH" != "1" ]; then
  "$PYTHON_BIN" get_ip_country.py
fi
```

Then create `run_prepare_generiek_blocks_fast_geo.sh`.

This is the first phase that changes an existing script, but it is backward compatible because the default stays old behavior.

### Phase D: Switch Monitor Cron

Current style:

```cron
*/30 * * * * cd /home/downloads/DropIPsByCountry && PYTHON=python2 /usr/bin/python2 monitor_server_status_blocks.py --url http://127.0.0.1/server-status --threshold 200 >> monitor_server_status_blocks.log 2>&1
```

Future fast path should point monitor at the wrapper script:

```bash
PYTHON=python2 /usr/bin/python2 monitor_server_status_blocks.py \
  --url http://127.0.0.1/server-status \
  --threshold 200 \
  --script ./run_prepare_generiek_blocks_fast_geo.sh
```

If the fast wrapper fails because the artifact is missing or stale, it should stop before UFW apply unless an explicit fallback flag is set.

## Runtime Data Flow

Old flow:

```text
server-status
  -> input.txt
  -> parse_ips.py
  -> get_ip_country.py
       -> ipinfo.io per unknown IP
       -> sleep 1 second per hit
  -> geo_data.json
  -> aggregate and block
```

New opt-in flow:

```text
server-status
  -> input.txt
  -> parse_ips.py
  -> fast_geo_lookup.py
       -> geo_data.json cache
       -> local range lookup
       -> no external calls
  -> geo_data.json
  -> existing aggregate and block
```

## Failure Policy

For incident response, failure must be obvious and early.

Recommended defaults:

- missing `data/fast_geo_ranges.tsv`: fail fast in the new wrapper
- stale artifact older than configurable threshold: warn for manual command, fail in monitor wrapper
- corrupt artifact: fail before UFW commands
- local misses: continue, but do not classify unknown IPs as target countries
- old flow: still available as fallback by running the old command directly

Suggested env flags:

```text
FAST_GEO_RANGES=data/fast_geo_ranges.tsv
FAST_GEO_MAX_AGE_DAYS=14
FAST_GEO_ALLOW_STALE=0
FAST_GEO_WRITE_UNKNOWN=0
```

## `geo_data.json` Ownership

`geo_data.json` becomes a shared cache with multiple writers:

- old writer: `get_ip_country.py`
- new writer: `fast_geo_lookup.py`
- future optional writer: API backfill command

Rules:

- exact IP key wins
- do not overwrite existing rows by default
- add `--refresh-existing` only for deliberate maintenance
- write via temp file + atomic rename to avoid corrupt JSON if the process is killed
- keep old fields stable: `country`, `region`, `city`, `org`, `loc`
- extra fields are allowed: `source`, `network`, `asn`, `range_source`, `lookup_updated_at`

This keeps `aggregate_generiek_subnets.py` and reporting code stable.

## Test Plan

Unit tests:

- `ipv4_to_int("123.201.0.1")`
- `cidr_to_range("123.201.0.0/16")`
- binary search returns the most specific matching range if overlaps are allowed
- invalid IPs are skipped
- private IPs return `Unknown` or miss
- existing `geo_data.json` entries are not overwritten
- output JSON remains readable by existing aggregation tests

Integration tests:

- tiny CSV fixture builds a tiny range artifact
- `fast_geo_lookup.py` enriches an `output.txt` fixture
- `aggregate_generiek_subnets.py --source geo --filter-ips-file output.txt` sees the new rows
- `run_prepare_generiek_blocks_fast_geo.sh` invokes the old pipeline with `SKIP_GEO_FETCH=1`

Operational tests on server:

```bash
PYTHON=python2 python2 build_fast_geo_ranges.py --input data/ipinfo_lite.csv --output data/fast_geo_ranges.tsv
PYTHON=python2 python2 fast_geo_lookup.py --input output.txt --geo-data geo_data.json --ranges data/fast_geo_ranges.tsv
PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks_fast_geo.sh
```

Do not test first with `APPLY=1`.

## Engineering Recommendation

Build the new fast path as additive commands first.

Sequence:

1. `build_fast_geo_ranges.py`
2. `fast_geo_lookup.py`
3. `SKIP_GEO_FETCH=1` hook
4. `run_prepare_generiek_blocks_fast_geo.sh`
5. switch monitor `--script` after dry-run verification

This gives the speed improvement without risking the existing blocker. If the new path misbehaves, the old command still exists and `geo_data.json` remains usable by both.

## Fast UFW Apply Plan

Country lookup is only half of the incident delay. The current UFW apply path is also too slow under a live overload because `block_generiek_subnet.py` runs one subprocess per subnet:

```text
ufw insert 1 deny from <cidr>
ufw insert 1 deny from <cidr>
ufw insert 1 deny from <cidr>
...
ufw reload
```

With more than 23k existing UFW deny rules, every `insert 1` makes UFW parse and rewrite a large ruleset. If hundreds of new CIDRs are planned, the attack can rotate to new IPs faster than this loop can insert rules.

The fast path should add a separate apply command that edits the UFW user rules file once, then reloads once.

### New Command: `fast_apply_ufw_user_rules.py`

Purpose: batch-add planned deny CIDRs directly into the UFW user rules file instead of calling `ufw insert` per CIDR.

Example dry-run:

```bash
python2 fast_apply_ufw_user_rules.py \
  --input aggregated_generiek_subnets.json \
  --user-rules /lib/ufw/user.rules \
  --dry-run
```

Example apply:

```bash
sudo env python2 fast_apply_ufw_user_rules.py \
  --input aggregated_generiek_subnets.json \
  --user-rules /lib/ufw/user.rules \
  --apply \
  --reload
```

Path note: many Ubuntu/Debian systems use `/etc/ufw/user.rules`. Your server appears to use `/lib/ufw/user.rules`. The command should not hardcode this. It should require `--user-rules` or detect both paths and print the selected path before writing.

### Rule Format

For every CIDR, write the same two-line UFW user rule shape that already exists on the server:

```text
### tuple ### deny any any 0.0.0.0/0 any 111.42.0.0/16 in
-A ufw-user-input -s 111.42.0.0/16 -j DROP
```

The command must generate both lines. Writing only the `-A ufw-user-input` line may work at iptables level but can confuse later UFW status/edit operations because UFW expects its tuple comments.

### Insert Location

Order matters.

The current saved rules show deny rules before broad allow rules:

```text
-A ufw-user-input -s 111.42.0.0/16 -j DROP
-A ufw-user-input -s 223.166.0.0/16 -j DROP
-A ufw-user-input -s 112.113.0.0/16 -j DROP
-A ufw-user-input -p tcp -m tcp --dport 443 -j ACCEPT
-A ufw-user-input -p udp -m udp --dport 443 -j ACCEPT
-A ufw-user-input -p tcp -m tcp --dport 80 -j ACCEPT
```

New deny rules must be inserted before the first non-deny `ufw-user-input` allow/limit/return section. Appending deny rules after port 80/443 allows would not block web traffic, because packets would match the allow first.

Recommended insertion anchor:

1. Parse all lines.
2. Find the first `-A ufw-user-input` line that is not a source DROP deny.
3. Insert generated deny blocks immediately before that line.
4. Preserve everything else unchanged.

If no safe anchor is found, fail. Do not guess.

### Existing Rule Detection

Before writing, parse existing CIDRs from both tuple lines and iptables lines:

```text
### tuple ### deny ... <cidr> in
-A ufw-user-input -s <cidr> -j DROP
```

Then compute:

```text
candidate_cidrs - existing_cidrs = cidrs_to_add
```

This keeps the file idempotent. Idempotent means the same command can be run twice and the second run does not add duplicates.

### Safety Checks Before Write

The command should fail before touching the live file if any check fails:

- `user.rules` does not exist
- file does not contain `*filter`
- file does not contain `COMMIT`
- file does not contain `:ufw-user-input`
- no safe insertion anchor is found
- a generated CIDR is invalid
- a generated CIDR overlaps crawler allowlist
- a generated CIDR contains non-target source evidence from `geo_data.json`
- planned output would remove or reorder unrelated existing lines

It should reuse the existing planning/safety logic from `block_generiek_subnet.py` where possible:

- `load_candidate_networks`
- `split_country_mismatch_candidates`
- `load_allowlist_networks`
- `split_allowlisted_candidates`
- `parse_ufw_denies`
- `plan_new_rules`

Do not duplicate the country and allowlist safety rules in a second incompatible implementation.

### Write Strategy

Use a two-file write with backup:

```text
/lib/ufw/user.rules
/lib/ufw/user.rules.backup-20260821-103000
/lib/ufw/user.rules.tmp-<pid>
```

Flow:

1. Read live file.
2. Generate new content in memory.
3. Write temp file in the same directory.
4. Validate temp file.
5. Copy live file to timestamped backup.
6. Atomic rename temp file over live file.
7. Run `ufw reload`.
8. Run `ufw status numbered` and confirm new CIDRs are visible.

Atomic rename avoids a half-written rules file if the process dies during write.

### Validation Command

Before replacing the live file, test the generated file if the server supports it:

```bash
iptables-restore --test < /path/to/generated-user.rules
```

If `iptables-restore --test` is unavailable or incompatible with the UFW user file on that server, fallback validation should at minimum verify:

- generated file parses as text
- generated file has same prefix before insertion anchor
- generated file has same suffix after insertion anchor
- added block count matches `cidrs_to_add`
- `COMMIT` is still present after all user rules

The first production use should be dry-run only and include a copied temp output path for manual inspection.

### Reload vs Restart

Preferred apply step:

```bash
ufw reload
```

Reload should be enough if `user.rules` is valid. It applies the new generated ruleset once, which is the whole speed win.

Fallback:

```bash
service ufw restart
```

Use restart only if reload fails and the operator explicitly chooses it. A restart is a broader firewall operation and should not be automatic in the first implementation.

### New Wrapper: `run_prepare_generiek_blocks_fast_all.sh`

Purpose: combine fast country lookup and fast UFW apply without disturbing the old scripts.

Example dry-run:

```bash
PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks_fast_all.sh
```

Example apply:

```bash
sudo env PYTHON=python2 APPLY=1 UFW_USER_RULES=/lib/ufw/user.rules ./run_prepare_generiek_blocks_fast_all.sh
```

Internal flow:

```text
parse_ips.py
fast_geo_lookup.py
recommend_country_prefixes.py
recommend_provider_subnets.py
aggregate_generiek_subnets.py
cache_crawler_ips.py
audit_generiek_subnets.py
fast_apply_ufw_user_rules.py
```

This wrapper should not call `block_generiek_subnet.py` in apply mode. It can still call `block_generiek_subnet.py --dry-run` or shared planning functions for previews during rollout.

### Expected Performance

Current apply:

```text
new_rules * ufw insert cost + one reload
```

Fast apply:

```text
read 74k-line file + generate new file + one reload
```

The reload can still take time because the ruleset is large, but the per-rule UFW overhead disappears. For hundreds of CIDRs, this should be materially faster.

This still may not be enough if the attack rotates faster than one UFW reload can apply. If reload time remains too high, the next architecture step is `ipset`/`nftables` set-based blocking, where the kernel rule is stable and the blocked CIDR set is updated in bulk.

### Rollout

Phase 1: dry-run only

```bash
python2 fast_apply_ufw_user_rules.py \
  --input aggregated_generiek_subnets.json \
  --user-rules /lib/ufw/user.rules \
  --dry-run \
  --output-preview user.rules.preview
```

Check:

- preview contains the expected tuple + DROP pairs
- deny blocks are before 80/443 accepts
- old allow rules are unchanged
- duplicate existing CIDRs are skipped

Phase 2: apply on a small fixture or non-production copy

```bash
python2 fast_apply_ufw_user_rules.py \
  --input small_test_subnets.json \
  --user-rules copied-user.rules \
  --apply \
  --no-reload
```

Phase 3: production dry-run during incident window

```bash
PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks_fast_all.sh
```

Phase 4: production apply

```bash
sudo env PYTHON=python2 APPLY=1 UFW_USER_RULES=/lib/ufw/user.rules ./run_prepare_generiek_blocks_fast_all.sh
```

### Rollback

Rollback must be a first-class command before production apply.

Suggested command:

```bash
sudo env python2 restore_ufw_user_rules_backup.py \
  --backup /lib/ufw/user.rules.backup-20260821-103000 \
  --user-rules /lib/ufw/user.rules \
  --reload
```

Minimum manual rollback:

```bash
cp /lib/ufw/user.rules.backup-20260821-103000 /lib/ufw/user.rules
ufw reload
```

Do not delete backups automatically during the first rollout.

### Additional Tests

Unit tests:

- parse existing tuple + DROP pairs
- generate exact UFW block for one CIDR
- insert generated blocks before the first allow rule
- skip CIDRs already present in `user.rules`
- preserve all unrelated existing lines byte-for-byte
- fail when `COMMIT` is missing
- fail when no insertion anchor exists

Integration tests:

- fixture `user.rules` with denies and 80/443 allows
- fixture `aggregated_generiek_subnets.json`
- dry-run produces expected preview
- apply to temp file creates backup and new file
- no-reload mode never calls `ufw reload`

Operational tests:

```bash
python2 fast_apply_ufw_user_rules.py --input aggregated_generiek_subnets.json --user-rules /lib/ufw/user.rules --dry-run
cp /lib/ufw/user.rules /tmp/user.rules.test
python2 fast_apply_ufw_user_rules.py --input aggregated_generiek_subnets.json --user-rules /tmp/user.rules.test --apply --no-reload
```

Only remove `--no-reload` after the generated file has been inspected on the real server.

### Engineering Decision

Recommended: add `fast_apply_ufw_user_rules.py` as a separate apply path, not as a modification of `block_generiek_subnet.py` first.

Reason:

- the old safe path remains available
- the new path can be dry-run compared against the old plan
- file editing is powerful and risky, so it deserves isolated tests
- the monitor can switch via `--script` only after the fast wrapper proves itself

This pairs with fast geo lookup to remove both slow parts:

```text
old: API per unknown IP + UFW insert per CIDR
new: local range lookup + one UFW file rewrite + one reload
```
