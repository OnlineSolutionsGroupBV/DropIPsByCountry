# DropIPsByCountry

DropIPsByCountry is a pragmatic firewall automation toolkit for mitigating high-volume bot, crawler, and abusive traffic against Apache-hosted websites. It was built for a network of small niche job sites where traffic can suddenly spread across hundreds of client IPs, countries, providers, and subnets.

The project extracts IP addresses from Apache `/server-status`, access logs, or any text input, enriches them with country/provider data, generates CIDR blocks, audits crawler allowlists, and applies UFW deny rules safely.

Open-source project:

https://github.com/OnlineSolutionsGroupBV/DropIPsByCountry

## Recommended Production Flow

The recommended setup is a cron monitor that checks Apache server-status every 30 minutes. When Apache has too many busy workers, it saves the status page as `input.txt` and runs the blocking flow.

### 1. Verify Apache Server Status

From the server:

```bash
cd /home/downloads/DropIPsByCountry
PYTHON=python2 /usr/bin/python2 monitor_server_status_blocks.py \
  --url http://127.0.0.1/server-status \
  --host-header www.nieuwejobs.com \
  --threshold 200 \
  --dry-run
```

If you must use HTTPS and the old Python/OpenSSL stack cannot validate the certificate:

```bash
PYTHON=python2 /usr/bin/python2 monitor_server_status_blocks.py \
  --url https://www.nieuwejobs.com/server-status \
  --threshold 200 \
  --insecure \
  --dry-run
```

Expected output below threshold:

```text
Busy requests: 44
Threshold: 200
Below threshold. No block run.
```

### 2. Install The Cron Job

Edit crontab:

```bash
crontab -e
```

Preferred local HTTP version:

```cron
*/30 * * * * cd /home/downloads/DropIPsByCountry && PYTHON=python2 /usr/bin/python2 monitor_server_status_blocks.py --url http://127.0.0.1/server-status --host-header www.nieuwejobs.com --threshold 200 >> monitor_server_status_blocks.log 2>&1
```

HTTPS fallback:

```cron
*/30 * * * * cd /home/downloads/DropIPsByCountry && PYTHON=python2 /usr/bin/python2 monitor_server_status_blocks.py --threshold 200 --insecure >> monitor_server_status_blocks.log 2>&1
```

Check cron:

```bash
crontab -l
tail -f /home/downloads/DropIPsByCountry/monitor_server_status_blocks.log
```

The monitor uses `.server_status_block.lock`, so overlapping cron runs skip automatically.

## Manual Incident Run

If you already saved an Apache server-status response into `input.txt`, run:

```bash
cd /home/downloads/DropIPsByCountry
PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks.sh
```

Review:

```bash
less aggregated_generiek_subnets.json
less generiek_country_report.json
less provider_dangerous_subnets.txt
```

Apply after review:

```bash
PYTHON=python2 APPLY=1 ./run_prepare_generiek_blocks.sh
```

## Fast Manual Incident Run

The fast path is opt-in. It keeps `geo_data.json` as the shared country/provider cache, but avoids per-IP API calls and per-rule `ufw insert` calls.

Build or refresh the local country range artifact first:

```bash
cd /home/downloads/DropIPsByCountry
SOURCE_CSV=/path/to/ipinfo_lite.csv PYTHON=python2 ./refresh_fast_geo_data.sh
```

Supported CSV inputs are IPinfo `network,...` exports and IPinfo `start_ip,end_ip,country,...` exports.

Or download IPinfo Lite directly when `IPINFO_TOKEN` is available:

```bash
IPINFO_TOKEN=... PYTHON=python2 ./refresh_fast_geo_data.sh
```

If the server has an old CA/OpenSSL setup and `curl` fails certificate verification, use the explicit insecure download fallback:

```bash
CURL_INSECURE=1 IPINFO_TOKEN=... PYTHON=python2 ./refresh_fast_geo_data.sh
```

By default the refresh command reuses `data/country_asn.csv` when it is at least 1 MB and not older than 24 hours, then rebuilds `data/fast_geo_ranges.tsv` from that local file. Use `FORCE_DOWNLOAD=1` to force a fresh IPinfo download.

Fast geo lookup only, then old safe UFW apply path:

```bash
PYTHON=python2 APPLY=0 ./run_prepare_generiek_blocks_fast_geo.sh
```

Fast geo lookup plus fast `user.rules` batch apply preview:

```bash
PYTHON=python2 APPLY=0 UFW_USER_RULES=/lib/ufw/user.rules ./run_prepare_generiek_blocks_fast_all.sh
```

`run_prepare_generiek_blocks_fast_all.sh` fetches live Apache server-status into `input.txt` by default before parsing. Defaults:

```text
FETCH_SERVER_STATUS=1
SERVER_STATUS_URL=http://127.0.0.1/server-status
SERVER_STATUS_HOST=www.nieuwejobs.com
```

To analyze an already saved `input.txt`, disable the fetch:

```bash
FETCH_SERVER_STATUS=0 PYTHON=python2 APPLY=0 UFW_USER_RULES=/lib/ufw/user.rules ./run_prepare_generiek_blocks_fast_all.sh
```

For a live incident via the monitor threshold gate:

```bash
sudo env PYTHON=python2 \
  /usr/bin/python2 monitor_server_status_blocks.py \
  --url http://127.0.0.1/server-status \
  --host-header www.nieuwejobs.com \
  --threshold 200 \
  --script ./run_prepare_generiek_blocks_fast_all.sh \
  --env POLICY_MODE=0 \
  --env TARGET_PREFIX=16 \
  --env MIN_HITS=1 \
  --env UFW_USER_RULES=/lib/ufw/user.rules \
  --apply
```

`run_prepare_generiek_blocks.sh` refuses to continue when parsing finds zero IPs. Use `ALLOW_EMPTY_INPUT=1` only for an intentional empty dry-run.

Review:

```bash
less aggregated_generiek_subnets.json
less generiek_country_report.json
less runs/$(ls -1 runs | tail -1)/user.rules.preview
```

Apply only after review:

```bash
sudo env PYTHON=python2 APPLY=1 UFW_USER_RULES=/lib/ufw/user.rules ./run_prepare_generiek_blocks_fast_all.sh
```

The fast UFW apply command writes a timestamped backup before replacing `user.rules`. It then runs one `ufw reload` instead of hundreds of `ufw insert` commands.
Because it edits `user.rules` directly, the apply command must run as root. Dry-runs do not need write access unless you write the preview into a protected directory.

Rollback example:

```bash
sudo env python2 restore_ufw_user_rules_backup.py \
  --backup /lib/ufw/user.rules.backup-YYYYMMDD-HHMMSS \
  --user-rules /lib/ufw/user.rules \
  --apply \
  --reload
```

Compare local range country lookup against existing `geo_data.json` before switching production workflow:

```bash
python2 compare_geo_lookup.py --input output.txt --geo-data geo_data.json --ranges data/fast_geo_ranges.tsv --sample 100
```

## Emergency Broad Blocking

For a very broad distributed request pool, `/24` can be too narrow. In our incident data, almost every active IP came from a different `/24`, so `/24` blocking added many small rules but did not stop the pressure quickly enough.

The emergency option is `/16`:

```bash
PYTHON=python2 POLICY_MODE=0 TARGET_PREFIX=16 MIN_HITS=1 APPLY=0 ./run_prepare_generiek_blocks.sh
```

Review first, then apply:

```bash
PYTHON=python2 POLICY_MODE=0 TARGET_PREFIX=16 MIN_HITS=1 APPLY=1 ./run_prepare_generiek_blocks.sh
```

Use this carefully. A `/16` contains 65,536 IPv4 addresses. It is effective as an incident response tool, but it is intentionally aggressive.

## Default Policy Mode

`run_prepare_generiek_blocks.sh` uses policy mode by default:

```bash
PYTHON=python2 ./run_prepare_generiek_blocks.sh
```

Policy mode:

- parses `input.txt`
- writes parsed IPs to `output.txt`
- updates `geo_data.json`
- refreshes country recommendations
- refreshes provider recommendations for review
- aggregates the current snapshot with per-country prefix settings
- caps recommendation `min_hits` to `1` for server-status snapshots
- skips known safe providers such as Google, Bing/Microsoft, and OpenAI
- audits generated CIDRs before applying UFW rules
- saves a run snapshot under `runs/<timestamp>/`

Provider candidates are not merged by default, because they are based on historical `geo_data.json` and can add old provider ranges that are not present in the current attack snapshot.

Merge provider candidates only after review:

```bash
PYTHON=python2 MERGE_PROVIDER_CANDIDATES=1 APPLY=0 ./run_prepare_generiek_blocks.sh
```

## Safety Rules

The default country policy excludes protected local markets:

```text
BE, DE, FR, NL
```

The blocker also skips candidate subnets that:

- overlap crawler allowlists
- contain country mismatches from `geo_data.json`
- are already covered by existing UFW deny rules

Crawler allowlists include OpenAI, Google, Bing/Microsoft ranges where available.

## Apache Configuration For Server Status

For cron, local access is simplest:

```apache
<Location /server-status>
    SetHandler server-status
    Require local
</Location>
```

On older Apache syntax using `mod_access_compat`, allow the local server IPs explicitly:

```apache
<Location /server-status>
    SetHandler server-status
    Order deny,allow
    Deny from all
    Allow from 127.0.0.1 ::1 148.251.129.80
</Location>
```

Reload Apache:

```bash
apachectl configtest
service apache2 reload
```

Test:

```bash
curl http://127.0.0.1/server-status -H 'Host: www.nieuwejobs.com' | head
```

## What The Main Files Mean

- `input.txt`: raw source text, usually Apache `/server-status` or logs.
- `output.txt`: parsed IP addresses from `input.txt`.
- `geo_data.json`: unique IP to country/provider cache.
- `aggregated_generiek_subnets.json`: CIDRs generated for blocking.
- `generiek_country_report.json`: country statistics for the current run.
- `generiek_blocked_candidate_ips.txt`: source IPs selected for blocking.
- `generiek_allowed_non_target_ips.txt`: source IPs not selected for blocking.
- `provider_dangerous_subnets.txt`: human-readable provider/ASN review list.
- `blocked_generiek_ips.txt`: tracking file for successfully inserted blocks.
- `runs/<timestamp>/`: full run snapshots for later analysis.

## Initial Setup

Clone:

```bash
git clone https://github.com/OnlineSolutionsGroupBV/DropIPsByCountry.git
cd DropIPsByCountry
```

Install Python dependencies if needed:

```bash
python2 -m pip install ipaddress
```

Configure the IPInfo token in `get_ip_country.py`.

## Core Commands

Parse IPs:

```bash
python2 parse_ips.py
```

Update geo cache:

```bash
python2 get_ip_country.py
```

Build crawler allowlist:

```bash
python2 cache_crawler_ips.py --cache-dir ip_cache
```

Audit generated subnets:

```bash
python2 audit_generiek_subnets.py \
  --input aggregated_generiek_subnets.json \
  --allowlist ip_cache/allowlist_cidrs.json
```

Dry-run UFW additions:

```bash
python2 block_generiek_subnet.py --sudo --dry-run
```

Apply UFW additions:

```bash
python2 block_generiek_subnet.py --sudo
```

Use a saved UFW snapshot for local testing:

```bash
python3 block_generiek_subnet.py \
  --input aggregated_generiek_subnets.json \
  --ufw-status-file ufw_status_numbered \
  --dry-run
```

## Existing UFW Audit And Cleanup

Run this when setting up a server or after a firewall incident:

```bash
bash run_audit_existing_ufw.sh
```

Apply cleanup after review:

```bash
APPLY_CLEAN=1 bash run_audit_existing_ufw.sh
```

Manual steps:

```bash
python2 cache_crawler_ips.py --cache-dir ip_cache
python2 find_bad_ufw_rules.py \
  --allowlist ip_cache/allowlist_cidrs.json \
  --output bad_ufw_rules.json \
  --sudo
python2 clean_bad_ufw_rules.py --input bad_ufw_rules.json --sudo --dry-run
python2 clean_bad_ufw_rules.py --input bad_ufw_rules.json --sudo
```

`clean_bad_ufw_rules.py` deletes rules from high rule number to low rule number so UFW renumbering does not delete the wrong rule.

## Country Recommendations

Generate per-country prefix recommendations:

```bash
python2 recommend_country_prefixes.py --geo-data geo_data.json
```

Outputs:

- `country_prefix_recommendations.txt`
- `country_prefix_recommendations.json`
- `country_prefix_plan.sh`

The recommendation engine chooses wider prefixes only when enough historical IPs cluster inside that prefix. During current server-status snapshot blocking, `run_prepare_generiek_blocks.sh` caps `min_hits` to `1`, because a live snapshot often has one unique IP per subnet.

## Provider / ASN Recommendations

Generate provider-specific recommendations:

```bash
python2 recommend_provider_subnets.py --geo-data geo_data.json
```

Outputs:

- `provider_subnet_recommendations.txt`
- `provider_dangerous_subnets.txt`
- `provider_subnet_recommendations.json`
- `provider_subnet_candidates.json`

Review first:

```bash
less provider_dangerous_subnets.txt
```

Apply provider candidate CIDRs only when you deliberately want broader historical provider blocking:

```bash
python2 block_generiek_subnet.py \
  --input provider_subnet_candidates.json \
  --sudo \
  --dry-run
```

## Updating Existing UFW Rules From Country Recommendations

Create a replacement plan for existing live UFW deny rules:

```bash
python2 plan_ufw_country_rule_updates.py \
  --recommendations country_prefix_recommendations.json \
  --geo-data geo_data.json \
  --sudo
```

Review:

```bash
less ufw_country_update_plan.txt
```

Dry-run apply commands:

```bash
python2 apply_ufw_country_rule_updates.py --plan ufw_country_update_plan.json --sudo
```

Apply:

```bash
python2 apply_ufw_country_rule_updates.py --plan ufw_country_update_plan.json --sudo --apply
```

The planner does not add new countries. It only prepares replacements for existing `DENY IN` rules and skips protected countries, mixed-country evidence, and crawler allowlist overlaps.

## Apache Log Analysis

For multi-site servers, Apache access logs are often a better decision source than one live `/server-status` snapshot.

```bash
python2 analyze_apache_subnets.py \
  --log-dir /var/log/apache2 \
  --geo-data geo_data.json \
  --prefixes 32,24,20,16 \
  --min-requests 100 \
  --min-unique-ips 3
```

Outputs:

- `apache_subnet_report.json`
- `apache_subnet_report.txt`
- `apache_subnet_candidates.txt`
- `apache_log_ips.txt`
- `apache_missing_geo_ips.txt`

Decision labels:

- `CANDIDATE`: subnet passes thresholds and contains only target-country evidence.
- `LOW_EVIDENCE`: traffic exists, but not enough evidence to block automatically.
- `REVIEW_NON_TARGET_PRESENT`: subnet contains non-target evidence and should not be applied blindly.

## Run Snapshot Analysis

Analyze previous runs:

```bash
python2 analyze_runs.py --runs-dir runs
```

Outputs:

- `runs_analysis.txt`
- `runs_analysis.json`

This helps compare input IP counts, generated subnet counts, top countries, and repeated versus new IPs across incidents.

## CIDR Size Reference

| CIDR | IP count | Notes |
| --- | ---: | --- |
| `/32` | 1 | One IP |
| `/24` | 256 | Narrow, often safe but weak against broad pools |
| `/20` | 4,096 | Medium provider/local range |
| `/18` | 16,384 | Broad |
| `/16` | 65,536 | Very broad, useful as emergency brake |

## UFW Notes

UFW rule order matters. First match wins. `block_generiek_subnet.py` inserts deny rules near the top:

```bash
ufw insert 1 deny from 1.2.3.0/24
```

Useful inspection commands:

```bash
sudo ufw status numbered
sudo ufw status verbose
iptables -L -n --line-numbers
iptables-save > iptables.txt
```

Save firewall snapshots for analysis:

```bash
sudo ufw status numbered > ufw_status_numbered
sudo ufw status verbose > ufw_status_verbose
sudo iptables-save > iptables.txt
```

## Legacy Country-Specific Scripts

Older scripts such as `block_cn_ips.py`, `aggregate_cn_subnets.py`, and `block_cn_subnet.py` are still present for historical compatibility. The recommended production path is now:

```bash
monitor_server_status_blocks.py
run_prepare_generiek_blocks.sh
aggregate_generiek_subnets.py
block_generiek_subnet.py
```

## Contact

Project:

https://github.com/OnlineSolutionsGroupBV/DropIPsByCountry

Company links:

https://ats.work/

https://onlinesolutionsgroup.website/
