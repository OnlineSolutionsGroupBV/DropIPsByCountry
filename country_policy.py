from __future__ import print_function

import re


DEFAULT_COUNTRY_CODES = [
    "CN", "BR", "IQ", "TR", "UZ", "IN", "SA", "VE", "RU", "KE", "BD",
    "AR", "JO", "PK", "MA", "ZA", "UA", "EC", "AZ", "UY", "MX", "PY",
    "KZ", "AE", "NP", "CO", "JM", "PH", "NI", "SY", "HK", "IR", "PS",
    "OM", "DZ", "SN", "BY", "TN", "GE", "ID", "RS", "AM", "AL", "SG",
    "MM", "ET", "LB", "MY", "VN", "BH", "TH", "US", "GB", "ES", "EG",
    "IT", "PL", "AU", "RO", "CL", "CA", "SE", "PT", "JP", "NG", "IL",
    "CG", "GR", "PE", "DO", "TW", "AO", "HU", "IE", "PA", "LY", "BG",
    "CZ", "KR", "NZ", "CI", "LK", "QA", "BO", "CR", "BF", "MN", "TZ",
    "GH", "MG", "KW", "CM", "TG", "MD", "DK", "KG", "UG", "NO", "XK",
]

PROTECTED_COUNTRY_CODES = ["BE", "DE", "FR", "NL"]
SAFE_PROVIDER_RE = re.compile(r"Google|Microsoft|OpenAI|Bing", re.I)


def default_country_block_policy():
    policy = {}
    for code in default_country_codes():
        policy[code] = {"target_prefix": 24, "min_hits": 1, "reason": "default country policy"}
    return policy


def parse_country_codes(value):
    return [code.strip().upper() for code in value.split(",") if code.strip()]


def effective_country_codes(codes):
    protected = set(PROTECTED_COUNTRY_CODES)
    result = []
    seen = set()
    for code in codes:
        code = code.strip().upper()
        if not code or code in protected or code in seen:
            continue
        result.append(code)
        seen.add(code)
    return result


def default_country_codes():
    return effective_country_codes(DEFAULT_COUNTRY_CODES)


def default_country_codes_csv():
    return ",".join(default_country_codes())


def protected_country_codes_csv():
    return ",".join(PROTECTED_COUNTRY_CODES)


def is_safe_provider(org):
    if org is None:
        return False
    return bool(SAFE_PROVIDER_RE.search(org))
