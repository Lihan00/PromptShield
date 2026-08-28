import copy
import json
import re
from typing import Any


SESSION_COOKIE_NAMES = {
    "phpsessid",
    "jsessionid",
    "sessionid",
    "connect.sid",
    "sid",
    "beefhook",
}

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "pass",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "api_key",
    "apikey",
    "x_api_key",
    "token",
}

TEXT_RULES = [
    ("bearer_token", re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._\-+/=]+"), r"\1[REDACTED_TOKEN]"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b"), "[REDACTED_JWT]"),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED_API_KEY]"),
    ("access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_ACCESS_KEY]"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    ("phone", re.compile(r"\b(?:01[016789]-?\d{3,4}-?\d{4}|0(?:2|[3-6][1-5]|70|80)-?\d{3,4}-?\d{4})\b"), "[REDACTED_PHONE]"),
    ("rrn", re.compile(r"\b\d{6}-?[1-8]\d{6}\b"), "[REDACTED_RRN]"),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
]


def normalize_key(key: str) -> str:
    return key.lower().replace("-", "_").replace(".", "_")


def is_sensitive_key(key: str) -> bool:
    normalized_key = normalize_key(key)

    return (
        normalized_key in SENSITIVE_KEYS
        or "password" in normalized_key
        or "passwd" in normalized_key
        or "secret" in normalized_key
        or "token" in normalized_key
        or "api_key" in normalized_key
        or "apikey" in normalized_key
    )


def mask_case(case_data: dict) -> dict:
    """
    전처리된 JSON 데이터를 받아 request/response 내부 민감정보를 마스킹한다.
    """
    masked_case = copy.deepcopy(case_data)
    masked_fields = set(masked_case.get("masked_fields", []))

    if "request" in masked_case:
        masked_case["request"] = mask_value(masked_case["request"], masked_fields)

    if "response" in masked_case:
        masked_case["response"] = mask_value(masked_case["response"], masked_fields)

    masked_case["masked_fields"] = sorted(masked_fields)
    return masked_case


def mask_value(value: Any, masked_fields: set) -> Any:
    if isinstance(value, dict):
        result = {}

        for key, val in value.items():
            lower_key = str(key).lower()

            if lower_key == "authorization":
                result[key] = mask_authorization(str(val), masked_fields)
            elif lower_key in {"cookie", "set-cookie"}:
                result[key] = mask_cookie(str(val), masked_fields)
            elif is_sensitive_key(str(key)):
                result[key] = "[REDACTED_SECRET]"
                masked_fields.add("secret_param")
            else:
                result[key] = mask_value(val, masked_fields)

        return result

    if isinstance(value, list):
        return [mask_value(item, masked_fields) for item in value]

    if isinstance(value, str):
        return mask_text(value, masked_fields)

    return value


def mask_authorization(value: str, masked_fields: set) -> str:
    if re.search(r"(?i)^Bearer\s+", value):
        masked_fields.add("bearer_token")
        return re.sub(r"(?i)(Bearer\s+).+", r"\1[REDACTED_TOKEN]", value)

    if re.search(r"(?i)^Basic\s+", value):
        masked_fields.add("basic_auth")
        return re.sub(r"(?i)(Basic\s+).+", r"\1[REDACTED_BASIC_AUTH]", value)

    masked_fields.add("authorization")
    return "[REDACTED_AUTHORIZATION]"

def mask_cookie(value: str, masked_fields: set) -> str:
    parts = value.split(";")
    masked_parts = []

    for part in parts:
        item = part.strip()

        if "=" not in item:
            masked_parts.append(item)
            continue

        name, cookie_value = item.split("=", 1)
        normalized_name = name.lower()

        if normalized_name in SESSION_COOKIE_NAMES or is_sensitive_key(name):
            masked_parts.append(f"{name}=[REDACTED_SESSION]")
            masked_fields.add("cookie_session")
        else:
            masked_parts.append(f"{name}={mask_text(cookie_value, masked_fields)}")

    return "; ".join(masked_parts)


def mask_text(text: str, masked_fields: set) -> str:
    masked_text = text

    for field_name, pattern, replacement in TEXT_RULES:
        masked_text, count = pattern.subn(replacement, masked_text)

        if count > 0:
            masked_fields.add(field_name)

    masked_text = mask_password_like_text(masked_text, masked_fields)
    return masked_text


def mask_password_like_text(text: str, masked_fields: set) -> str:
    pattern = re.compile(
        r'(?i)(password|passwd|pwd|pass|client_secret|access_token|refresh_token|id_token|api_key|apikey|token)'
        r'(\s*[:=]\s*["\']?)'
        r'([^"\'&\s,}]+)'
    )

    masked_text, count = pattern.subn(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED_SECRET]",
        text,
    )

    if count > 0:
        masked_fields.add("secret_param")

    return masked_text


def build_llm_payload(masked_case: dict) -> dict:
    """
    LLM에게 전달할 request/response만 추출한다.
    expected_vuln, expected_verdict, notes 등 정답 라벨은 제외한다.
    """
    return {
        "request": masked_case.get("request"),
        "response": masked_case.get("response"),
    }


if __name__ == "__main__":
    case_data = {
        "id": "case_001",
        "source": "DVWA - SQL Injection (low security)",
        "request": {
            "method": "GET",
            "path": "/vulnerabilities/sqli/",
            "query_params": {
                "id": "1' OR '1'='1",
                "Submit": "Submit"
            },
            "headers": {
                "Host": "192.168.0.10",
                "Cookie": "PHPSESSID=abc123; security=low",
                "Authorization": "Bearer abcdef123456"
            },
            "body": None
        },
        "response": {
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html",
                "Set-Cookie": "PHPSESSID=xyz789"
            },
            "body_excerpt": "You have an error in your SQL syntax near '1' OR '1'='1'"
        },
        "expected_vuln": "SQL Injection",
        "expected_verdict": "취약",
        "notes": "SQL 에러 메시지가 응답에 그대로 노출됨"
    }

    masked_case = mask_case(case_data)
    llm_payload = build_llm_payload(masked_case)

    print("=== 마스킹 완료 JSON ===")
    print(json.dumps(masked_case, ensure_ascii=False, indent=2))

    print("\n=== LLM 전달용 JSON ===")
    print(json.dumps(llm_payload, ensure_ascii=False, indent=2))
