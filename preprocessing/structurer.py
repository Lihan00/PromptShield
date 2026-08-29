"""
PromptShield - 데이터 전처리 2단계: 구조화
- validator를 통과한 정규화된 raw_request/raw_response 텍스트를
  필드 단위 딕셔너리로 분리한다.

- body는 Content-Type 헤더를 보고 파싱 방식을 분기하며,
  파싱 실패 시 예외를 던지지 않고 원문 문자열을 그대로 담는다.
"""

import json
import re
from urllib.parse import urlparse, parse_qs

REQUEST_LINE_PATTERN = re.compile(r'^(\S+)\s+(\S+)\s+HTTP/(\d\.\d)$', re.IGNORECASE)
STATUS_LINE_PATTERN = re.compile(r'^HTTP/\d\.\d\s+(\d{3})(\s+.*)?$')


def _flatten_qs(parsed: dict) -> dict:
    """parse_qs가 반환하는 {key: [values]} 형태를 단일 값/리스트로 정리."""
    return {k: (v[0] if len(v) == 1 else v) for k, v in parsed.items()}


def _split_head_body(lines_after_first: list) -> tuple:
    """첫 줄을 제외한 나머지 줄에서 헤더 dict와 body 원문(str)을 분리."""
    headers = {}
    blank_idx = len(lines_after_first)

    for i, line in enumerate(lines_after_first):
        if line.strip() == "":
            blank_idx = i
            break
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

    if blank_idx < len(lines_after_first):
        body_text = "\n".join(lines_after_first[blank_idx + 1:])
    else:
        body_text = ""

    return headers, body_text


def _get_content_type(headers: dict) -> str:
    for key, value in headers.items():
        if key.lower() == "content-type":
            return value.lower()
    return ""


def parse_body(body_text: str, headers: dict):
    """Content-Type에 따라 body를 파싱. 실패/미지원 형식이면 원문 문자열 유지."""
    if body_text is None or body_text.strip() == "":
        return None

    content_type = _get_content_type(headers)

    if "application/json" in content_type:
        try:
            return json.loads(body_text)
        except (json.JSONDecodeError, ValueError):
            return body_text

    if "application/x-www-form-urlencoded" in content_type:
        try:
            return _flatten_qs(parse_qs(body_text, keep_blank_values=True))
        except Exception:
            return body_text

    return body_text


def structure_request(raw_request: str) -> dict:
    """
    Raw request 텍스트를 다음 형태로 구조화:
    {"method", "path", "query_params", "headers", "body"}
    """
    lines = raw_request.split('\n')
    first_line = lines[0].strip()

    match = REQUEST_LINE_PATTERN.match(first_line)
    method = match.group(1).upper() if match else ""
    full_path = match.group(2) if match else ""

    parsed_url = urlparse(full_path)
    query_params = _flatten_qs(parse_qs(parsed_url.query, keep_blank_values=True))

    headers, body_text = _split_head_body(lines[1:])
    body = parse_body(body_text, headers)

    return {
        "method": method,
        "path": parsed_url.path,
        "query_params": query_params,
        "headers": headers,
        "body": body,
    }


def structure_response(raw_response: str) -> dict:
    """
    Raw response 텍스트를 다음 형태로 구조화:
    {"status_code", "headers", "body"}
    body 발췌(body_excerpt)는 3단계(extractor)에서 별도 처리한다.
    """
    lines = raw_response.split('\n')
    first_line = lines[0].strip()

    match = STATUS_LINE_PATTERN.match(first_line)
    status_code = int(match.group(1)) if match else None

    headers, body_text = _split_head_body(lines[1:])

    return {
        "status_code": status_code,
        "headers": headers,
        "body": body_text,
    }


if __name__ == "__main__":

    from sample_packets import SAMPLE_PACKETS
    from validator import validate_packet
     
    print(f"총 {len(SAMPLE_PACKETS)}개 케이스 검증\n")
     
    for case in SAMPLE_PACKETS:
        result = validate_packet(case["raw_request"], case["raw_response"])
        if not result["is_valid"]:
            print(f"케이스 {case['id']} 검증 실패: {result['errors']}")
            continue

        structured_request = structure_request(result["raw_request"])
        structured_response = structure_response(result["raw_response"])

        print(f"케이스 {case['id']} 구조화 결과:")
        print("Request:", structured_request)
        print("Response:", structured_response)
        print("-" * 40)
