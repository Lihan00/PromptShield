"""
PromptShield - 데이터 전처리 1단계: 유효성 검증
- Request/Response를 각각 텍스트로 입력받아 형식이 올바른지 검사
- 통과하면 다음 단계(구조화)로 넘길 준비된 딕셔너리 반환
"""

import re

# HTTP 메서드 목록
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


def normalize_line_endings(text: str) -> str:
    """줄바꿈 통일 (\\r\\n, \\r -> \\n)"""
    return text.replace('\r\n', '\n').replace('\r', '\n')


def is_valid_request(text: str) -> bool:
    """첫 줄이 'METHOD /path HTTP/1.x' 형태인지 확인"""
    lines = text.strip().split('\n')
    if not lines:
        return False
    first_line = lines[0].strip()
    pattern = r'^(' + '|'.join(HTTP_METHODS) + r')\s+\S+\s+HTTP/\d(\.\d)?$'
    return bool(re.match(pattern, first_line, re.IGNORECASE))


def is_valid_response(text: str) -> bool:
    """첫 줄이 'HTTP/1.x 상태코드 메시지' 형태인지 확인"""
    lines = text.strip().split('\n')
    if not lines:
        return False
    first_line = lines[0].strip()
    pattern = r'^HTTP/\d(\.\d)?\s+\d{3}(\s+.*)?$'
    return bool(re.match(pattern, first_line))


def has_headers(text: str) -> bool:
    """
    첫 줄(요청/상태 라인) 다음에 최소 1개 이상의 'Key: Value' 헤더가 있는지 확인.
    GET처럼 body가 없는 경우도 있으므로 body 존재는 체크하지 않음.
    """
    lines = text.strip().split('\n')
    if len(lines) < 2:
        return False  # 요청/상태 라인만 있고 헤더가 아예 없음

    header_found = False
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "":
            break  # 빈 줄 = 헤더 끝, body 시작
        if ':' not in stripped:
            return False  # 헤더도 아니고 빈 줄도 아닌 이상한 줄
        header_found = True

    return header_found


def detect_packet_type(text: str) -> str:
    """
    request인지 response인지 자동 판별.
    UI에서 이미 구분해서 입력받기로 했으니 보조 확인용으로 사용.
    """
    if is_valid_response(text):
        return "response"
    if is_valid_request(text):
        return "request"
    return "unknown"


def validate_packet(
    request_text: str,
    response_text: str,
    skip_request: bool = False,
    skip_response: bool = False,
) -> dict:
    """
    request/response 원문을 받아 유효성 검사 수행.
    통과 시 다음 단계(구조화)로 넘길 준비된 딕셔너리를 반환.

    skip_request / skip_response: UI에서 "입력 안함" 버튼을 눌렀을 때
    명시적으로 True를 전달. 빈 텍스트만으로 "생략 의도"를 추측하지 않고,
    이 플래그로만 생략 여부를 판단한다 (빈칸이 실수인지 의도인지 구분 불가하므로).
    request/response 둘 다 skip이면 분석할 대상이 없으므로 에러 처리.
    """
    errors = []

    if skip_request and skip_response:
        return {
            "is_valid": False,
            "errors": ["Request와 Response 중 최소 하나는 입력해야 합니다."],
            "raw_request": None,
            "raw_response": None,
        }

    request_text = normalize_line_endings(request_text or "") if not skip_request else None
    response_text = normalize_line_endings(response_text or "") if not skip_response else None

    # --- Request 검증 (skip이면 건너뜀) ---
    if not skip_request:
        if not request_text.strip():
            errors.append("Request가 비어있습니다.")
        elif not is_valid_request(request_text):
            errors.append(
                "올바른 HTTP Request 형식이 아닙니다. "
                "첫 줄은 'GET /path HTTP/1.1' 같은 형태여야 합니다."
            )
        elif not has_headers(request_text):
            errors.append("Request에 헤더가 없습니다 (Host 등 최소 1개 필요).")

    # --- Response 검증 (skip이면 건너뜀) ---
    if not skip_response:
        if not response_text.strip():
            errors.append("Response가 비어있습니다.")
        elif not is_valid_response(response_text):
            errors.append(
                "올바른 HTTP Response 형식이 아닙니다. "
                "첫 줄은 'HTTP/1.1 200 OK' 같은 형태여야 합니다."
            )
        elif not has_headers(response_text):
            errors.append("Response에 헤더가 없습니다 (Content-Type 등 최소 1개 필요).")

    is_valid = len(errors) == 0

    return {
        "is_valid": is_valid,
        "errors": errors,
        # 통과 시에만 다음 단계로 넘길 정규화된 원문 포함
        # skip된 쪽은 애초에 None (구조화 단계에서 "생략됨"으로 처리)
        "raw_request": request_text if (is_valid and not skip_request) else None,
        "raw_response": response_text if (is_valid and not skip_response) else None,
    }


def validate_packet_file(file_text: str) -> dict:
    """
    .txt 파일 업로드용 - 파일 하나에 request/response가 같이 들어있는 경우 대비.
    구분자는 팀에서 정하기 나름인데, 우선 빈 줄 2개(\\n\\n\\n) 이상을
    request/response 경계로 가정하는 기본 버전.
    UI팀과 실제 업로드 포맷 정해지면 이 부분만 교체하면 됨.
    """
    text = normalize_line_endings(file_text)
    parts = re.split(r'\n\s*\n\s*\n', text.strip(), maxsplit=1)

    if len(parts) != 2:
        return {
            "is_valid": False,
            "errors": ["파일에서 Request와 Response 구간을 구분할 수 없습니다."],
            "raw_request": None,
            "raw_response": None,
        }

    return validate_packet(parts[0], parts[1])


if __name__ == "__main__":
    from sample_packets import SAMPLE_PACKETS

    print(f"총 {len(SAMPLE_PACKETS)}개 케이스 검증\n")

    for case in SAMPLE_PACKETS:
        result = validate_packet(case["raw_request"], case["raw_response"])
        status = "✅ 통과" if result["is_valid"] else "❌ 실패"

        print(f"[{case['id']}] {case['source']} -> {status}")
        if not result["is_valid"]:
            for err in result["errors"]:
                print(f"    - {err}")
        print()
