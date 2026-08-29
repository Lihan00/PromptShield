"""
PromptShield - 데이터 전처리 3단계: 응답 발췌 (response에만 적용)

- 구조화된 response body(수천~수만 자일 수 있음)에서 취약점 판단에
  필요한 부분만 추출해 body_excerpt를 만든다.
- response.headers는 이 단계에서 다루지 않는다 (자르지 않고 그대로 유지되는 필드).
  보안헤더/쿠키 플래그 체크는 헤더 전체가 있어야 판단 가능하기 때문.

취약점 판단에 쓸 부분을 찾는 방법 - 우선순위 1 -> 2 -> 3 순서로 시도하고,
앞 단계에서 찾으면 뒷 단계는 시도하지 않는다 (첫 매칭만 사용):

1순위. 에러 메시지 키워드 주변
   - SQLi, Path Traversal, Command Injection, 디버그모드 노출 등
     "이게 나오면 취약점 신호일 확률이 높은" 키워드가 body에 있는지 찾는다.
2순위. 요청 페이로드 반사(reflect) 여부
   - 주로 XSS 판단용. 우리가 요청에 실어보낸 문자열이 응답에 그대로
     다시 나타나면(필터링 없이 반사되면) 위험 신호로 본다.
3순위. 위 두 가지 다 해당 없으면 앞부분을 max_len 만큼 truncate
   - 특이사항 없는 평범한 응답이라는 뜻. 그래도 "정상 응답이었다"는
     최소한의 근거는 남겨두기 위해 앞부분만 잘라서 보존한다.
"""

import re

# 진단하기로 한 취약점 카테고리별로 정리한 감시 키워드.
# "많이" 넣는 게 목표가 아니라, 우리가 진단하기로 한 카테고리
# (SQLi/Command Injection, Path Traversal, Security Misconfiguration)를
# 빠짐없이 커버하는 게 목표. XSS는 여기 대신 2순위(반사 여부 체크)가 담당.
ERROR_KEYWORDS = [
    # --- SQL Injection ---
    "SQL syntax",
    "mysql_fetch",
    "ORA-",  # Oracle DB 에러 코드 (예: ORA-00933)
    "SQLSTATE",
    "Unclosed quotation mark",  # MSSQL 계열 에러
    "you have an error in your sql",

    # --- Path Traversal (파일 유출 흔적) ---
    "root:x:0:0",       # 리눅스 /etc/passwd 유출 시 나타나는 패턴
    "daemon:x:",         # 위와 동일 맥락
    "/bin/bash",
    "/bin/sh",
    "[extensions]",      # 윈도우 win.ini 유출 시 나타나는 패턴
    "[fonts]",

    # --- Command Injection ---
    "command not found",             # 유닉스 계열 셸 에러
    "is not recognized as an internal",  # 윈도우 cmd 에러
    "uid=",              # id 명령어 실행 결과 (uid=0(root) gid=0(root) 형태)

    # --- 일반 에러/스택트레이스 (여러 카테고리 공통 신호) ---
    "Warning:",
    "Fatal error",
    "Traceback",
    "stack trace",
    "Exception",
    "at java.",           # 자바 스택트레이스 특징

    # --- Security Misconfiguration (디버그 모드/설정 노출) ---
    "Django Version",
    "Whitelabel Error Page",  # 스프링 부트 기본 에러 페이지
    "DEBUG = True",
]

CONTEXT_CHARS = 250  # 키워드/페이로드 앞뒤로 확보할 문맥 길이


def _find_error_keyword_excerpt(body: str) -> str:
    """
    1순위: body 안에서 ERROR_KEYWORDS 중 하나라도 나타나는지 검사.
    가장 먼저 발견되는 키워드 위치를 기준으로 앞뒤 CONTEXT_CHARS자를 잘라 반환.
    아무 키워드도 없으면 None 반환 (2순위로 넘어가라는 신호).
    """
    for keyword in ERROR_KEYWORDS:
        match = re.search(re.escape(keyword), body, re.IGNORECASE)
        if match:
            start = max(0, match.start() - CONTEXT_CHARS)
            end = min(len(body), match.end() + CONTEXT_CHARS)
            return body[start:end]
    return None


def _find_reflected_payload_excerpt(body: str, request_payload: str) -> str:
    """
    2순위: 우리가 request에 실어보낸 문자열(request_payload, 주로 XSS
    페이로드)이 응답 body에 그대로 반사되어 나타나는지 검사.
    발견 위치 기준 앞뒤 CONTEXT_CHARS자를 잘라 반환.
    request_payload가 없거나 못 찾으면 None 반환 (3순위로 넘어가라는 신호).
    """
    if not request_payload:
        return None
    idx = body.find(request_payload)
    if idx == -1:
        return None
    start = max(0, idx - CONTEXT_CHARS)
    end = min(len(body), idx + len(request_payload) + CONTEXT_CHARS)
    return body[start:end]


def extract_body_excerpt(body: str, request_payload: str = "", max_len: int = 1000) -> str:
    """
    response body에서 LLM에 넘길 발췌본(body_excerpt)을 만드는 최종 함수.
    1순위 -> 2순위 -> 3순위 순서로 시도하고, 먼저 성공하는 방법의 결과를 사용.
    """
    if not body:
        return ""

    # 1순위: 에러/취약점 흔적 키워드 먼저 확인
    excerpt = _find_error_keyword_excerpt(body)
    if excerpt is not None:
        return excerpt

    # 2순위: 요청 페이로드가 그대로 반사됐는지 확인 (XSS 등)
    excerpt = _find_reflected_payload_excerpt(body, request_payload)
    if excerpt is not None:
        return excerpt

    # 3순위: 특이사항 없음 -> 앞부분만 잘라서 최소한의 근거 보존
    return body[:max_len]