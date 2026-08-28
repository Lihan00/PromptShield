"""
PromptShield - 테스트용 예시 패킷 모음

1~5번은 AI로 만든 간단한 패킷들 이후는 실제 burp에서 가져온 패킷들

각 항목은 개발/검증 단계에서만 쓰는
참고 라벨(source, expected_vuln,expected_verdict)을 포함하지만, 이 라벨은 절대 LLM 프롬프트에 넣지 않는다.
"""

def get_case(case_id: str) -> dict:
    """id로 특정 케이스 하나 찾기"""
    for case in SAMPLE_PACKETS:
        if case["id"] == case_id:
            return case
    raise ValueError(f"케이스를 찾을 수 없습니다: {case_id}")

SAMPLE_PACKETS = [
    {
        "id": "case_001",
        "source": "DVWA - SQL Injection (low security)",
        "expected_vuln": "SQL Injection",
        "expected_verdict": "취약",
        "raw_request": (
            "GET /vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: PHPSESSID=2a1b3c4d5e6f7g8h9i0j; security=low\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            "Accept: text/html,application/xhtml+xml\r\n"
            "Connection: close\r\n"
            "\r\n"
        ),
        "raw_response": (
            "HTTP/2 200 OK\r\n"
            "Date: Wed, 26 Aug 2026 10:00:00 GMT\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Set-Cookie: PHPSESSID=2a1b3c4d5e6f7g8h9i0j; path=/\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<html><body><h2>Vulnerability: SQL Injection</h2>"
            "<pre>You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version for the right syntax to use "
            "near '1' OR '1'='1' LIMIT 1' at line 1</pre></body></html>"
        ),
    },
    {
        "id": "case_002",
        "source": "DVWA - SQL Injection (high security, blocked)",
        "expected_vuln": "SQL Injection",
        "expected_verdict": "양호",
        "raw_request": (
            "GET /vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: PHPSESSID=9z8y7x6w5v4u3t2s1r0q; security=high\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            "Connection: close\r\n"
            "\r\n"
        ),
        "raw_response": (
            "HTTP/3 200 OK\r\n"
            "Date: Wed, 26 Aug 2026 10:05:00 GMT\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<html><body><h2>Vulnerability: SQL Injection</h2>"
            "<pre>ID: 1' OR '1'='1<br />First name: <br />Surname: </pre>"
            "</body></html>"
        ),
    },
    {
        "id": "case_003",
        "source": "DVWA - XSS Reflected (low security)",
        "expected_vuln": "XSS",
        "expected_verdict": "취약",
        "raw_request": (
            "GET /vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: PHPSESSID=2a1b3c4d5e6f7g8h9i0j; security=low\r\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123signature\r\n"
            "Connection: close\r\n"
            "\r\n"
        ),
        "raw_response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<html><body><h2>Vulnerability: Reflected Cross Site Scripting (XSS)</h2>"
            "<div id='result'>Hello <script>alert(1)</script></div></body></html>"
        ),
    },
    {
        "id": "case_004",
        "source": "자체 Flask 테스트 서버 - 로그인 폼",
        "expected_vuln": "Security Misconfiguration",
        "expected_verdict": "취약",
        "raw_request": (
            "POST /login HTTP/1.1\r\n"
            "Host: localhost:5000\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 34\r\n"
            "Connection: close\r\n"
            "\r\n"
            "username=admin&password=1234abcd"
        ),
        "raw_response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Set-Cookie: session=eyJsb2dnZWRfaW4iOnRydWV9.abcXYZ123; Path=/\r\n"
            "Server: Werkzeug/2.0.1 Python/3.9.5\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<html><body>Login successful, welcome admin@example.com</body></html>"
        ),
    },
    {
        #그냥 잘못된 입력 예시 패킷 ㅇㅇ
        "id": "case_005",
        "source": "잘못된 입력 예시 - 유효성 검사 실패용",
        "expected_vuln": None,
        "expected_verdict": None,
        "raw_request": "이건 그냥 아무 텍스트임, 패킷 아님",
        "raw_response": "이것도 마찬가지",
    },
    {
        #실제 Burp 캡처에서 가져온 Path Traversal 의심 케이스
        "id": "case_006",
        "source": "실제 Burp 캡처 - 사내 게시판 파일 다운로드 (Path Traversal 의심)",
        "expected_vuln": "Path Traversal",
        "expected_verdict": "취약",
        "raw_request": (
            "GET /board/download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1\r\n"
            "Host: board.internal.example.com\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
            "Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "Referer: http://board.internal.example.com/board/list?category=%EA%B3%B5%EC%A7%80%EC%82%AC%ED%95%AD\r\n"
            "Cookie: JSESSIONID=8F3A1C9B2D4E5F6A7B8C9D0E1F2A3B4C; user_name=%ED%99%8D%EA%B8%B8%EB%8F%99\r\n"
            "X-Requested-With: XMLHttpRequest\r\n"
            "Connection: close\r\n"
            "\r\n"
        ),
        "raw_response": (
            "HTTP/1.1 200 OK\r\n"
            "Date: Thu, 27 Aug 2026 03:12:41 GMT\r\n"
            "Server: Apache-Coyote/1.1\r\n"
            "Content-Type: text/html; charset=EUC-KR\r\n"
            "Content-Length: 512\r\n"
            "Set-Cookie: JSESSIONID=8F3A1C9B2D4E5F6A7B8C9D0E1F2A3B4C; Path=/board\r\n"
            "X-Powered-By: JSP/2.3\r\n"
            "Connection: close\r\n"
            "\r\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "<!-- 게시판 첨부파일 다운로드 오류: 공지사항 파일을 찾을 수 없습니다 -->\n"
            "<html><body><p>알 수 없는 오류가 발생했습니다. 관리자에게 문의하세요.</p></body></html>"
        ),
        "notes": (
            "EUC-KR 인코딩 응답 + 한글 쿠키/파라미터 포함 실제 캡처 재현 예시. "
            "구조화 단계에서 헤더 개수 많음/한글 URL 인코딩 처리 엣지케이스 검증용."
        ),
    },
]
