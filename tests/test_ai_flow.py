import os
import sys
import types
import unittest


# AI/PDF 외부 패키지 없이 payload 생성과 후처리만 단위 테스트한다.
os.environ.setdefault("OPENAI_API_KEY", "unit-test-key")
if "openai" not in sys.modules:
    openai = types.ModuleType("openai")
    openai.OpenAI = lambda **kwargs: object()
    openai.OpenAIError = Exception
    sys.modules["openai"] = openai
if "dotenv" not in sys.modules:
    dotenv = types.ModuleType("dotenv")
    dotenv.load_dotenv = lambda: None
    sys.modules["dotenv"] = dotenv
if "playwright.sync_api" not in sys.modules:
    playwright = types.ModuleType("playwright")
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = lambda: None
    playwright.sync_api = sync_api
    sys.modules["playwright"] = playwright
    sys.modules["playwright.sync_api"] = sync_api

import main
from orchestrator import process_packet


REQUEST = "GET /search?q=test HTTP/1.1\nHost: example.com\nAccept: application/json\n\n"
RESPONSE = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"ok\": true}"


class PayloadTests(unittest.TestCase):
    def assert_sections(self, request, response, expected_keys):
        result = process_packet(
            request,
            response,
            skip_request=not bool(request),
            skip_response=not bool(response),
        )
        self.assertTrue(result["success"])
        self.assertEqual(list(result["llm_payload"]), expected_keys)

        context = main.parse_incoming_json(result["llm_payload"])
        payload = main.build_openai_request_payload(context)
        self.assertEqual(
            list(payload), ["model", "messages", "temperature", "response_format"]
        )
        user_content = payload["messages"][1]["content"]
        self.assertEqual("[HTTP Request (Masked)]" in user_content, bool(request))
        self.assertEqual("[HTTP Response (Masked)]" in user_content, bool(response))
        self.assertNotIn("null", user_content.lower())

    def test_request_and_response(self):
        self.assert_sections(REQUEST, RESPONSE, ["request", "response"])

    def test_request_only(self):
        self.assert_sections(REQUEST, "", ["request"])

    def test_response_only(self):
        self.assert_sections("", RESPONSE, ["response"])

    def test_neither_is_rejected(self):
        result = process_packet("", "", skip_request=True, skip_response=True)
        self.assertFalse(result["success"])


class PostprocessTests(unittest.TestCase):
    def result(self, verdict, severity):
        return main.postprocess_llm_result({
            "vulnerability_name": "SQL Injection",
            "verdict": verdict,
            "severity": severity,
        })

    def test_vulnerable_count_and_korean_mapping(self):
        result = self.result("VULNERABLE", "HIGH")
        self.assertEqual(result["vulnerability_count"], 1)
        self.assertEqual(result["verdict_ko"], "취약")
        self.assertEqual(result["severity_ko"], "높음")
        self.assertEqual(result["vulnerability_name_ko"], "SQL 인젝션")

    def test_safe_count_and_severity(self):
        result = self.result("SAFE", "HIGH")
        self.assertEqual(result["vulnerability_count"], 0)
        self.assertEqual(result["verdict_ko"], "양호")
        self.assertIsNone(result["severity"])
        self.assertIsNone(result["severity_ko"])

    def test_na_count_and_severity(self):
        result = self.result("N/A", "LOW")
        self.assertEqual(result["vulnerability_count"], 0)
        self.assertEqual(result["verdict_ko"], "판단 불가")
        self.assertIsNone(result["severity"])
        self.assertIsNone(result["severity_ko"])

    def test_all_canonical_korean_mappings(self):
        expected_severity = {
            "CRITICAL": "매우 심각", "HIGH": "높음", "MEDIUM": "보통",
            "LOW": "낮음", "INFO": "정보",
        }
        for severity, severity_ko in expected_severity.items():
            self.assertEqual(self.result("VULNERABLE", severity)["severity_ko"], severity_ko)

        expected_names = {
            "SQL Injection": "SQL 인젝션",
            "Command Injection": "명령어 인젝션",
            "Cross-Site Scripting (XSS)": "크로스사이트 스크립팅(XSS)",
            "Broken Access Control / IDOR": "접근 통제 취약점 / IDOR",
            "Server-Side Request Forgery (SSRF)": "서버 측 요청 위조(SSRF)",
            "Path Traversal": "경로 조작",
            "Unrestricted File Upload": "무제한 파일 업로드",
            "Sensitive Information Exposure": "민감정보 노출",
        }
        for name, name_ko in expected_names.items():
            result = main.postprocess_llm_result({
                "vulnerability_name": name,
                "verdict": "VULNERABLE",
                "severity": "INFO",
            })
            self.assertEqual(result["vulnerability_name_ko"], name_ko)


if __name__ == "__main__":
    unittest.main()
