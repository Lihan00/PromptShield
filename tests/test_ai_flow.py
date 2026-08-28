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
    def test_prompt_requests_vulnerabilities_array(self):
        self.assertIn('"vulnerabilities": [', main.SYSTEM_PROMPT)
        self.assertIn("Do not generate vulnerability_count", main.SYSTEM_PROMPT)

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
    def finding(self, name="SQL Injection", verdict="VULNERABLE", severity="HIGH", **extra):
        finding = {
            "vulnerability_name": name,
            "verdict": verdict,
            "severity": severity,
            "reason": f"{name} 분석 결과",
            "evidence": {"request": ["요청 근거"], "response": ["응답 근거"]},
            "impact": "영향",
            "remediation_summary": "조치",
            "additional_check": None,
        }
        finding.update(extra)
        return finding

    def result(self, vulnerabilities):
        return main.postprocess_llm_result({"vulnerabilities": vulnerabilities})

    def test_zero_vulnerabilities(self):
        result = self.result([])
        self.assertEqual(result["vulnerability_count"], 0)
        self.assertEqual(result["vulnerabilities"], [])

    def test_one_vulnerability(self):
        result = self.result([self.finding()])
        self.assertEqual(result["vulnerability_count"], 1)

    def test_three_vulnerabilities_are_counted_from_array(self):
        result = self.result([
            self.finding("Sensitive Information Exposure", severity="MEDIUM"),
            self.finding("Security Misconfiguration", severity="LOW"),
            self.finding("Cross-Site Scripting (XSS)", severity="HIGH"),
        ])
        self.assertEqual(result["vulnerability_count"], 3)
        self.assertEqual(len(result["vulnerabilities"]), 3)
        self.assertEqual(result["vulnerability_name"], "Cross-Site Scripting (XSS)")
        self.assertEqual(result["severity"], "HIGH")

    def test_mixed_verdicts_count_only_vulnerable(self):
        result = self.result([
            self.finding("SQL Injection", "VULNERABLE", "HIGH"),
            self.finding("Command Injection", "SAFE", "CRITICAL"),
            self.finding("Path Traversal", "N/A", "LOW"),
            self.finding("Sensitive Information Exposure", "VULNERABLE", "MEDIUM"),
        ])
        self.assertEqual(result["vulnerability_count"], 2)
        self.assertEqual(len(result["vulnerabilities"]), 4)
        self.assertIsNone(result["vulnerabilities"][1]["severity"])
        self.assertIsNone(result["vulnerabilities"][2]["severity"])

    def test_representative_tie_keeps_first(self):
        result = self.result([
            self.finding("SQL Injection", severity="HIGH"),
            self.finding("Cross-Site Scripting (XSS)", severity="HIGH"),
        ])
        self.assertEqual(result["vulnerability_name"], "SQL Injection")

    def test_full_vulnerability_details_are_preserved(self):
        original = self.finding(custom_detail={"key": "value"})
        result = self.result([original])
        finding = result["vulnerabilities"][0]
        for key, value in original.items():
            self.assertEqual(finding[key], value)

    def test_report_contains_count_and_all_findings(self):
        result = self.result([
            self.finding("SQL Injection", severity="HIGH"),
            self.finding("Security Misconfiguration", severity="LOW"),
        ])
        report = main.generate_report_html_content(result)
        self.assertIn("전체 취약점 건수", report)
        self.assertIn("전체 취약점 분석 결과 (2건 탐지)", report)
        self.assertIn("SQL Injection", report)
        self.assertIn("Security Misconfiguration", report)

    def test_vulnerable_korean_mapping(self):
        result = self.result([self.finding()])
        self.assertEqual(result["verdict_ko"], "취약")
        self.assertEqual(result["severity_ko"], "높음")
        self.assertEqual(result["vulnerability_name_ko"], "SQL 인젝션")

    def test_safe_count_and_severity(self):
        result = self.result([self.finding(verdict="SAFE", severity="HIGH")])
        self.assertEqual(result["vulnerability_count"], 0)
        self.assertEqual(result["verdict_ko"], "양호")
        self.assertIsNone(result["severity"])
        self.assertIsNone(result["severity_ko"])

    def test_na_count_and_severity(self):
        result = self.result([self.finding(verdict="N/A", severity="LOW")])
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
            result = self.result([self.finding(severity=severity)])
            self.assertEqual(result["severity_ko"], severity_ko)

        expected_names = {
            "SQL Injection": "SQL 인젝션",
            "Command Injection": "명령어 인젝션",
            "Cross-Site Scripting (XSS)": "크로스사이트 스크립팅(XSS)",
            "Broken Access Control / IDOR": "접근 통제 취약점 / IDOR",
            "Server-Side Request Forgery (SSRF)": "서버 측 요청 위조(SSRF)",
            "Path Traversal": "경로 조작",
            "Unrestricted File Upload": "무제한 파일 업로드",
            "Sensitive Information Exposure": "민감정보 노출",
            "Security Misconfiguration": "보안 설정 오류",
        }
        for name, name_ko in expected_names.items():
            result = self.result([self.finding(name=name, severity="INFO")])
            self.assertEqual(result["vulnerability_name_ko"], name_ko)


if __name__ == "__main__":
    unittest.main()
