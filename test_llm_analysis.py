"""PromptShield 다중 취약점 구조의 실제 OpenAI API 라이브 검증 스크립트."""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parent
SAMPLE_PATH = ROOT / "samples" / "masked_sample.json"
REQUIRED_FINDING_FIELDS = {
    "vulnerability_name",
    "owasp_category",
    "verdict",
    "severity",
    "reason",
    "evidence",
    "impact",
    "remediation_summary",
    "additional_check",
}


def _allow_main_import_without_pdf_dependency() -> None:
    """Playwright가 없어도 LLM 전용 라이브 테스트에서 main을 import할 수 있게 한다."""
    try:
        __import__("playwright.sync_api")
    except ModuleNotFoundError:
        playwright = types.ModuleType("playwright")
        sync_api = types.ModuleType("playwright.sync_api")
        sync_api.sync_playwright = None
        playwright.sync_api = sync_api
        sys.modules["playwright"] = playwright
        sys.modules["playwright.sync_api"] = sync_api


load_dotenv(ROOT / ".env")
_allow_main_import_without_pdf_dependency()
import main  # noqa: E402  main의 실제 OpenAI client/prompt/후처리를 재사용한다.


def _safe_error(error: Exception) -> str:
    message = str(error)
    api_key = os.environ.get("OPENAI_API_KEY")
    return message.replace(api_key, "[REDACTED_API_KEY]") if api_key else message


def _print_json(title: str, value: Any) -> None:
    print(f"\n--- {title} ---")
    print(json.dumps(value, ensure_ascii=False, indent=2))


def _load_sample() -> dict:
    if not SAMPLE_PATH.is_file():
        raise FileNotFoundError(f"테스트 입력 파일이 없습니다: {SAMPLE_PATH}")
    with SAMPLE_PATH.open("r", encoding="utf-8") as file:
        sample = json.load(file)
    if not isinstance(sample, dict) or "request" not in sample or "response" not in sample:
        raise ValueError("masked_sample.json에는 request와 response 객체가 모두 필요합니다.")
    return sample


def _validate_raw_schema(raw_result: Any) -> list[str]:
    errors = []
    if not isinstance(raw_result, dict):
        return ["OpenAI 원본 응답의 최상위 값이 JSON 객체가 아닙니다."]

    vulnerabilities = raw_result.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return [
            "OpenAI 원본 응답이 배열 Schema를 따르지 않았습니다: "
            "'vulnerabilities'가 배열이 아닙니다."
        ]

    for index, finding in enumerate(vulnerabilities):
        label = f"vulnerabilities[{index}]"
        if not isinstance(finding, dict):
            errors.append(f"{label}가 JSON 객체가 아닙니다.")
            continue
        missing = sorted(REQUIRED_FINDING_FIELDS - finding.keys())
        if missing:
            errors.append(f"{label} 필수 필드 누락: {', '.join(missing)}")
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict):
            errors.append(f"{label}.evidence가 JSON 객체가 아닙니다.")
        else:
            for section in ("request", "response"):
                if not isinstance(evidence.get(section), list):
                    errors.append(f"{label}.evidence.{section}가 배열이 아닙니다.")
    return errors


def _validate_final_result(final_result: dict) -> list[str]:
    errors = []
    vulnerabilities = final_result.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return ["후처리 결과의 'vulnerabilities'가 배열이 아닙니다."]

    actual_count = sum(
        finding.get("verdict") == "VULNERABLE"
        for finding in vulnerabilities
        if isinstance(finding, dict)
    )
    if final_result.get("vulnerability_count") != actual_count:
        errors.append(
            "vulnerability_count 불일치: "
            f"결과={final_result.get('vulnerability_count')}, 실제={actual_count}"
        )

    non_vulnerable_count = sum(
        finding.get("verdict") in {"SAFE", "N/A"}
        for finding in vulnerabilities
        if isinstance(finding, dict)
    )
    if actual_count + non_vulnerable_count != len(vulnerabilities):
        errors.append("허용되지 않은 verdict가 후처리 결과에 남아 있습니다.")

    expected_representative = main.select_representative_vulnerability(vulnerabilities)
    for field in ("vulnerability_name", "verdict", "severity"):
        if final_result.get(field) != expected_representative.get(field):
            errors.append(f"대표 취약점의 {field}가 최고 severity 선택 결과와 다릅니다.")

    for index, finding in enumerate(vulnerabilities):
        label = f"vulnerabilities[{index}]"
        verdict = finding.get("verdict")
        severity = finding.get("severity")
        name = finding.get("vulnerability_name")
        if finding.get("verdict_ko") != main.VERDICT_KO.get(verdict):
            errors.append(f"{label} verdict 영문/한글 매핑 불일치")
        if finding.get("severity_ko") != main.SEVERITY_KO.get(severity):
            errors.append(f"{label} severity 영문/한글 매핑 불일치")
        if name not in main.VULNERABILITY_NAME_KO:
            errors.append(f"{label}에 등록되지 않은 canonical 취약점명: {name}")
        elif finding.get("vulnerability_name_ko") != main.VULNERABILITY_NAME_KO[name]:
            errors.append(f"{label} 취약점명 영문/한글 매핑 불일치")
        if verdict in {"SAFE", "N/A"} and (
            severity is not None or finding.get("severity_ko") is not None
        ):
            errors.append(f"{label} SAFE/N/A severity가 null이 아닙니다.")
    return errors


def _call_openai_once(case_name: str, llm_input: dict) -> dict:
    print("\n" + "=" * 72)
    print(f"LIVE CASE: {case_name}")
    print(f"LLM 입력 섹션: {', '.join(llm_input.keys())}")
    print("=" * 72)

    context = main.parse_incoming_json(llm_input)
    api_payload = main.build_openai_request_payload(context)
    response = main.client.chat.completions.create(**api_payload)
    content = response.choices[0].message.content
    if not content:
        raise ValueError("OpenAI 응답 content가 비어 있습니다.")

    try:
        raw_result = json.loads(content)
    except json.JSONDecodeError as error:
        print("\n--- OpenAI 원본 텍스트 ---")
        print(content)
        raise ValueError(f"OpenAI 응답이 유효한 JSON이 아닙니다: {error}") from error

    _print_json("OpenAI 원본 응답", raw_result)
    raw_errors = _validate_raw_schema(raw_result)
    if raw_errors:
        raise AssertionError("\n".join(raw_errors))

    final_result = main.postprocess_llm_result(raw_result)
    _print_json("postprocess_llm_result() 최종 결과", final_result)
    final_errors = _validate_final_result(final_result)
    if final_errors:
        raise AssertionError("\n".join(final_errors))

    print(
        "\n검증 성공: "
        f"전체 항목 {len(final_result['vulnerabilities'])}개, "
        f"VULNERABLE {final_result['vulnerability_count']}개, "
        f"대표 {final_result.get('vulnerability_name')}"
    )
    return final_result


def main_live_test() -> int:
    if not os.environ.get("OPENAI_API_KEY"):
        print("오류: .env에 OPENAI_API_KEY가 설정되어 있지 않습니다.")
        return 2

    try:
        sample = _load_sample()
    except Exception as error:
        print(f"오류: {_safe_error(error)}")
        return 2

    cases = [
        ("Request + Response", {"request": sample["request"], "response": sample["response"]}),
        ("Request only", {"request": sample["request"]}),
        ("Response only", {"response": sample["response"]}),
    ]
    passed = 0
    failures = []
    for case_name, llm_input in cases:
        try:
            _call_openai_once(case_name, llm_input)
            passed += 1
        except Exception as error:
            failures.append((case_name, _safe_error(error)))
            print(f"\n검증 실패 [{case_name}]: {_safe_error(error)}")

    print("\n" + "=" * 72)
    print("LIVE TEST SUMMARY")
    print(f"성공: {passed}/{len(cases)}")
    for case_name, message in failures:
        print(f"- 실패 [{case_name}]: {message}")
    if passed == len(cases):
        print("평가: 세 입력 조합에서 현재 vulnerabilities 배열 구조를 따랐습니다.")
        return 0
    print("평가: 배열 구조가 모든 라이브 호출에서 안정적으로 유지되지 않았습니다.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main_live_test())
