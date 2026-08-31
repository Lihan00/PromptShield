"""
PromptShield - 전처리 파이프라인 진입점
validator -> structurer -> extractor 세 단계를 순서대로 실행.
마스킹팀은 이 파일의 run_preprocessing() 하나만 호출하면 됨.
"""

from validator import validate_packet
from structurer import structure_request, structure_response
from extractor import extract_body_excerpt


def run_preprocessing(
    request_text: str,
    response_text: str,
    skip_request: bool = False,
    skip_response: bool = False,
) -> dict:
    """
    검증 -> 구조화 -> 응답 발췌 까지 수행 / 마스킹팀이 이걸 받아서 수행.

    skip_request 또는 skip_response가 True면 (UI의 "입력 안함" 버튼 등으로
    명시적으로 표시된 경우) 해당 쪽은 구조화/발췌를 건너뛰고 결과의
    request 또는 response 값이 None으로 채워진다. 두 값 모두 skip이면
    검증 단계에서 에러로 처리됨 (validate_packet 참고).
    """
    validation = validate_packet(
        request_text, response_text,
        skip_request=skip_request, skip_response=skip_response
    )
    if not validation["is_valid"]:
        return {"success": False, "errors": validation["errors"], "data": None}

    data = {}
    if validation["raw_request"] is not None:
        data["request"] = structure_request(validation["raw_request"])
    if validation["raw_response"] is not None:
        structured_response = structure_response(validation["raw_response"])
        structured_response["body_excerpt"] = extract_body_excerpt(structured_response["body"])
        data["response"] = structured_response

    return {
        "success": True,
        "errors": [],
        "data": data
    }


def _read_multiline(prompt: str) -> str:
    """
    터미널에서 여러 줄 입력을 받는다.
    빈 줄을 연속 2번 입력하면 입력 종료로 간주.
    Burp에서 복사한 패킷을 그대로 붙여넣고 마지막에 Enter를 두 번 누르면 됨.
    """
    print(prompt)
    print("(입력 끝내려면 빈 줄에서 Enter 두 번)")
    lines = []
    blank_count = 0
    while True:
        line = input()
        if line == "":
            blank_count += 1
            if blank_count >= 2:
                break
        else:
            blank_count = 0
        lines.append(line)
    # 마지막에 추가된 빈 줄들 제거
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


if __name__ == "__main__":
    import json

    print("=== PromptShield 전처리 파이프라인 - 직접 입력 테스트 ===\n")

    request_text = _read_multiline("Request를 붙여넣으세요:")
    print()
    response_text = _read_multiline("Response를 붙여넣으세요:")
    print()

    result = run_preprocessing(request_text, response_text)

    if not result["success"]:
        print("❌ 검증 실패")
        for err in result["errors"]:
            print(f"  - {err}")
    else:
        print("✅ 전처리 성공 — 마스킹팀으로 넘어갈 데이터:\n")
        print(json.dumps(result["data"], ensure_ascii=False, indent=2))
