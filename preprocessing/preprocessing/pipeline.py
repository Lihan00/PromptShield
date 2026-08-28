from validator import validate_packet
from structurer import structure_request, structure_response
from extractor import extract_body_excerpt
from sample_packets import SAMPLE_PACKETS
import json

def run_preprocessing(request_text: str, response_text: str) -> dict:
    """
    검증 -> 구조화 -> 응답 발췌 까지 수행 / 마스킹팀이 이걸 받아서 수행
    """
    validation = validate_packet(request_text, response_text)
    if not validation["is_valid"]:
        return {"success": False, "errors": validation["errors"], "data": None}

    structured_request = structure_request(validation["raw_request"])
    structured_response = structure_response(validation["raw_response"])
    structured_response["body_excerpt"] = extract_body_excerpt(structured_response["body"])

    #딕셔너리 형태로 반환
    return {
        "success": True,
        "errors": [],
        "data": {
            "request": structured_request,
            "response": structured_response
        }
    }

#입력 데이터 터미널 실행 시 필요 함수
"""
def _read_multiline(prompt: str) -> str:
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
"""

if __name__ == "__main__":
    # 샘플 케이스 검증용
    """
    print(f"총 {len(SAMPLE_PACKETS)}개 케이스 검증\n")
 
    for case in SAMPLE_PACKETS:
        result = run_preprocessing(case["raw_request"], case["raw_response"])
        status = "통과" if result["success"] else "실패"
 
        print(f"========== [{case['id']}] {case['source']} -> {status} ==========")
 
        if not result["success"]:
            print(f"  오류: {result['errors']}")
        else:
            # 마스킹팀으로 실제 넘어가는 부분 = result["data"]
            print(json.dumps(result["data"], ensure_ascii=False, indent=2))
 
        print()
    """

    #실제 데이터 처리
    """
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
    """