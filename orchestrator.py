"""
검증 -> 구조화 -> 응답 발췌 -> 마스킹 -> LLM 전달용 payload 생성까지
전체 파이프라인을 한 번에 실행하는 단일 진입점.

LLM API(OpenAI 등) 호출 코드는 여기 넣지 않는다. LLM팀이 이 파일의
process_packet()을 호출해서 나온 llm_payload를 가져다 실제 API에 넘긴다.
"""

import json
import sys

from pipeline import run_preprocessing
from masker import mask_case, build_llm_payload


def process_packet(request_text: str, response_text: str) -> dict:
    """
    request/response 원문 텍스트를 받아서
    검증 -> 구조화 -> 응답 발췌 -> 마스킹 -> LLM 전달용 payload 생성까지
    전체 파이프라인을 한 번에 실행한다.

    반환값:
      성공 시: {"success": True, "llm_payload": {...}, "masked_case": {...}}
      실패 시: {"success": False, "errors": [...]}

    - masked_case: 마스킹 완료된 전체 데이터 (masked_fields 포함, UI에서
      마스킹 전/후 비교용으로 쓸 수 있음)
    - llm_payload: masked_case에서 request/response만 뽑은 것 (실제 LLM API에 넘길 것)
    """
    try:
        preprocessed = run_preprocessing(request_text, response_text)
    except Exception as e:
        return {"success": False, "errors": [f"처리 중 오류: {e}"]}

    if not preprocessed["success"]:
        return {"success": False, "errors": preprocessed["errors"]}

    try:
        masked_case = mask_case(preprocessed["data"])
        llm_payload = build_llm_payload(masked_case)
    except Exception as e:
        return {"success": False, "errors": [f"처리 중 오류: {e}"]}

    return {
        "success": True,
        "llm_payload": llm_payload,
        "masked_case": masked_case,
    }

#입력 데이터 터미널 실행 시 필요 함수

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



if __name__ == "__main__":
    # Windows 콘솔(cp949)에서 이모지/한글 출력 시 UnicodeEncodeError 방지
    sys.stdout.reconfigure(encoding="utf-8")

    print("=== PromptShield 오케스트레이터 - 직접 입력 테스트 ===\n")

    request_text = _read_multiline("Request를 붙여넣으세요:")
    print()
    response_text = _read_multiline("Response를 붙여넣으세요:")
    print()

    result = process_packet(request_text, response_text)

    if not result["success"]:
        print("처리 실패")
        for err in result["errors"]:
            print(f"  - {err}")
    else:
        print("처리 성공 — LLM팀으로 넘어갈 데이터 (llm_payload):\n")
        print(json.dumps(result["llm_payload"], ensure_ascii=False, indent=2))
