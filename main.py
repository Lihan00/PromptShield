import json
import os
from openai import OpenAI
import markdown
from weasyprint import HTML
from dotenv import load_dotenv


# .env 파일 로드
load_dotenv()

# 환경 변수에서 키 불러오기
api_key = os.getenv("OPENAI_API_KEY")

# OpenAI 클라이언트 초기화
client = OpenAI(api_key=api_key)


def parse_incoming_json(json_data: dict) -> str:
    """
    앞 팀에서 넘겨준 JSON 스키마에서 request와 response를 추출해 
    LLM이 분석하기 좋은 텍스트 형태로 변환합니다.
    """
    req = json_data.get("request", {})
    res = json_data.get("response", {})
    
    context = f"""
[Target Information]
- Source/Context: {json_data.get('source')}

[HTTP Request]
Method: {req.get('method')}
Path: {req.get('path')}
Query Params: {json.dumps(req.get('query_params'), ensure_ascii=False)}
Headers: {json.dumps(req.get('headers'), ensure_ascii=False)}
Body: {req.get('body')}

[HTTP Response]
Status Code: {res.get('status_code')}
Headers: {json.dumps(res.get('headers'), ensure_ascii=False)}
Body Excerpt: {res.get('body_excerpt')}
    """
    return context.strip()

def run_llm_diagnosis(packet_context: str) -> dict:
    """
    OpenAI API를 호출하여 취약점 진단 결과를 구조화된 JSON 형태로 받아옵니다.
    """
    system_prompt = """
    You are a Lead Penetration Tester and Principal Application Security Engineer.
    Analyze the provided masked HTTP Request/Response logs and diagnose security vulnerabilities based on OWASP Top 10.
    Output must be strictly formatted as valid JSON. Do not include markdown code blocks if not needed, or ensure the output is pure JSON.
    """

    user_prompt = f"""
    다음 패킷 로그를 분석하여 진단 결과를 아래 JSON 구조로만 출력해줘. 다른 설명은 적지 마.

    [Target Packet Log]
    {packet_context}

    [Required JSON Output Schema]
    {{
      "vulnerability_found": true,
      "vulnerability_name": "SQL Injection", 
      "owasp_category": "Injection",
      "severity": "High",
      "result": "VULNERABLE",
      "reason": {
        "request_fingerprint": "요청 파라미터에 SQL 특수문자가 포함됨",
        "response_context": "응답 본문에서 SQL 구문 에러 메시지가 노출됨"
      },
      "remediation_summary": "PreparedStatement를 사용하여 바인딩 쿼리를 구현해야 합니다."
    }}
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2,
            response_format={"type": "json_object"} # JSON 출력을 강제함
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {"error": str(e)}

def generate_report_and_pdf(llm_result: dict, output_path: str = "PromptShield_Report.pdf"):
    """
    LLM 진단 결과와 우리의 시큐어코딩 데이터베이스(SECURE_CODE_DATABASE)를 결합하여 
    Markdown을 만들고, WeasyPrint로 PDF를 생성합니다.
    """
    vuln_name = llm_result.get("vulnerability_name", "")
    
    # 데이터베이스에서 해당 취약점의 시큐어코딩 코드 가져오기
    code_guide = SECURE_CODE_DATABASE.get(vuln_name, {
        "language": "N/A",
        "vulnerable_code": "// 관련 코드 없음",
        "secure_code": "// 관련 코드 없음"
    })

    # Markdown 보고서 본문 구성
    markdown_content = f"""
    ## 📊 1. 취약점 요약 대시보드
    - **취약점 탐지 여부**: {'🚨 취약 발견' if llm_result.get('vulnerability_found') else '🛡️ 양호'}
    - **위험도**: `{llm_result.get('severity', 'N/A')}`
    - **OWASP 카테고리**: {llm_result.get('owasp_category', 'N/A')}
    - **진단 결과**: {llm_result.get('result', 'N/A')}

    ## 🔍 2. 취약점 상세 분석 (3단계 Inference Engine)
    - **취약점 명칭**: {vuln_name}
    - **판단 근거**:
      - **Request Fingerprint**: {llm_result.get('reason', {}).get('request_fingerprint', '')}
      - **Response Context**: {llm_result.get('reason', {}).get('response_context', '')}

    ## 🛠️ 3. 시큐어코딩 가이드 및 패치 (4단계 Remediation)
    - **대응 방법 요약**: {llm_result.get('remediation_summary', '')}
    - **적용 언어**: {code_guide['language']}

    ### ❌ 취약한 코드 (Vulnerable Code)
    ```java
    {code_guide['vulnerable_code']}
    ```

    ### ⭕ 안전한 패치 코드 (Secure Code Patch)
    ```java
    {code_guide['secure_code']}
    ```
    """

    # HTML 변환 및 PDF 빌드
    html_body = markdown.markdown(markdown_content, extensions=['fenced_code', 'tables'])
    
    styled_html = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <style>
            @page {{ size: A4; margin: 20mm 15mm; }}
            body {{ font-family: 'Malgun Gothic', sans-serif; color: #2c3e50; line-height: 1.6; font-size: 10pt; }}
            h1 {{ color: #1a252f; font-size: 18pt; border-bottom: 2px solid #2c3e50; padding-bottom: 10px; }}
            h2 {{ border-bottom: 2px solid #3498db; padding-bottom: 5px; margin-top: 25px; font-size: 13pt; color: #2980b9; }}
            h3 {{ font-size: 11pt; margin-top: 15px; }}
            pre {{ background-color: #2d3748; color: #e2e8f0; padding: 12px; border-radius: 6px; font-size: 8.5pt; line-height: 1.4; }}
            code {{ font-family: monospace; color: #c7254e; background: #f8f9fa; padding: 2px 4px; }}
            pre code {{ color: inherit; background: transparent; padding: 0; }}
            ul {{ padding-left: 20px; }}
            li {{ margin-bottom: 5px; }}
        </style>
    </head>
    <body>
        <h1>🛡️ PromptShield 보안 진단 보고서</h1>
        {html_body}
    </body>
    </html>
    """
    
    HTML(string=styled_html).write_pdf(output_path)
    print(f"[+] PDF 보고서가 성공적으로 생성되었습니다: {output_path}")

# --- 실행 메인 테스트부 ---
if __name__ == "__main__":
    # 앞 팀이 넘겨줄 JSON 스키마 시뮬레이션
    sample_json_from_masking_team = {
        "id": "case_001",
        "source": "DVWA - SQL Injection (low security)",
        "request": {
            "method": "GET",
            "path": "/vulnerabilities/sqli/",
            "query_params": {"id": "1' OR '1'='1", "Submit": "Submit"},
            "headers": {
                "Host": "localhost",
                "Cookie": "PHPSESSID=[REDACTED_SESSION]; security=low",
                "Authorization": "Bearer [REDACTED_TOKEN]"
            },
            "body": None
        },
        "response": {
            "status_code": 200,
            "headers": {"Content-Type": "text/html"},
            "body_excerpt": "... You have an error in your SQL syntax near '1' OR '1'='' at line 1 ..."
        },
        "masked_fields": ["cookie_session", "bearer_token"],
        "expected_vuln": "SQL Injection"
    }

    print("1. 앞 팀 JSON 데이터 파싱 중...")
    packet_context = parse_incoming_json(sample_json_from_masking_team)

    print("2. LLM(OpenAI) 진단 수행 중...")
    llm_output_json = run_llm_diagnosis(packet_context)
    print(f"   - 진단된 취약점: {llm_output_json.get('vulnerability_name')}")

    print("3. 시큐어코딩 가이드 결합 및 PDF 보고서 빌드 중...")
    generate_report_and_pdf(llm_output_json, output_path="PromptShield_Report.pdf")