import json
import os
from openai import OpenAI
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# 환경 변수에서 OpenAI API 키를 안전하게 불러옵니다.
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


if not OPENAI_API_KEY:
    raise ValueError(
        "❌ 오류: OPENAI_API_KEY가 설정되지 않았습니다.\n"
        "프로젝트 루트 디렉토리에 .env 파일을 만들고 'OPENAI_API_KEY=키값' 형태로 입력해 주세요."
    )

# 안전하게 로드된 API 키를 사용하여 클라이언트 초기화
client = OpenAI(api_key=OPENAI_API_KEY)

# Flask, Spring, Node.js 다중 시큐어코딩 데이터베이스
SECURE_CODE_DATABASE = {
    "SQL Injection": {
        "vulnerable_code": {
            "Spring (Java)": "String query = \"SELECT * FROM users WHERE user_id = '\" + userId + \"'\";\nStatement stmt = connection.createStatement();\nResultSet rs = stmt.executeQuery(query);",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        },
        "secure_code": {
            "Spring (Java)": "String query = \"SELECT * FROM users WHERE user_id = ?\";\nPreparedStatement pstmt = connection.prepareStatement(query);\npstmt.setString(1, userId);\nResultSet rs = pstmt.executeQuery();",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        }
    },
    "Command Injection": {
        "vulnerable_code": {
            "Spring (Java)": "String cmd = \"ping -c 1 \" + userIp;\nProcess process = Runtime.getRuntime().exec(cmd);",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        },
        "secure_code": {
            "Spring (Java)": "if (!Pattern.matches(\"^[0-9.]+$\", userIp)) {\n    throw new IllegalArgumentException(\"Invalid IP\");\n}\nString[] cmd = {\"ping\", \"-c\", \"1\", userIp};\nProcess process = new ProcessBuilder(cmd).start();",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        }
    },
    "Broken Access Control / IDOR": {
        "vulnerable_code": {
            "Spring (Java)": "@GetMapping(\"/user/info\")\npublic User getUserInfo(@RequestParam(\"userId\") String userId) {\n    return userService.findById(userId);\n}",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        },
        "secure_code": {
            "Spring (Java)": "@GetMapping(\"/user/info\")\npublic User getUserInfo(@RequestParam(\"userId\") String userId, HttpSession session) {\n    String loginUser = (String) session.getAttribute(\"loginUser\");\n    if (!loginUser.equals(userId)) {\n        throw new AccessDeniedException(\"권한 없음\");\n    }\n    return userService.findById(userId);\n}",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        }
    },
    "Server-Side Request Forgery (SSRF)": {
        "vulnerable_code": {
            "Spring (Java)": "String targetUrl = request.getParameter(\"url\");\nRestTemplate rest = new RestTemplate();\nString res = rest.getForObject(targetUrl, String.class);",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        },
        "secure_code": {
            "Spring (Java)": "String targetUrl = request.getParameter(\"url\");\nif (!targetUrl.startsWith(\"https://api.trusted.com\")) {\n    throw new IllegalArgumentException(\"허용되지 않은 도메인\");\n}",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        }
    },
    "Cross-Site Scripting (XSS)": {
        "vulnerable_code": {
            "Spring (Java)": "model.addAttribute(\"userInput\", userInput);",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        },
        "secure_code": {
            "Spring (Java)": "String safeInput = HtmlUtils.htmlEscape(userInput);\nmodel.addAttribute(\"userInput\", safeInput);",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        }
    },
    "Path Traversal": {
        "vulnerable_code": {
            "Spring (Java)": "String fileName = request.getParameter(\"filename\");\nFile file = new File(\"/var/uploads/\" + fileName);",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        },
        "secure_code": {
            "Spring (Java)": "Path basePath = Paths.get(\"/var/uploads\").toAbsolutePath().normalize();\nPath targetPath = basePath.resolve(fileName).normalize();\nif (!targetPath.startsWith(basePath)) {\n    throw new SecurityException(\"잘못된 경로 접근\");\n}",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        }
    },
    "Unrestricted File Upload": {
        "vulnerable_code": {
            "Spring (Java)": "MultipartFile file = request.getFile(\"file\");\nfile.transferTo(new File(\"/var/www/upload/\" + file.getOriginalFilename()));",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        },
        "secure_code": {
            "Spring (Java)": "MultipartFile file = request.getFile(\"file\");\nString ext = getFileExtension(file.getOriginalFilename());\nif (!ext.equalsIgnoreCase(\"jpg\")) {\n    throw new IllegalArgumentException(\"허용되지 않는 형식\");\n}\nString safeName = UUID.randomUUID().toString() + \".\" + ext;\nfile.transferTo(new File(\"/var/www/upload/\" + safeName));",
            "Flask (Python)": "// Java/Spring 코드만 제공됨",
            "Node.js": "// Java/Spring 코드만 제공됨"
        }
    }
}

# 🌟 최신 정의된 전문 System Prompt 적용
SYSTEM_PROMPT = """
You are a web application security analyst specializing in HTTP request/response analysis.

Analyze the provided masked HTTP Request and Response and identify evidence of web application vulnerabilities.

Use OWASP Top 10:2025 for high-level risk categorization and OWASP Web Security Testing Guide (WSTG) principles for assessment.

[Analysis Scope]
1. SQL Injection
2. Command Injection
3. Cross-Site Scripting (XSS)
4. Broken Access Control / IDOR
5. Server-Side Request Forgery (SSRF)
6. Path Traversal
7. Unrestricted File Upload
8. Sensitive Information Exposure

[General Rules]
1. Analyze both Request and Response.
2. Do not classify a request as vulnerable only because it contains suspicious input.
3. Use observable Request and Response evidence together whenever possible.
4. Do not assume server-side behavior that cannot be observed.
5. If evidence is insufficient, return N/A instead of guessing.
6. Evidence must come from the supplied Request or Response.
7. Redacted values such as [REDACTED_TOKEN] and [REDACTED_SESSION] are not attack evidence.
8. Do not use expected labels or ground-truth information outside Request and Response.

[Assessment Guidelines]

SQL Injection:
- Inspect user-controlled query, form, JSON, and body parameters.
- Check Response for database errors, meaningful data changes, or behavior consistent with unsafe SQL processing.
- SQL-like input alone is not enough for a vulnerable verdict.

Command Injection:
- Inspect inputs that may become OS commands or command arguments.
- Check Response for command output, OS errors, or observable execution behavior.
- Do not infer command execution without evidence.

XSS:
- Inspect input that may enter HTML or JavaScript contexts.
- Check whether input is reflected and whether it is encoded or neutralized.
- Do not assume browser-side execution when HTTP data cannot demonstrate it.

Broken Access Control / IDOR:
- Inspect object IDs, user IDs, resource paths, and authorization-related parameters.
- Check whether unauthorized resources or functions are returned.
- If role, ownership, or comparison data is unavailable, prefer N/A.

SSRF:
- Inspect user-controlled URLs, hostnames, callbacks, and webhooks.
- Look for evidence that the server accessed an unintended resource.
- A URL parameter alone is not enough for a vulnerable verdict.

Path Traversal:
- Inspect file/path parameters for references outside the intended directory.
- Check Response for evidence of access to files/directories outside the expected scope.

Unrestricted File Upload:
- Inspect multipart data, filenames, extensions, Content-Type, and upload parameters.
- Check whether a restricted file was accepted, stored, or processed.
- If post-upload behavior cannot be determined, use N/A where appropriate.

Sensitive Information Exposure:
- Inspect Response for unnecessary disclosure of credentials, personal data, internal application details, detailed errors, or sensitive server information.
- Do not classify ordinary public information as sensitive without sufficient context.

[Verdict Rules]

VULNERABLE:
Sufficient observable evidence supports the existence of the vulnerability.

SAFE:
The supplied data sufficiently shows that the tested behavior was safely handled, rejected, encoded, restricted, or otherwise protected.

N/A:
The supplied Request/Response is insufficient to determine the vulnerability reliably or the item cannot be meaningfully assessed from the supplied data.

For N/A:
- Explain why the determination cannot be made.
- State what additional information or test is needed.
- severity must be null.

[Severity Rules]

Assign severity only for VULNERABLE findings.

CRITICAL:
Evidence indicates extremely severe impact such as broad system compromise.

HIGH:
Evidence supports significant unauthorized access, sensitive data compromise, privilege abuse, or command execution.

MEDIUM:
A vulnerability is supported, but exploitation needs additional conditions or demonstrated impact is limited.

LOW:
Security impact or exploitability is relatively limited.

INFO:
Primarily security-relevant information or a hardening recommendation rather than a directly demonstrated exploitable vulnerability.

For SAFE or N/A, severity must be null.

[OWASP Mapping]
- SQL Injection -> A05 Injection
- Command Injection -> A05 Injection
- XSS -> A05 Injection
- Broken Access Control / IDOR -> A01 Broken Access Control
- SSRF -> A01 Broken Access Control

For Path Traversal, Unrestricted File Upload, and Sensitive Information Exposure, do not force an unsupported category.
If a reliable project mapping cannot be determined, return null for owasp_category.

[Output Rules]
Return valid JSON only.
All textual explanations, reasons, impact, remediation summaries, and additional checks must be written in fluent Korean.
Do not include Markdown or explanatory text outside JSON.
Do not invent evidence.

Use this structure:
{
  "vulnerability_name": "string",
  "owasp_category": "string or null",
  "verdict": "VULNERABLE | SAFE | N/A",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO | null",
  "reason": "Concise explanation of the verdict in Korean.",
  "evidence": {
    "request": ["Observable Request evidence in Korean"],
    "response": ["Observable Response evidence in Korean"]
  },
  "impact": "Security impact if supported, otherwise null (in Korean).",
  "remediation_summary": "Concise recommended remediation or null (in Korean).",
  "additional_check": "Additional information/testing required for N/A, otherwise null (in Korean)."
}
""".strip()


def parse_incoming_json(json_data: dict) -> str:
    """
    [데이터 입력 영역 1] 
    앞 팀 또는 프론트엔드에서 전달받은 마스킹된 패킷 JSON 데이터를 파싱합니다.
    
    전달받아야 하는 `json_data` 구조 예시:
    {
        "id": "case_001",
        "source": "출처 정보",
        "request": {
            "method": "GET 또는 POST 등",
            "path": "요청 경로",
            "query_params": { ... } 또는 body 데이터
        },
        "response": {
            "status_code": 200,
            "body_excerpt": "응답 바디 내용"
        }
    }
    """
    req = json_data.get("request", {})
    res = json_data.get("response", {})
    
    context = f"""
[Target Information]
- Source/Context: {json_data.get('source')}

[HTTP Request (Masked)]
Method: {req.get('method')}
Path: {req.get('path')}
Query Params: {json.dumps(req.get('query_params'), ensure_ascii=False)}

[HTTP Response (Masked)]
Status Code: {res.get('status_code')}
Body Excerpt: {res.get('body_excerpt')}
    """
    return context.strip()


def run_llm_diagnosis(packet_context: str) -> dict:
    """OpenAI API를 통한 취약점 진단 (전문 프롬프트 및 한국어 출력 강제)"""
    user_prompt = f"""Analyze the following masked HTTP Request and Response.

{packet_context}
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2,
            response_format={"type": "json_object"}
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {"error": str(e)}


def generate_report_html(llm_result: dict, output_path: str = "PromptShield_Report.html"):
    """다중 언어 가이드 및 한국어 근거가 포함된 보고서 생성"""
    vuln_name = llm_result.get("vulnerability_name", "SQL Injection")
    verdict = llm_result.get("verdict", "VULNERABLE")
    
    code_guide = SECURE_CODE_DATABASE.get(vuln_name, {
        "vulnerable_code": {
            "Spring (Java)": "// 해당 항목 코드 없음",
            "Flask (Python)": "// 해당 항목 코드 없음",
            "Node.js": "// 해당 항목 코드 없음"
        },
        "secure_code": {
            "Spring (Java)": "// 해당 항목 코드 없음",
            "Flask (Python)": "// 해당 항목 코드 없음",
            "Node.js": "// 해당 항목 코드 없음"
        }
    })

    if verdict == "VULNERABLE":
        result_badge = '<span class="badge-vulnerable">취약 발견 (VULNERABLE)</span>'
    elif verdict == "SAFE":
        result_badge = '<span class="badge-safe">양호 (SAFE)</span>'
    else:
        result_badge = '<span style="background-color: #f1f5f9; color: #475569; padding: 4px 8px; border-radius: 4px; font-weight: bold;">판단 불가 (N/A)</span>'

    # 다중 언어 코드 블록 생성 렌더링
    multi_lang_html = ""
    for lang in ["Spring (Java)", "Flask (Python)", "Node.js"]:
        vuln_snippet = code_guide["vulnerable_code"].get(lang, "")
        secure_snippet = code_guide["secure_code"].get(lang, "")
        multi_lang_html += f"""
        <div class="lang-section">
            <h4>📌 프레임워크: {lang}</h4>
            <div class="code-box-wrapper">
                <div class="code-title vuln">❌ 취약한 코드 (Vulnerable)</div>
                <pre><code>{vuln_snippet}</code></pre>
            </div>
            <div class="code-box-wrapper">
                <div class="code-title secure">⭕ 안전한 패치 코드 (Secure)</div>
                <pre><code>{secure_snippet}</code></pre>
            </div>
        </div>
        """

    # 근거 배열 처리
    evidence_dict = llm_result.get("evidence", {})
    req_evidence = "<br>".join(evidence_dict.get("request", ["근거 없음"]))
    res_evidence = "<br>".join(evidence_dict.get("response", ["근거 없음"]))

    styled_html = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <style>
            body {{
                font-family: 'Malgun Gothic', sans-serif;
                color: #333333;
                line-height: 1.5;
                max-width: 850px;
                margin: 30px auto;
                padding: 20px;
                background-color: #ffffff;
            }}
            .report-title {{
                text-align: center;
                font-size: 22pt;
                font-weight: bold;
                color: #111111;
                margin-bottom: 30px;
                padding-bottom: 10px;
                border-bottom: 3px solid #2c3e50;
            }}
            .section-header {{
                font-size: 13pt;
                font-weight: bold;
                color: #ffffff;
                background-color: #2c3e50;
                padding: 8px 12px;
                margin-top: 25px;
                margin-bottom: 10px;
                border-radius: 4px;
            }}
            table.info-table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 15px;
                font-size: 10pt;
            }}
            table.info-table th, table.info-table td {{
                border: 1px solid #cbd5e1;
                padding: 8px 12px;
            }}
            table.info-table th {{
                background-color: #f1f5f9;
                width: 25%;
                text-align: left;
                color: #1e293b;
            }}
            .badge-vulnerable {{
                background-color: #fee2e2;
                color: #dc2626;
                padding: 4px 8px;
                border-radius: 4px;
                font-weight: bold;
            }}
            .badge-safe {{
                background-color: #dcfce7;
                color: #16a34a;
                padding: 4px 8px;
                border-radius: 4px;
                font-weight: bold;
            }}
            .lang-section {{
                background-color: #f8fafc;
                border: 1px solid #e2e8f0;
                padding: 15px;
                border-radius: 6px;
                margin-bottom: 20px;
            }}
            .lang-section h4 {{
                margin-top: 0;
                color: #1e293b;
                font-size: 11pt;
                border-bottom: 2px solid #cbd5e1;
                padding-bottom: 5px;
            }}
            .code-title {{
                font-size: 9pt;
                font-weight: bold;
                margin-top: 8px;
                margin-bottom: 3px;
            }}
            .code-title.vuln {{ color: #dc2626; }}
            .code-title.secure {{ color: #16a34a; }}
            pre {{
                background-color: #1e293b;
                color: #f8fafc;
                padding: 10px;
                border-radius: 4px;
                font-size: 9pt;
                overflow-x: auto;
                margin: 0 0 10px 0;
                border: 1px solid #334155;
            }}
            code {{
                font-family: 'Consolas', monospace;
            }}
            .desc-box {{
                background-color: #f8fafc;
                border-left: 4px solid #3b82f6;
                padding: 10px 15px;
                margin-bottom: 15px;
                font-size: 9.5pt;
                color: #475569;
            }}
        </style>
    </head>
    <body>
        <div class="report-title">웹 취약점 진단 보고서</div>

        <div class="section-header">1. 진단 사이트 개요</div>
        <table class="info-table">
            <tr>
                <th>진단 호스트</th>
                <td>localhost / Target Server (Masked)</td>
            </tr>
            <tr>
                <th>진단 결과 (Verdict)</th>
                <td>{result_badge}</td>
            </tr>
        </table>
        <div class="desc-box">
            본 보고서는 마스킹 처리된 패킷 데이터를 기반으로 LLM이 진단한 결과 및 N/A 판정 근거를 포함하며, 개발 언어 미특정 환경을 고려하여 주요 프레임워크별 시큐어코딩 가이드를 제공합니다.
        </div>

        <div class="section-header">2. 진단 결과 요약 및 상세 분석 (근거 포함)</div>
        <table class="info-table">
            <tr>
                <th>취약점 명칭</th>
                <td><b>{vuln_name}</b></td>
            </tr>
            <tr>
                <th>OWASP 카테고리</th>
                <td>{llm_result.get('owasp_category', 'N/A')}</td>
            </tr>
            <tr>
                <th>위험도 (Severity)</th>
                <td><span style="color: #dc2626; font-weight: bold;">{llm_result.get('severity', 'N/A')}</span></td>
            </tr>
            <tr>
                <th>판단 근거 요약</th>
                <td>{llm_result.get('reason', '근거 없음')}</td>
            </tr>
            <tr>
                <th>요청 분석 근거 (Request)</th>
                <td>{req_evidence}</td>
            </tr>
            <tr>
                <th>응답 분석 근거 (Response)</th>
                <td>{res_evidence}</td>
            </tr>
            <tr>
                <th>보안 영향 (Impact)</th>
                <td>{llm_result.get('impact', '해당 없음')}</td>
            </tr>
            <tr>
                <th>추가 확인사항 (N/A 전용)</th>
                <td>{llm_result.get('additional_check', '해당 없음')}</td>
            </tr>
        </table>

        <div class="section-header">3. 프레임워크별 시큐어코딩 및 패치 가이드</div>
        <div class="desc-box">
            <b>대응 방안 요약:</b> {llm_result.get('remediation_summary', '해당 없음')}
        </div>

        {multi_lang_html}
    </body>
    </html>
    """
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(styled_html)
    print(f"진단 보고서 생성 완료: {output_path}")


# ==========================================
# 🌟 [외부 연동 핵심 함수]
# ==========================================
def generate_vulnerability_report(masked_json_data: dict, output_path: str = "PromptShield_Report.html") -> str:
    """
    [데이터 입력 지점]
    외부(앞 팀, 프론트엔드 등)에서 마스킹된 JSON 데이터를 전달받아
    파싱, LLM 진단, HTML 보고서 생성까지 한 번에 처리하고 생성된 보고서 파일 경로를 반환합니다.

    :param masked_json_data: dict 형태의 마스킹된 패킷 데이터
    :param output_path: 생성될 HTML 보고서 저장 경로
    :return: 생성된 HTML 파일 경로 (str)
    """
    try:
        # 1. 패킷 데이터 파싱
        packet_context = parse_incoming_json(masked_json_data)
        
        # 2. LLM 진단 수행
        llm_output_json = run_llm_diagnosis(packet_context)
        
        # 만약 LLM 호출 중 에러가 났다면 예외 처리
        if "error" in llm_output_json:
            raise Exception(f"LLM 진단 실패: {llm_output_json['error']}")
            
        # 3. HTML 보고서 빌드
        generate_report_html(llm_output_json, output_path=output_path)
        
        return output_path,llm_output_json
        
    except Exception as e:
        print(f"[Error] 통합 보고서 생성 중 오류 발생: {str(e)}")
        raise e