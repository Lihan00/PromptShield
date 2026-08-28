import html
import json
import os
import uuid
import time
from pathlib import Path
from typing import Any
from io import BytesIO

from dotenv import load_dotenv
from openai import OpenAI, OpenAIError
from playwright.sync_api import sync_playwright



# .env 파일 로드
load_dotenv()

api_key = os.environ.get("OPENAI_API_KEY")

if not api_key:
    raise ValueError(
        "❌ 오류: OPENAI_API_KEY가 설정되지 않았습니다.\n"
        "프로젝트 루트 디렉토리에 .env 파일을 만들고 'OPENAI_API_KEY=키값' 형태로 입력해 주세요."
    )

client = OpenAI(api_key=api_key)

SECURE_CODE_DATABASE = {
    "SQL Injection": {
        "vulnerable_code": {
            "Spring (Java)": 'String query = "SELECT * FROM users WHERE user_id = \'" + userId + "\'";\nStatement stmt = connection.createStatement();',
            "Flask (Python)": 'query = f"SELECT * FROM users WHERE user_id = \'{user_id}\'"\ncursor.execute(query)',
            "Node.js": 'const query = `SELECT * FROM users WHERE user_id = \'${userId}\'`;\ndb.query(query);'
        },
        "secure_code": {
            "Spring (Java)": 'String query = "SELECT * FROM users WHERE user_id = ?";\nPreparedStatement pstmt = connection.prepareStatement(query);\npstmt.setString(1, userId);',
            "Flask (Python)": 'query = "SELECT * FROM users WHERE user_id = %s"\ncursor.execute(query, (user_id,))',
            "Node.js": "const query = 'SELECT * FROM users WHERE user_id = ?';\ndb.query(query, [userId], callback);"
        }
    },
    "Command Injection": {
        "vulnerable_code": {
            "Spring (Java)": 'String cmd = "ping -c 1 " + userIp;\nProcess p = Runtime.getRuntime().exec(cmd);',
            "Flask (Python)": 'os.system(f"ping -c 1 {user_ip}")',
            "Node.js": 'exec(`ping -c 1 ${userIp}`, (err, stdout) => { ... });'
        },
        "secure_code": {
            "Spring (Java)": 'String[] cmd = {"ping", "-c", "1", userIp};\nProcess p = new ProcessBuilder(cmd).start();',
            "Flask (Python)": 'subprocess.run(["ping", "-c", "1", user_ip], check=True)',
            "Node.js": "execFile('ping', ['-c', '1', userIp], (err, stdout) => { ... });"
        }
    },
    "Cross-Site Scripting (XSS)": {
        "vulnerable_code": {
            "Spring (Java)": '// 사용자 입력을 그대로 모델에 담아 뷰에 전달\nmodel.addAttribute("input", userInput);',
            "Flask (Python)": '# Jinja2 템플릿에서 |safe 필터 사용 또는 안전하지 않은 렌더링\nreturn render_template_string(f"<div>{user_input}</div>")',
            "Node.js": 'res.send(`<div>${userInput}</div>`);'
        },
        "secure_code": {
            "Spring (Java)": '// Spring Security 또는 OWASP Encoder를 통한 HTML Entity Encoding 적용',
            "Flask (Python)": '# Jinja2는 기본적으로 자동 에스케이핑(Auto-escaping) 지원\nreturn render_template("index.html", user_input=user_input)',
            "Node.js": '// DOMPurify 또는 escape-html 라이브러리 사용\nres.send(`<div>${escapeHtml(userInput)}</div>`);'
        }
    },
    "Broken Access Control / IDOR": {
        "vulnerable_code": {
            "Spring (Java)": '// 권한 검증 누락된 컨트롤러 로직\n@GetMapping("/user/{id}")\npublic User getUser(@PathVariable Long id) { return userService.findById(id); }',
            "Flask (Python)": '# 세션 검증 없는 객체 직접 참조\n@app.route("/user/<int:user_id>")\ndef get_user(user_id): return User.query.get(user_id)',
            "Node.js": 'app.get("/user/:id", (req, res) => { db.find(req.params.id); });'
        },
        "secure_code": {
            "Spring (Java)": '// Spring Security @PreAuthorize 및 소유권 검증 추가\n@PreAuthorize("#id == principal.id")',
            "Flask (Python)": '# 현재 로그인한 사용자와 요청된 리소스 소유자 일치 여부 확인',
            "Node.js": '// 세션 사용자 ID와 요청된 리소스 소유권 대조 로직 구현'
        }
    },
    "Server-Side Request Forgery (SSRF)": {
        "vulnerable_code": {
            "Spring (Java)": 'RestTemplate restTemplate = new RestTemplate();\nrestTemplate.getForObject(userInputUrl, String.class);',
            "Flask (Python)": 'requests.get(user_input_url)',
            "Node.js": 'axios.get(userInputUrl);'
        },
        "secure_code": {
            "Spring (Java)": '// 허용된 도메인 리스트(Whitelist) 검증 및 내부망 IP 차단 로직 구현',
            "Flask (Python)": '# IP 어드레스 검증 및 사설 IP(RFC 1918) 대역 접근 차단',
            "Node.js": '// URL 파싱 후 외부 공인 도메인 여부 화이트리스트 기반 검증'
        }
    },
    "Path Traversal": {
        "vulnerable_code": {
            "Spring (Java)": 'File file = new File("/var/www/uploads/" + fileName);',
            "Flask (Python)": 'return send_from_directory("/var/www/uploads", file_name)',
            "Node.js": 'fs.readFile(__dirname + "/uploads/" + fileName, ...);'
        },
        "secure_code": {
            "Spring (Java)": '// CanonicalPath 검증 및 경로 이탈 방지 로직 구현',
            "Flask (Python)": 'safe_path = secure_filename(file_name)',
            "Node.js": 'path.basename()을 통한 파일명 추출 및 path.resolve() 경로 검증'
        }
    },
    "Unrestricted File Upload": {
        "vulnerable_code": {
            "Spring (Java)": 'file.transferTo(new File("/upload/" + file.getOriginalFilename()));',
            "Flask (Python)": 'file.save(os.path.join("/upload", file.filename))',
            "Node.js": 'fs.writeFileSync("/upload/" + req.file.originalname, req.file.buffer);'
        },
        "secure_code": {
            "Spring (Java)": '// 허용된 확장자(Whitelist) 검증 및 파일 이름 난수화(UUID)',
            "Flask (Python)": 'secure_filename() 사용 및 허용 확장자 검증 후 저장',
            "Node.js": '// 확장자 검증 및 multer 안전 설정 적용'
        }
    },
    "Sensitive Information Exposure": {
        "vulnerable_code": {
            "Spring (Java)": 'e.printStackTrace(); // 스택 트레이스를 응답으로 그대로 반환',
            "Flask (Python)": 'return str(e) # 상세 시스템 에러 메시지 노출',
            "Node.js": 'res.status(500).send(err);'
        },
        "secure_code": {
            "Spring (Java)": '// 커스텀 ErrorResponse 사용 및 내부 에러 은닉',
            "Flask (Python)": '# 사용자 친화적인 일반 에러 페이지 반환',
            "Node.js": '// 상세 에러 로그는 서버에만 남기고 클라이언트에는 일반 메시지 전송'
        }
    }
}

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
    req = json_data.get("request", {})
    res = json_data.get("response", {})
    
    req_method = req.get('method', 'UNKNOWN')
    req_path = req.get('path', '/')
    req_query = req.get('query_params', {})
    req_headers = req.get('headers', {})
    req_body = req.get('body', {})
    
    res_status = res.get('status_code', 200)
    res_headers = res.get('headers', {})
    res_body = res.get('body') or res.get('body_excerpt') or "응답 데이터 내용 없음"

    context = f"""
[Target Information]
- Source/Context: {json_data.get('source', 'Unknown')}

[HTTP Request (Masked)]
Method: {req_method}
Path: {req_path}
Query Params: {json.dumps(req_query, ensure_ascii=False)}
Headers: {json.dumps(req_headers, ensure_ascii=False)}
Body: {json.dumps(req_body, ensure_ascii=False)}

[HTTP Response (Masked)]
Status Code: {res_status}
Headers: {json.dumps(res_headers, ensure_ascii=False)}
Body Excerpt: {res_body}
    """
    return context.strip()


def run_llm_diagnosis(packet_context: str) -> dict:
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


def print_terminal_summary(llm_result: dict):
    verdict = llm_result.get("verdict", "UNKNOWN")
    vuln_name = llm_result.get("vulnerability_name", "N/A")
    severity = llm_result.get("severity", "N/A")
    owasp = llm_result.get("owasp_category", "N/A")
    reason = llm_result.get("reason", "근거 없음")
    
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    if verdict == "VULNERABLE":
        v_color = RED
    elif verdict == "SAFE":
        v_color = GREEN
    else:
        v_color = YELLOW

    print("\n" + "="*60)
    print(f"{BOLD}🔍 [LLM 웹 취약점 진단 결과 요약]{RESET}")
    print("="*60)
    print(f"• 취약점 명칭 : {BOLD}{vuln_name}{RESET}")
    print(f"• 진단 결과    : {v_color}{BOLD}{verdict}{RESET}")
    print(f"• 위험도      : {RED if severity in ['CRITICAL', 'HIGH'] else CYAN}{severity}{RESET}")
    print(f"• OWASP 분류  : {owasp}")
    print(f"• 판단 근거   : {reason}")
    print("="*60 + "\n")


def generate_report_html_content(llm_result: dict) -> str:
    vuln_name = llm_result.get("vulnerability_name", "SQL Injection")
    verdict = llm_result.get("verdict", "VULNERABLE")
    severity = llm_result.get("severity", "N/A")


    
    code_guide = None
    for key in SECURE_CODE_DATABASE:
        if key.lower() in vuln_name.lower() or vuln_name.lower() in key.lower():
            code_guide = SECURE_CODE_DATABASE[key]
            break
            
    if not code_guide:
        code_guide = {
            "vulnerable_code": {
                "Spring (Java)": "// 해당 취약점에 대한 샘플 코드 준비 중",
                "Flask (Python)": "// 해당 취약점에 대한 샘플 코드 준비 중",
                "Node.js": "// 해당 취약점에 대한 샘플 코드 준비 중"
            },
            "secure_code": {
                "Spring (Java)": "// 입력값 검증 및 안전한 API 사용 필수",
                "Flask (Python)": "// 입력값 검증 및 안전한 API 사용 필수",
                "Node.js": "// 입력값 검증 및 안전한 API 사용 필수"
            }
        }

    if verdict == "VULNERABLE":
        result_badge = '<span class="badge badge-vulnerable">취약 발견 (VULNERABLE)</span>'
    elif verdict == "SAFE":
        result_badge = '<span class="badge badge-safe">양호 (SAFE)</span>'
    else:
        result_badge = '<span class="badge badge-na">판단 불가 (N/A)</span>'

    severity_badge = f'<span class="badge badge-severity">{severity}</span>' if severity and severity != "N/A" else '<span style="color:#64748b;">-</span>'

    multi_lang_html = ""
    for lang in ["Spring (Java)", "Flask (Python)", "Node.js"]:
        vuln_snippet = code_guide["vulnerable_code"].get(lang, "")
        secure_snippet = code_guide["secure_code"].get(lang, "")
        multi_lang_html += f"""
        <div class="lang-card">
            <div class="lang-title">{lang}</div>
            <div class="code-block-container">
                <div class="code-label vuln-label"> 취약한 코드 (Vulnerable)</div>
                <pre><code>{html.escape(vuln_snippet)}</code></pre>
            </div>
            <div class="code-block-container">
                <div class="code-label secure-label"> 안전한 패치 코드 (Secure)</div>
                <pre><code>{html.escape(secure_snippet)}</code></pre>
            </div>
        </div>
        """

    evidence_dict = llm_result.get("evidence", {})
    req_evidence = "<br>• ".join([""] + evidence_dict.get("request", ["근거 없음"]))
    res_evidence = "<br>• ".join([""] + evidence_dict.get("response", ["근거 없음"]))

    styled_html = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <style>
            * {{
                font-family: 'Malgun Gothic', 'Apple SD Gothic Neo', sans-serif !important;
                box-sizing: border-box;
            }}
            body {{
                color: #1e293b;
                line-height: 1.6;
                max-width: 900px;
                margin: 0 auto;
                padding: 40px 30px;
                background-color: #f8fafc;
            }}
            .report-container {{
                background: #ffffff;
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
            }}
            .report-header {{
                text-align: center;
                margin-bottom: 35px;
                padding-bottom: 20px;
                border-bottom: 2px solid #e2e8f0;
            }}
            .report-title {{
                font-size: 24pt;
                font-weight: 800;
                color: #0f172a;
                margin: 0 0 10px 0;
                letter-spacing: -0.5px;
            }}
            .report-subtitle {{
                font-size: 10.5pt;
                color: #64748b;
                margin: 0;
            }}
            .section {{
                margin-bottom: 30px;
            }}
            .section-title {{
                font-size: 13pt;
                font-weight: 700;
                color: #1e293b;
                margin-bottom: 12px;
                padding-bottom: 6px;
                border-bottom: 2px solid #3b82f6;
                display: flex;
                align-items: center;
            }}
            .info-table {{
                width: 100%;
                border-collapse: collapse;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                border: 1px solid #e2e8f0;
                margin-bottom: 15px;
            }}
            .info-table th, .info-table td {{
                padding: 12px 16px;
                font-size: 10pt;
                border-bottom: 1px solid #f1f5f9;
                vertical-align: middle;
            }}
            .info-table th {{
                background-color: #f8fafc;
                width: 22%;
                font-weight: 600;
                color: #475569;
                text-align: left;
            }}
            .info-table tr:last-child th, .info-table tr:last-child td {{
                border-bottom: none;
            }}
            .badge {{
                display: inline-block;
                padding: 5px 10px;
                border-radius: 6px;
                font-weight: 700;
                font-size: 9.5pt;
            }}
            .badge-vulnerable {{
                background-color: #fef2f2;
                color: #dc2626;
                border: 1px solid #fecaca;
            }}
            .badge-safe {{
                background-color: #f0fdf4;
                color: #16a34a;
                border: 1px solid #bbf7d0;
            }}
            .badge-na {{
                background-color: #f1f5f9;
                color: #475569;
                border: 1px solid #e2e8f0;
            }}
            .badge-severity {{
                background-color: #fff7ed;
                color: #c2410c;
                border: 1px solid #ffedd5;
            }}
            .desc-box {{
                background-color: #f8fafc;
                border: 1px solid #e2e8f0;
                border-left: 4px solid #3b82f6;
                padding: 12px 16px;
                border-radius: 6px;
                font-size: 9.5pt;
                color: #334155;
                margin-bottom: 15px;
            }}
            .lang-card {{
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.02);
            }}
            .lang-title {{
                font-size: 11.5pt;
                font-weight: 700;
                color: #0f172a;
                margin-bottom: 14px;
                padding-bottom: 8px;
                border-bottom: 1px solid #f1f5f9;
            }}
            .code-block-container {{
                margin-bottom: 12px;
            }}
            .code-block-container:last-child {{
                margin-bottom: 0;
            }}
            .code-label {{
                font-size: 9pt;
                font-weight: 700;
                margin-bottom: 4px;
            }}
            .vuln-label {{ color: #dc2626; }}
            .secure-label {{ color: #16a34a; }}
            pre {{
                background-color: #0f172a;
                color: #f8fafc;
                padding: 12px 14px;
                border-radius: 6px;
                font-size: 9pt;
                overflow-x: auto;
                margin: 0;
                border: 1px solid #1e293b;
            }}
            code {{
                font-family: 'Consolas', 'Courier New', Courier, monospace;
            }}
        </style>
    </head>
    <body>
        <div class="report-container">
            <div class="report-header">
                <h1 class="report-title">웹 취약점 진단 보고서</h1>
                <p class="report-subtitle">Web Application Vulnerability Assessment Report</p>
            </div>

            <div class="section">
                <div class="section-title">1. 진단 사이트 개요</div>
                <table class="info-table">
                    <tr>
                        <th>진단 호스트</th>
                        <td>localhost / Target Server (Masked)</td>
                    </tr>
                    <tr>
                        <th>종합 진단 결과</th>
                        <td>{result_badge}</td>
                    </tr>
                </table>
                <div class="desc-box">
                    본 보고서는 마스킹 처리된 패킷 데이터를 기반으로 LLM이 진단한 결과 및 N/A 판정 근거를 포함하며, 개발 언어 미특정 환경을 고려하여 주요 프레임워크별 시큐어코딩 가이드를 제공합니다.
                </div>
            </div>

            <div class="section">
                <div class="section-title">2. 진단 결과 요약 및 상세 분석</div>
                <table class="info-table">
                    <tr>
                        <th>취약점 명칭</th>
                        <td><b>{vuln_name}</b></td>
                    </tr>
                    <tr>
                        <th>OWASP 분류</th>
                        <td>{llm_result.get('owasp_category', 'N/A')}</td>
                    </tr>
                    <tr>
                        <th>위험도 (Severity)</th>
                        <td>{severity_badge}</td>
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
            </div>

            <div class="section">
                <div class="section-title">3. 프레임워크별 시큐어코딩 및 패치 가이드</div>
                <div class="desc-box">
                    <b>대응 방안 요약:</b> {llm_result.get('remediation_summary', '해당 없음')}
                </div>
                {multi_lang_html}
            </div>
        </div>
    </body>
    </html>
    """
    return styled_html


def cleanup_old_reports(output_dir: str, max_age_seconds: int = 1800):
    if not os.path.exists(output_dir):
        return
    current_time = time.time()
    for filename in os.listdir(output_dir):
        if filename.endswith(".html"):
            file_path = os.path.join(output_dir, filename)
            if current_time - os.path.getmtime(file_path) > max_age_seconds:
                try:
                    os.remove(file_path)
                except Exception:
                    pass


def generate_vulnerability_report_pdf_bytes(masked_json_data: dict) -> bytes:
    packet_context = parse_incoming_json(masked_json_data)
    llm_output_json = run_llm_diagnosis(packet_context)
    
    if "error" in llm_output_json:
        raise Exception(f"LLM 진단 실패: {llm_output_json['error']}")
        
    print_terminal_summary(llm_output_json)
        
    html_string = generate_report_html_content(llm_output_json)
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content(html_string)
        pdf_bytes = page.pdf(format="A4", print_background=True, margin={"top": "20px", "bottom": "20px", "left": "20px", "right": "20px"})
        browser.close()
        
    return pdf_bytes,llm_output_json


def generate_vulnerability_report(masked_json_data: dict, output_dir: str = "./reports") -> str:
    try:
        os.makedirs(output_dir, exist_ok=True)
        cleanup_old_reports(output_dir, max_age_seconds=1800)
        
        unique_filename = f"report_{uuid.uuid4().hex[:8]}.pdf"
        output_path = os.path.join(output_dir, unique_filename)
        
        pdf_bytes,diagnosis = generate_vulnerability_report_pdf_bytes(masked_json_data)
        
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)
            
        return output_path,diagnosis
    except Exception as e:
        print(f"[Error] 통합 보고서 파일 생성 실패: {str(e)}")
        raise e
    
# ==========================================
# 🧪 테스트 실행 코드
# ==========================================
if __name__ == "__main__":
    sample_packet = {
    "request": {
    "method": "GET",
    "path": "/gm/search_result.php",
    "query_params": {
      "search": "name",
      "searchstring": "') order by 1#"
    },
    "headers": {
      "Host": "[REDACTED_IP]",
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate, br",
      "Connection": "keep-alive",
      "Referer": "http://[REDACTED_IP]/gm/search_result.php?search=name&searchstring=%27%29+order+by+1%23",
      "Cookie": "security_level=1; BEEFHOOK=[REDACTED_SESSION]; PHPSESSID=[REDACTED_SESSION]",
      "Upgrade-Insecure-Requests": "1",
      "Priority": "u=0, i"
    },
    "body": None
  },
  "response": {
    "status_code": 200,
    "headers": {
      "Date": "Fri, 28 Aug 2026 00:59:30 GMT",
      "Server": "Apache/2.2.8 (Ubuntu) DAV/2 mod_fastcgi/2.4.6 PHP/5.2.4-2ubuntu5 with Suhosin-Patch mod_ssl/2.2.8 OpenSSL/0.9.8g",
      "X-Powered-By": "PHP/5.2.4-2ubuntu5",
      "Expires": "Thu, 19 Nov 1981 08:52:00 GMT",
      "Cache-Control": "no-store, no-cache, must-revalidate, post-check=0, pre-check=0",
      "Pragma": "no-cache",
      "Keep-Alive": "timeout=15, max=100",
      "Connection": "Keep-Alive",
      "Content-Type": "text/html",
      "Content-Length": "73383"
    },
    "body": "<html>\n<head>\n<style>\n.box {font-size: 9pt; border:1px solid #464646;background-color:white;  } \n.box1 {font-size: 9pt; border:1px solid #d4d0c8;background-color:#F7F7F7;  } \n.graybox {font-size: 9pt; border:1px solid #000000;background-color:#d4d0c8;  } \n.nonbox {font-size: 9pt; border:0px solid #000000;background-color:white;  } \n.radio {font-size: 9pt; border:0px solid #000000;background-color:white;  } \n.text {font-size: 9pt; border:1px solid #000000;}\n.text_l {font-size: 9pt; border:1px solid #ACACAC;}\n.mem {font-size:8pt;font-family: \"돋움\";letter-spacing:-1;color:#464646;}\n.stext{font-size:8pt;font-family: \"돋움\";}\n.sm {font-size:8pt;font-family: \"돋움\";letter-spacing:-1;color:#ff4800;}\n.text1 { FONT-SIZE: 9pt; COLOR: #7C682D; BACKGROUND-COLOR: #F6F4EE; Border:1px SOLID #E1DCCD;}\n.text2 { FONT-SIZE: 9pt; COLOR: #7C682D; BACKGROUND-COLOR: #F6F4EE; Border:1px SOLID #E1DCCD;}\n.select1 {font-size: 8pt; border:0px solid #ffffff;background-color:#638bb7; color:#ffffff;}\n.select {font-size: 9pt; border:0px solid #000000;}\n.outset {font-size:9pt;border:1px outset #ffffff;}\n.box_s{font-family: \"돋움\"; BORDER-RIGHT: #ffffff 1px solid; BORDER-TOP: #999999 1px solid; PADDING-LEFT: 3px; FONT-SIZE: 11px; BORDER-LEFT: #999999 1px solid; COLOR: #666666; BORDER-BOTTOM: #ffffff 1px solid; BACKGROUND-COLOR:#f1f1f1}\n\n.blue {font-size: 9pt; color: #215987; line-height: 19px} \n.blue A:link{color:#214A87;text-decoration:none} \n.blue A:visited {color:#214A87;text-decoration:none} \n.blue A:active {color:#214A87;text-decoration:none} \n.blue A:hover{color:#214A87;text-decoration:none} \n\nBODY {\tFONT-SIZE: 9pt;  FONT-FAMILY: \"굴림\"}\nTD {\tFONT-SIZE: 9pt;  FONT-FAMILY: \"굴림\"}\nA:link {    text-decoration:none;     color:#636363;} \nA:visited {    text-decoration:none;  color:#636363;   }\nA:hover {    text-decoration:none;     }\nA:active {    text-decoration:underline;    }\n\nimg {border:none;}\n\n.table {border-style: solid; \nborder-width: 1px; \nborder-color: #D9D7D7;\nborder-collapse:collapse;\n}\n\n.table2 {border-style: solid; \nborder-top-width: 1px; \nborder-right-width: 1px; \nborder-bottom-width: 1px; \nborder-left-width: 1px; \n\nborder-color: #000000;}\n\n.table_coll\n{\nborder-color : #D4D0C8;\nborder-collapse : collapse;\nborder-style: solid; \nborder-width: 1px 1px 1px 1px;\n}\n.table_coll_nonepx\n{\nborder-color : #000000;\nborder-collapse : collapse;\nborder-style: solid; \nborder-top-width: 0px; \nborder-right-width: 0px; \nborder-bottom-width: 0px; \nborder-left-width: 0px; \n}\n\n.help {font-size:9pt;color:#73A47A; font-family:굴림}\n.select_1 {font-size: 9pt; border:0; background-color:#eeeeee;}\n\n.button\n{\nbackground-color:#3109C4;\ncolor:white;\nfont-weight:bold;\ntext-align:center;\n}\n.button_pink\n{\nbackground-color:#FF00FF;\ncolor:white;\nfont-weight:bold;\ntext-align:center;\n}\nform { display : inline; }\n</style>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=euc-kr\">\n<title>굿모닝샵 프리 쇼핑몰 솔루션</title>\n<META name=\"description\" content=\"굿모닝샵,독립형,솔루션,쇼핑몰\">\n<META name=\"keywords\" content=\"굿모닝샵,독립형,솔루션,쇼핑몰\">\n<script language=javascript src=\"./script/admin.js\"></script>\n</head><SCRIPT LANGUAGE=\"JavaScript\">\n<!--\n//공지사항 보기\nfunction noticeView(Idx,App,Width,Height,bPopup)\n{\n\t// 공지사항 기본틀 사용안할때\n\tif(App==\"n\")\n\t{\n\t\tvar popup_height =Height+40;\n\t\tvar popup_width\t =Width+20;\n\t\twindow.open(\"notice_view_html.php?bcook=no&idx=\"+Idx,\"\",\"scrollbars=yes,width=\"+popup_width+\",height=\"+popup_height+\",top=100,left=100\");\n\t}\n\telse\n\t{\n\t\twindow.open(\"notice_view_text.php?bcook=no&idx=\"+Idx,\"\",\"scrollbars=yes,width=520,height=470,top=100,left=100\");\n\t}\n}\n\n//투표하기 \n//Status\tlast:마지막 투표  now:현재진행중\n//pPlu\t\t1:복수응답불가  2~10:복수응답가능개수\n//reCan\t\t1:회원,비회원\t\t2:회원제\nfunction pollWrite(Status,bPlu,reCan)\n{\n\tvar form=document.pollForm;\n\tvar voteArr = new Array();\t//투표배열\n\tvar loginCheck =\"guest\";\t//로그인 체크\n\tif(Status==\"last\") alert(\"기간이 만료된 설문조사 입니다.\");\n\telse\n\t{\n\t\tif(reCan==2 && loginCheck!=\"member\")\n\t\t{\n\t\t\talert(\"회원제 설문조사 입니다. 회원 로그인을 해주십시오.\");\n\t\t}\n\t\telse\n\t\t{\n\t\t\tvar bVote = false;\n\t\t\tvar voteCnt =0;\t//투표수\n\t\t\tfor(i=0;i<form.vote.length;i++)\n\t\t\t{\n\t\t\t\tif(form.vote[i].checked)\n\t\t\t\t{\n\t\t\t\t\tbVote=true;\n\t\t\t\t\tvoteArr[i]=1;\t//선택\n\t\t\t\t\tvoteCnt++;\t//선택수 증가\n\t\t\t\t}\n\t\t\t\telse\n\t\t\t\t{\n\t\t\t\t\tvoteArr[i]=0;\t//비선택\n\t\t\t\t}\n\t\t\t}\n\t\t\tif(bVote)\n\t\t\t{\n\t\t\t\tif(voteCnt >bPlu)\n\t\t\t\t{\n\t\t\t\t\t//복수응답 초과\n\t\t\t\t\talert(bPlu+\"개의 복수응답이 가능한 설문조사 입니다.\");\n\t\t\t\t}\n\t\t\t\telse\n\t\t\t\t{\n\t\t\t\t\tform.voteArrstr.value = voteArr.join(\"|\");\n\t\t\t\t\twinP = window.open(\"\",\"Window\",\"width=320,height=372,top=200,left=400,status,scrollbars\");\n\t\t\t\t\tform.target=\"Window\";\n\t\t\t\t\tform.submit();\n\t\t\t\t\twinP.focus();\n\t\t\t\t}\n\t\t\t}\n\t\t\telse\n\t\t\t{\n\t\t\t\talert(\"투표를 하지 않으셨습니다.\");\n\t\t\t}\n\t\t}\n\t}\n}\n\n//투표 에러\nfunction pollErr()\n{\n\talert(\"이미 투표 하셨습니다.\");\n}\n\n//설문조사 결과 보기\nfunction viewPoll(Data)\n{\n\twindow.open(\"poll_new.php?data=\"+Data,\"\",\"width=320,height=372,top=200,left=400,status,scrollbars\");\n}\n\n//로그인 체크\nfunction mypageLoginChek()\n{\n\t\talert(\"회원 메뉴입니다.\\n\\n로그인 해 주십시오.\");\n\tdocument.mypage.submit();}\n\nfunction login()\n{\n\tdocument.a.submit();\n}\n\nvar speed = \"15\";\nvar k=1\nvar pre=0\nfunction verscroll()\n{\n\tif (xx.layer111.style.pixelLeft >= 1000) xx.layer111.style.pixelLeft = -500;\n\tif (xx.layer111.style.pixelLeft <= -1000) xx.layer111.style.pixelLeft = 500;\n\txx.layer111.style.pixelLeft = xx.layer111.style.pixelLeft + k;\n\tsetTimeout(\"verscroll(k)\",speed);\n}\nfunction ss()\n{\n\tverscroll();\n}\nfunction chg(x)\n{\n\tk = x;\n}\nfunction stop()\n{\n\tpre = k;\n\tchg(0)\n}\nfunction start()\n{\n\tchg(pre)\n}\n\nfunction left_login_check()\n{\n\tvar form=document.loginmainForm;\n\tif(form.userid.value==\"\")\n\t{\n\t\talert(\"아이디를 입력해 주십시오.\");\n\t\tform.userid.focus();\n\t}\n\telse if(form.pwd.value==\"\")\n\t{\n\t\talert(\"비밀번호를 입력해 주십시오.\");\n\t\tform.pwd.focus();\n\t}\n\telse\n\t{\n\t\tform.submit();\n\t}\n}\n\nfunction left_loginChek(aEvent)\n{\n\tvar myEvent = aEvent ? aEvent : window.event;\n\tif(myEvent.keyCode==13) left_login_check();\n}\n\nfunction searchId(Part)\n{\n\twindow.open(\"id_loss.php?part=\"+Part,\"\",\"scrollbars=no,width=330,height=240,top=200,left=200\");\n}\n\nvar arr_TodayImg = new Array();\t// 이미지주소 배열 \nvar arr_TodayGoodsIdx = new Array();\t// 상품DB idx 배열 \nvar current_today = 0;\t// 이미지업다운을 위한 첫이미지 배열원소값\n\tarr_TodayImg[0] = \"120060721161024216.gif\";\narr_TodayGoodsIdx[0] = \"224\";\nfunction imgUp()\t// 오늘본상품 5개 초과일때 이미지 한칸 올리기\n{\n\tif (arr_TodayImg.length<6)\n\t{\n\t\t// alert(\"오늘본상품이 5개가 넘으면 작동함.\");\n\t}\n\telse if (current_today>0)\n\t{\n\t\tcurrent_today--;\n\t\tvar next=0;\n\t\tfor (var i=0; i<5; i++)\n\t\t{\n\t\t\tnext = current_today + i;\n\t\t\tvar obj = eval(\"document.todayimg\"+i);\n\t\t\tobj.src = \"upload/goods/\"+ arr_TodayImg[next];\n\t\t\tvar obj2 = eval(\"document.all.href\"+i);\t\t\n\t\t\tobj2.href = \"goods_detail.php?goodsIdx=\"+arr_TodayGoodsIdx[next]; \n\t\t}\n\t}\n}\n\nfunction imgDown()\t// 오늘본상품 5개 초과일때 이미지 한칸 내리기\n{\n\tif (arr_TodayImg.length<6)\n\t{\n\t\t// alert(\"오늘본상품이 5개가 넘으면 작동함.\");\n\t}\n\telse if ((arr_TodayImg.length - current_today) > 5 )\n\t{\n\t\tcurrent_today++;\n\t\tvar next=0;\n\t\tfor (var i=0; i<5; i++)\n\t\t{\n\t\t\tnext = current_today + i;\n\t\t\tvar obj = eval(\"document.todayimg\"+i);\n\t\t\tobj.src = \"upload/goods/\"+ arr_TodayImg[next];\n\t\t\tvar obj2 = eval(\"document.all.href\"+i);\n\t\t\tobj2.href = \"goods_detail.php?goodsIdx=\"+arr_TodayGoodsIdx[next];\n\t\t}\n\t}\n}\n\nvar main_width = (screen.width - 900)/2;\n//-->\n</SCRIPT>\n<style type=\"text/css\">\n#main_layer {width:900px; text-align:left}\n#main_layer #top_layer, #main_layer #left_layer, #main_layer #center_layer, #main_layer #bottom_layer {float:left}\n#main_layer #top_layer {width:900px}\n#main_layer #left_layer {width:180px}\n#main_layer #center_layer {width:720px}\n#main_layer #bottom_layer {width:900px}\n</style>\n<body style=\"background-repeat:repeat-x;\" background='image/index/body_bg.gif' text=\"#636363\" topmargin='0' leftmargin='0'  >\n<div align=\"center\">\n<!-- 일반적인 로그인버튼 클릭시 -->\n<form name=\"a\" method=\"post\" action=\"login.php\"></form>\n<!-- mypage 로그인 체크시 referer값 셋팅-->\n<form name=\"mypage\" method=\"post\" action=\"login.php\">\n<input type=\"hidden\" name=\"referer\" value=\"http://사이트명/mypage_member.php\">\n</form>\n<form name=\"underForm\" method=\"post\" action=\"under.php\"></form>\n<table width='900' border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n\t<tr>\n\t\t<td><font style=\"position:relative;\"><div id=\"divMenu2\" style=\"position:absolute; top: 105px; left: -50px\">\n\t\t\t<table border=\"0\" cellspacing='0' cellpadding='0'>\t\t\t</table></div>\n\t\t\t<!--------------------- 우측 날개 베너 ------------------->\t\t\t<div id=\"divMenu1\" style=\"position:absolute; top: 105px; left: 900px; width:50\">\t\t\t<table width=\"45\" border=\"0\" cellspacing='0' cellpadding='0'>\n\t\t\t\t<tr>\n\t\t\t\t\t<td><a href=\"cart.php\"><img src='image/index/right_cart_t.gif' border='0'></a></td>\n\t\t\t\t</tr>\n\t\t\t\t<tr>\n\t\t\t\t\t<td background='image/index/right_cart_bg.gif' align='center'>\n\t\t\t\t\t\t<table width='40' border='0' cellspacing='0' cellpadding='0'>\n\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td bgcolor='5f8f0f' align='center'><font class='stext' color='ffffff'><b>0</b></font></td>\n\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t</table>\n\t\t\t\t\t</td>\n\t\t\t\t</tr>\n\t\t\t\t<tr>\n\t\t\t\t\t<td><img src='image/index/right_cart_b.gif'></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t\t<table width=\"45\" border=\"0\" cellspacing='0' cellpadding='0'>\n\t\t\t\t<tr>\n\t\t\t\t\t<td height='3'></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t\t<table width=\"45\" border=\"0\" cellspacing='0' cellpadding='0'>\n\t\t\t\t<tr>\n\t\t\t\t\t<td><img src='image/index/right_good_t.gif' border='0'></td>\n\t\t\t\t</tr>\n\t\t\t\t<tr>\n\t\t\t\t\t<td background='image/index/right_good_bg.gif' align='center'>\n\t\t\t\t\t\t<table width='40' border='0' cellspacing='0' cellpadding='0'>\n\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td bgcolor='4296b5' align='center'><font class='stext' color='ffffff'><b>1</b></font></td>\n\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td height='2'></td>\n\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td><a href=\"#;\" onclick=\"imgUp()\"><img src='image/index/right_prev.gif' border='0' alt='이전'></a></td>\n\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t<tr align=\"center\">\n\t\t\t\t\t\t\t\t<td height=\"42\"><a id=\"href0\" href=\"goods_detail.php?goodsIdx=224\"><img name=\"todayimg0\" src=\"upload/goods/120060721161024216.gif\" width=\"40\" height=\"40\"></a></td>\n\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td><a href=\"#;\" onclick=\"imgDown()\"><img src='image/index/right_next.gif' border='0' alt='다음'></a></td>\n\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t</table>\n\t\t\t\t\t</td>\n\t\t\t\t</tr>\n\t\t\t\t<tr>\n\t\t\t\t\t<td><img src='image/index/right_good_b.gif'></td>\n\t\t\t\t</tr>\n\t\t\t\t<tr>\n\t\t\t\t\t<td align='center'><a href='#top'><img src='image/index/right_top.gif' border='0' alt='위로'></a></td>\n\t\t\t\t</tr>\n\t\t\t</table></div></font>\n\t\t\t<script language=javascript>\n\t\t\t<!-- \n\t\t\t// 좌우측 날개 베너를 위한 스크립트\n\t\t\tvar bNetscape4plus = (navigator.appName == \"Netscape\" && navigator.appVersion.substring(0,1) >= \"4\");\n\t\t\tvar bExplorer4plus = (navigator.appName == \"Microsoft Internet Explorer\" && navigator.appVersion.substring(0,1) >= \"4\");\n\t\t\tfunction CheckUIElements()\n\t\t\t{\n\t\t\t\tvar yMenuFrom, yMenuTo, yButtonFrom, yButtonTo, yOffset, timeoutNextCheck;\n \t\t\t\tif ( bNetscape4plus )\n\t\t\t\t{\n\t\t\t\t\tyMenuTo     = window.pageYOffset + 0;\n\t\t\t\t}\n\t\t\t\telse if ( bExplorer4plus )\n\t\t\t\t{\n\t\t\t\t\tyMenuTo     = document.body.scrollTop + 105;\n\t\t\t\t}\n\t\t\t\tyMenuFrom   = parseInt(document.getElementById(\"divMenu1\").style.top, 10);\n\t\t\t\tyMenuFrom2   = parseInt(document.getElementById(\"divMenu2\").style.top, 10);\n\t\t\t\ttimeoutNextCheck = 500;\n\n\t\t\t\tif ( yMenuFrom != yMenuTo )\n\t\t\t\t{\n\t\t\t\t\tyOffset = Math.ceil( Math.abs( yMenuTo - yMenuFrom ) / 20 );\n\t\t\t\t\tif ( yMenuTo < yMenuFrom ) yOffset = -yOffset;\n\t\t\t\t\tif ( bNetscape4plus ) document.getElementById(\"divMenu1\").top += yOffset;\n\t\t\t\t\telse if ( bExplorer4plus )\n\t\t\t\t\t{\n\t\t\t\t\t\tdocument.getElementById(\"divMenu1\").style.top = parseInt (document.getElementById(\"divMenu1\").style.top, 10) + yOffset;\n\t\t\t\t\t\tdocument.getElementById(\"divMenu2\").style.top = parseInt (document.getElementById(\"divMenu2\").style.top, 10) + yOffset;\n\t\t\t\t\t}\n\t\t\t\t\ttimeoutNextCheck = 10;\n\t\t\t\t}\n\t\t\t\tsetTimeout (\"CheckUIElements()\", timeoutNextCheck);\n\t\t\t}\n\t\t\t\n\t\t\tfunction OnLoad()\n\t\t\t{\n\t\t\t\tvar y;\n\t\t\t\tif ( top.frames.length )\n\t\t\t\t{\n\t\t\t\t\tif ( bNetscape4plus )\n\t\t\t\t\t{\n\t\t\t\t\t\tdocument.getElementById(\"divMenu1\").top = top.pageYOffset + 145;\n\t\t\t\t\t\tdocument.getElementById(\"divMenu1\").visibility = \"visible\";\n\t\t\t\t\t}\n\t\t\t\t\telse if ( bExplorer4plus)\n\t\t\t\t\t{\n\t\t\t\t\t\tdocument.getElementById(\"divMenu1\").style.top = document.body.scrollTop + 145;\n\t\t\t\t\t\tdocument.getElementById(\"divMenu1\").style.visibility = \"visible\";\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t\tCheckUIElements();\n\t\t\t\treturn true;\n\t\t\t}\n\t\t\tOnLoad();\n\t\t\t//-->\n\t\t\t</script>\t\t\t<table width=\"900\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td width=\"180\" align=\"center\"><a href=\"index.php\"><img src=\"./upload/design/20060614134927_20060530180752_ci.gif\"  border=\"1\"></a></td>\n\t\t\t\t\t<td width=\"720\" valign=\"top\">\n\t\t\t\t\t\t<table width=\"720\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td align=\"right\"><table width=\"200\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\t<tr>\t\t<td><a href=\"member_article.php\" onMouseOut=\"MM_swapImgRestore()\" onMouseOver=\"MM_swapImage('Image211','','./upload/design/1144380041',1)\"><img name=\"Image211\" src=\"./upload/design/1144380040\" border=\"0\"></a></td>\t\t<td><a href=\"javascript:login();\" onMouseOut=\"MM_swapImgRestore()\" onMouseOver=\"MM_swapImage('Image311','','./upload/design/1144380060',1)\"><img name=\"Image311\" src=\"./upload/design/1144380059\" border=\"0\"></a></td>\t\t<td><a href=\"javascript:mypageLoginChek();\" onMouseOut=\"MM_swapImgRestore()\" onMouseOver=\"MM_swapImage('Image411','','upload/design/1144381305',1)\"><img name=\"Image411\" src=\"upload/design/1144381304\" border=\"0\"></a></td>\t\t<td><a href=\"cart.php\" onMouseOut=\"MM_swapImgRestore()\" onMouseOver=\"MM_swapImage('Image511','','upload/design/1144381320',1)\"><img name=\"Image511\" src=\"upload/design/1144381319\" border=\"0\"></a></td>\t\t<td><a href=\"order_refer.php\" onMouseOut=\"MM_swapImgRestore()\" onMouseOver=\"MM_swapImage('Image611','','upload/design/1144381332',1)\"><img name=\"Image611\" src=\"upload/design/1144381331\" border=\"0\"></a></td>\t</tr></table></td>\n\t\t\t\t\t\t\t\t<td height=\"20\"></td>\n\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td colspan='2' valign='bottom'>\n\t\t\t\t\t\t\t\t\t<form name='loginmainForm' method='post' action='login_ok.php'><table align='left' width='40%' cellpadding='0' cellspacing='0' border='0' height='27'>\t<tr>\t\t<td style='padding:0 0 0 10'><img src='upload/design/20060519091636_Array'></td>\t\t<td width=75><input autocomplete='off' class='text_l' type='text' name='userid' size='10' ></td>\t\t<td class=\"font11\"><div align=\"center\"><img style=\"cursor:pointer\" src=\"upload/design/20060519091645_Array\"></div></td>\t\t<td width=80><input autocomplete=\"off\" class=\"text_l\" type=\"password\" name=\"pwd\" size=\"10\" onKeyDown=\"javascript:left_loginChek(event);\"></td>\t\t<td><img style=\"cursor:pointer\" onclick=\"left_login_check();\" src=\"upload/design/20060407131646_Array\" border=\"0\" align=\"absmiddle\"></td>\t</tr></table></form>\t\t\t\t\t\t\t\t\t<table align='right' border='0' cellpadding='0' cellspacing='0'>\t<tr>\t\t<td><a href='#' onclick=\"{window.external.AddFavorite('http://사이트명','굿모닝샵 프리 쇼핑몰 솔루션')}\"><img src='./upload/design/20060614135301_20060518171558_fav.gif' border='0'></a></td>\t</tr></table>\t\t\t\t\t\t\t\t</td>\n\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td colspan='2' valign='bottom'>\n\t\t\t\t\t\t\t\t\t<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t\t\t<td valign='top'>\n\t\t\t\t\t\t\t\t\t\t\t\t<script language='javascript'>\n\t\t\t\t\t\t\t\t\t\t\t\t\tgetFlash(\"./upload/design/20060712101321_top_menu7.swf\", \"109\", \"49\");\n\t\t\t\t\t\t\t\t\t\t\t\t</script>\n\t\t\t\t\t\t\t\t\t\t\t</td>\t\t\t\t\t\t\t\t\t\t\t<td valign='top'>\n\t\t\t\t\t\t\t\t\t\t\t\t<script language='javascript'>\n\t\t\t\t\t\t\t\t\t\t\t\t\tgetFlash(\"./upload/design/20060712101326_top_menu8.swf\", \"109\", \"49\");\n\t\t\t\t\t\t\t\t\t\t\t\t</script>\n\t\t\t\t\t\t\t\t\t\t\t</td>\t\t\t\t\t\t\t\t\t\t\t<td valign='top'>\n\t\t\t\t\t\t\t\t\t\t\t\t<script language='javascript'>\n\t\t\t\t\t\t\t\t\t\t\t\t\tgetFlash(\"./upload/design/20060712101344_top_menu5.swf\", \"109\", \"49\");\n\t\t\t\t\t\t\t\t\t\t\t\t</script>\n\t\t\t\t\t\t\t\t\t\t\t</td>\t\t\t\t\t\t\t\t\t\t\t<td valign='top'>\n\t\t\t\t\t\t\t\t\t\t\t\t<script language='javascript'>\n\t\t\t\t\t\t\t\t\t\t\t\t\tgetFlash(\"./upload/design/20060712101350_top_menu6.swf\", \"109\", \"49\");\n\t\t\t\t\t\t\t\t\t\t\t\t</script>\n\t\t\t\t\t\t\t\t\t\t\t</td>\t\t\t\t\t\t\t\t\t\t\t<td valign='top'>\n\t\t\t\t\t\t\t\t\t\t\t\t<script language='javascript'>\n\t\t\t\t\t\t\t\t\t\t\t\t\tgetFlash(\"./upload/design/20060712101519_top_menu9.swf\", \"109\", \"49\");\n\t\t\t\t\t\t\t\t\t\t\t\t</script>\n\t\t\t\t\t\t\t\t\t\t\t</td>\t\t\t\t\t\t\t\t\t\t\t<td valign='top'>\n\t\t\t\t\t\t\t\t\t\t\t\t<script language='javascript'>\n\t\t\t\t\t\t\t\t\t\t\t\t\tgetFlash(\"./upload/design/20060712102054_top_menu10.swf\", \"109\", \"49\");\n\t\t\t\t\t\t\t\t\t\t\t\t</script>\n\t\t\t\t\t\t\t\t\t\t\t</td></tr>\n\t\t\t\t\t\t\t\t\t</table>\n\t\t\t\t\t\t\t\t</td>\n\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t</table>\n\t\t\t\t\t</td>\n\t\t\t\t</tr>\n\t\t\t</table><!--------------- 전체카테고리보기 & 상품검색바 ------------>\n\t\t\t<table width=\"900\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td>\n\t\t\t\t\t\t<table width='900' border='0' align='center' cellpadding='0' cellspacing='0'>\n\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td width='180'>\n\t\t\t\t\t\t\t\t\t<table width='100%' border='0' cellpadding='0' cellspacing='0' align='center'>\n\t\t\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t\t\t<td><img src=\"image/btn_anotherStoreGo.gif\" border=\"0\" onclick=\"MM_showHideLayers('Layer_cate','','show');\" style=\"cursor:pointer\"></td>\n\t\t\t\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t\t\t<td style='padding:0 0 0 5'><div style=\"position:relative;\" onMouseOver=\"MM_showHideLayers('Layer_cate','','show');\" onMouseOut=\"MM_showHideLayers('Layer_cate','','hide');\">\n\t\t\t\t\t\t\t\t\t\t\t\t<table width=\"100%\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" bgcolor=\"#ffffff\" id=\"Layer_cate\" style=\"position:absolute; top:0px; width:132px; height:120px; z-index:1; visibility: hidden; filter:alpha(opacity=85);border:1px;border-style:solid;border-color:#ffffff\">\t\t\t\t\t\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td style='padding:3 0 3 15;'><a href=\"goods_list.php?Index=1\"><font class='stext' color=\"#363636\">컴퓨터주변기기</font></a></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td style='padding:3 0 3 15;'><a href=\"goods_list.php?Index=4\"><font class='stext' color=\"#363636\">가전제품</font></a></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td style='padding:3 0 3 15;'><a href=\"goods_list.php?Index=5\"><font class='stext' color=\"#363636\">가구 | 인테리어</font></a></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td style='padding:3 0 3 15;'><a href=\"goods_list.php?Index=17\"><font class='stext' color=\"#363636\">패션잡화 | 명품</font></a></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td style='padding:3 0 3 15;'><a href=\"goods_list.php?Index=21\"><font class='stext' color=\"#363636\">화장품 | 미용</font></a></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td style='padding:3 0 3 15;'><a href=\"goods_list.php?Index=25\"><font class='stext' color=\"#363636\">스포츠 | 레져</font></a></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td width='1' bgcolor='cccccc'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t<td colspan='3' bgcolor='cccccc' height='1'></td>\n\t\t\t\t\t\t\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t\t\t\t\t\t</table></div>\n\t\t\t\t\t\t\t\t\t\t\t</td>\n\t\t\t\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t\t\t</table>\n\t\t\t\t\t\t\t\t</td>\n\t\t\t\t\t\t\t\t<td width=\"630\">\n\t\t\t\t\t\t\t\t\t<form name=\"topGoodsSearchForm\" method=\"get\" action=\"search_result.php\">\n\t\t\t\t\t\t\t\t\t<table width=\"350\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t\t\t<td align=\"right\"><img align=\"absmiddle\" src=\"upload/design/20060529221434_search1.gif\"></td>\n\t\t\t\t\t\t\t\t\t\t\t<td width='100' align=\"center\"><select name=\"search\" class=\"box\"><option value=\"name\">상품명</option><option value=\"price\">가격</option><option value=\"company\">제조사</option><option value=\"model\">모델명</option></select></td>\n\t\t\t\t\t\t\t\t\t\t\t<td><input type=\"text\" name=\"searchstring\" size=\"25\" class=\"text_l\"></td>\n\t\t\t\t\t\t\t\t\t\t\t<td width=32 align=\"right\"><a href=\"javascript:goodsSearchSendit(document.topGoodsSearchForm);\"><img align=\"absmiddle\" src=\"upload/design/20060518163158_search00.gif\" border=\"0\"></a></td>\n\t\t\t\t\t\t\t\t\t\t\t<td width=68 align=\"right\"><a href=\"detail_search.php\"><img align=\"absmiddle\" src=\"upload/design/20060518163443_search01.gif\" border=\"0\"></a></td>\n\t\t\t\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t\t\t</table></form>\n\t\t\t\t\t\t\t\t</td>\n\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t</table>\n\t\t\t\t\t</td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td> \n\t</tr>\n</table><table width=\"900\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" bgcolor=\"#ffffff\">\n\t<tr>\n\t\t<td valign=\"top\" width=\"180\">\n\t<table width=\"180\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\">\t</table>\t<table width=\"180\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\">\n\t\t<tr>\n\t\t\t<td valign=\"top\"><!--  카테고리 시작  -->\n\t\t\t\t<table width=\"175\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align='center'>\n\t\t\t\t\t<tr>\n\t\t\t\t\t\t<td bgcolor=\"#FFFFFF\" valign=\"top\">\n\t\t\t\t\t\t\t<table width=\"175\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align='center'>\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t<td align=\"center\"><img src=\"./upload/design/20050425112341_cate_t.gif\"></td>\n\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t<td></td>\n\t\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t<td valign=\"top\">\n\t\t\t\t\t\t\t\t\t\t<table width=\"150\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\">\t\t\t\t\t\t\t\t\t\t\t<tr onMouseOut=\"MM_showHideLayers('Layer1','','hide');MM_swapImgRestore();\" onMouseOver=\"MM_showHideLayers('Layer1','','show');MM_swapImage('Image151','','upload/category/b96030_cate2_1.gif',1);\" style=\"cursor:pointer;\" >\t\t\t\t\t\t\t\t\t\t\t\t<td height=\"25\" onclick=\"location.href='goods_list.php?Index=1'\"><img name=\"Image151\" border=\"0\" src=\"upload/category/a96030_cate2.gif\" height=\"25\" width=175></td>\t\t\t\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t\t\t\t<tr onMouseOut=\"MM_showHideLayers('Layer2','','hide');MM_swapImgRestore();\" onMouseOver=\"MM_showHideLayers('Layer2','','show');MM_swapImage('Image152','','upload/category/b95996_cate1_1.gif',1);\" style=\"cursor:pointer;\" >\t\t\t\t\t\t\t\t\t\t\t\t<td height=\"25\" onclick=\"location.href='goods_list.php?Index=4'\"><img name=\"Image152\" border=\"0\" src=\"upload/category/a95996_cate1.gif\" height=\"25\" width=175></td>\t\t\t\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t\t\t\t<tr onMouseOut=\"MM_showHideLayers('Layer3','','hide');MM_swapImgRestore();\" onMouseOver=\"MM_showHideLayers('Layer3','','show');MM_swapImage('Image153','','upload/category/b96392_cate3_1.gif',1);\" style=\"cursor:pointer;\" >\t\t\t\t\t\t\t\t\t\t\t\t<td height=\"25\" onclick=\"location.href='goods_list.php?Index=5'\"><img name=\"Image153\" border=\"0\" src=\"upload/category/a96392_cate3.gif\" height=\"25\" width=175></td>\t\t\t\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t\t\t\t<tr onMouseOut=\"MM_showHideLayers('Layer4','','hide');MM_swapImgRestore();\" onMouseOver=\"MM_showHideLayers('Layer4','','show');MM_swapImage('Image154','','upload/category/b96624_cate6_1.gif',1);\" style=\"cursor:pointer;\" >\t\t\t\t\t\t\t\t\t\t\t\t<td height=\"25\" onclick=\"location.href='goods_list.php?Index=17'\"><img name=\"Image154\" border=\"0\" src=\"upload/category/a96624_cate6.gif\" height=\"25\" width=175></td>\t\t\t\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t\t\t\t<tr onMouseOut=\"MM_showHideLayers('Layer5','','hide');MM_swapImgRestore();\" onMouseOver=\"MM_showHideLayers('Layer5','','show');MM_swapImage('Image155','','upload/category/b96613_cate5_1.gif',1);\" style=\"cursor:pointer;\" >\t\t\t\t\t\t\t\t\t\t\t\t<td height=\"25\" onclick=\"location.href='goods_list.php?Index=21'\"><img name=\"Image155\" border=\"0\" src=\"upload/category/a96613_cate5.gif\" height=\"25\" width=175></td>\t\t\t\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t\t\t\t<tr onMouseOut=\"MM_showHideLayers('Layer6','','hide');MM_swapImgRestore();\" onMouseOver=\"MM_showHideLayers('Layer6','','show');MM_swapImage('Image156','','upload/category/b96415_cate4_1.gif',1);\" style=\"cursor:pointer;\" >\t\t\t\t\t\t\t\t\t\t\t\t<td height=\"25\" onclick=\"location.href='goods_list.php?Index=25'\"><img name=\"Image156\" border=\"0\" src=\"upload/category/a96415_cate4.gif\" height=\"25\" width=175></td>\t\t\t\t\t\t\t\t\t\t\t</tr><!-- 왼쪽 카테고리 메뉴 끝 -->\n\t\t\t\t\t\t\t\t\t\t</table>\n\t\t\t\t\t\t\t\t\t</td>\n\t\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t</table>\n\t\t\t\t\t\t</td>\n\t\t\t\t\t</tr>\n\t\t\t\t</table><!--  카테고리 끝  -->\n\t\t\t</td>\n\t\t</tr>\n\t\t<tr>\n\t\t\t<td height='5'></td>\n\t\t</tr>\n\t</table><!-------무료배송------------><!--  게시판 시작  -->\t<table width=\"180\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\">\n\t\t<tr>\n\t\t\t<td>\n\t\t\t\t<table width=\"175\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\">\n\t\t\t\t\t<tr>\n\t\t\t\t\t\t<td bgcolor=\"#FFFFFF\" valign=\"top\"><a href='community.php'><img src=\"./upload/design/20060518152401_tit_commu.gif\" border='0'></a></td>\n\t\t\t\t\t</tr>\n\t\t\t\t\t<tr>\n\t\t\t\t\t\t<td width=\"175\" bgcolor=\"#FFFFFF\">\n\t\t\t\t\t\t\t<table width=\"150\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\">\n\t\t\t\t\t\t\t<!-- 게시판 시작 -->\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t<td><a href=\"board_list.php?boardIndex=1\"><img src=\"upload/bbs/name30512_commu02.gif\"></a></td>\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t<td><a href=\"board_list.php?boardIndex=4\"><img src=\"upload/bbs/name30555_commu01.gif\"></a></td>\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t<td><a href=\"board_list.php?boardIndex=5\"><img src=\"upload/bbs/name30572_commu03.gif\"></a></td>\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t<td><a href=\"board_list.php?boardIndex=6\"><img src=\"upload/bbs/name71714_bbs.gif\"></a></td>\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t<td><a href=\"board_list.php?boardIndex=7\"><img src=\"upload/bbs/name71727_bbs.gif\"></a></td>\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t<td><a href=\"board_list.php?boardIndex=8\"><img src=\"upload/bbs/name71733_bbs.gif\"></a></td>\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t<td><a href=\"board_list.php?boardIndex=9\"><img src=\"upload/bbs/name71744_bbs.gif\"></a></td>\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t<td><a href=\"board_list.php?boardIndex=10\"><img src=\"upload/bbs/name71751_bbs.gif\"></a></td>\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t<td><a href=\"board_list.php?boardIndex=11\"><img src=\"upload/bbs/name71758_bbs.gif\"></a></td>\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t<td><a href=\"board_list.php?boardIndex=12\"><img src=\"upload/bbs/name71769_bbs.gif\"></a></td>\t\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t\t\t<tr>\t\t\t\t\t\t\t\t\t<td><a href=\"board_list.php?boardIndex=13\"><img src=\"upload/bbs/name30673_commu04.gif\"></a></td>\t\t\t\t\t\t\t\t</tr><!-- 게시판 끝 -->\n\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t<td height=\"10\"></td>\n\t\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t</table>\n\t\t\t\t\t\t</td>\n\t\t\t\t\t</tr>\n\t\t\t\t</table>\n\t\t\t</td>\n\t\t</tr>\n\t</table><!--  게시판  끝  --><!--  공통  배너 시작  -->\n\t<table width=\"180\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\"> \n\t\t<tr>\n\t\t\t<td valign=\"top\">\n\t\t\t\t<table width=\"175\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\"><!--   배너  시작 --><!-- 오른쪽 배너  끝 -->\n\t\t\t\t</table>\n\t\t\t</td>\n\t\t</tr>\n\t</table>\n\t<table width='180' border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\">\n\t\t<tr>\n\t\t\t<td><script language='javascript'>\n\t\t\t\tgetFlash(\"image/index/banner.swf\", \"180\", \"57\");\n\t\t\t</script></td>\n\t\t</tr>\n\t</table>\n\t<!--  공통 배너 끝  -->\n\t<!--  설문조사 시작  --><!--  카테고리별  배너 시작  --></td>\t\t<td height=\"51\" valign=\"top\" width=\"720\" bgcolor=\"#FFFFFF\">\n\t\t\t<table width=\"720\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr bgcolor=\"#FFFFFF\" valign=\"top\">\n\t\t\t\t\t<td colspan=\"2\" height=\"51\">\n\t\t\t\t\t\t<table width=\"720\" height=\"35\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" ailgn='center'>\n\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td width=\"2\"  bgcolor=\"FFFFFF\" rowspan=\"2\"></td>\n\t\t\t\t\t\t\t\t<td width=\"2\"  bgcolor=\"FFFFFF\" rowspan=\"2\"></td>\n\t\t\t\t\t\t\t\t<td width=\"220\" height=\"30\" bgcolor=\"FFFFFF\"><img src=\"./upload/design/1137634958\" ></td>\n\t\t\t\t\t\t\t\t<td width=\"490\" height=\"30\" bgcolor=\"FFFFFF\"><div align=\"right\"> &nbsp;<font color=\"464646\"> &nbsp; 현재위치 : HOME &gt; 상세검색</font>&nbsp;</div></td>\n\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t</table>\n\t\t\t\t\t</td>\n\t\t\t\t</tr>\n\t\t\t\t<tr>\n\t\t\t\t\t<td valign=\"top\" width=\"720\">\n\t\t\t\t\t\t<table width=\"714\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td><img src=\"./upload/design/1148025069\" ></td>\n\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t</table>\n\t\t\t\t\t</td>\n\t\t\t\t</tr>\n\t\t\t\t<tr>\n\t\t\t\t\t<td valign=\"top\" width=\"720\">\t\t\t\t\t\t<SCRIPT LANGUAGE=\"JavaScript\">\n\t\t\t\t\t\t<!--\n\t\t\t\t\t\t//소팅 전송   (정렬기준,방법)\n\t\t\t\t\t\tfunction goodsSort()\n\t\t\t\t\t\t{\n\t\t\t\t\t\t\tvar form=document.sortForm;\n\t\t\t\t\t\t\tvar Index = form.sortIndex.selectedIndex;\n\t\t\t\t\t\t\tif(Index ==1)\n\t\t\t\t\t\t\t{\n\t\t\t\t\t\t\t\tform.sort.value=\"asc\";\n\t\t\t\t\t\t\t\tform.sortStr.value = \"name\";\n\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\telse if(Index==2)\n\t\t\t\t\t\t\t{\n\t\t\t\t\t\t\t\tform.sort.value=\"desc\";\n\t\t\t\t\t\t\t\tform.sortStr.value = \"name\";\n\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\telse if(Index==3)\n\t\t\t\t\t\t\t{\n\t\t\t\t\t\t\t\tform.sort.value=\"asc\";\n\t\t\t\t\t\t\t\tform.sortStr.value = \"price\";\n\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\telse if(Index==4)\n\t\t\t\t\t\t\t{\n\t\t\t\t\t\t\t\tform.sort.value=\"desc\";\n\t\t\t\t\t\t\t\tform.sortStr.value = \"price\";\n\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\tform.submit();\n\t\t\t\t\t\t}\n\t\t\t\t\t\t//-->\n\t\t\t\t\t\t</SCRIPT>\t\t\t\t\t\t<table width=\"650\" border=\"0\" cellspacing=\"1\" cellpadding=\"0\" align=\"center\" bgcolor='e1e1e1'>\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td  height=\"30\" bgcolor='f7f7f7' style='padding:0 0 0 15'><img src='image/sub/search_code.gif' align='absmiddle'> &nbsp;&nbsp;&nbsp;현재 ‘ 상품명 : <FONT  COLOR=\"#e10000\"><b>') order by 1#</b></FONT> '(으)로 검색하셨습니다.</td>\n\t\t\t\t\t\t\t</tr>\t\t\t\t\t\t</table>\n\t\t\t\t\t\t<table width=\"670\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\">\n\t\t\t\t\t\t\t<form name=\"sortForm\" method=\"post\" action=\"search_result.php\">\n\t\t\t\t\t\t\t<input type=\"hidden\" name=\"sort\"><!-- 정렬방법 ex)asc:오름차순  desc:내림차순 -->\n\t\t\t\t\t\t\t<input type=\"hidden\" name=\"sortStr\"><!-- 정렬기준 ex)name:이름  price:가격 -->\n\t\t\t\t\t\t\t<input type=\"hidden\" name=\"name\" value=\"\"><!-- 상품명 -->\n\t\t\t\t\t\t\t<input type=\"hidden\" name=\"price\" value=\"\"><!-- 가격 -->\n\t\t\t\t\t\t\t<input type=\"hidden\" name=\"company\" value=\"\"><!-- 회사 -->\n\t\t\t\t\t\t\t<input type=\"hidden\" name=\"category\" value=\"\"><!-- 분류 -->\n\t\t\t\t\t\t\t<input type=\"hidden\" name=\"detail\" value=\"\"><!-- 검색방법 ex) 1:상세검색 0:일반검색 -->\n\t\t\t\t\t\t\t<input type=\"hidden\" name=\"data\" value=\"pagecnt%3D0%26letter_no%3D32%26offset%3D0%26search%3Dname%26searchstring%3D%27%29+order+by+1%23%26present_num%3D32\">\n\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td height=\"40\" colspan=\"4\">\n\t\t\t\t\t\t\t\t\t<table width=\"650\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align='center'>\n\t\t\t\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t\t\t\t<td><font color=\"#003366\">총 <B>2</B> 페이지에 <B>32</B> 개의 상품이 준비되어 있습니다.</font></td>\n\t\t\t\t\t\t\t\t\t\t\t<td height=\"30\" width=\"141\"> <select name=\"sortIndex\" onChange=\"javascript:goodsSort();\"><option value=\"0\">상품정렬기준 선택</option><option value=\"1\">이름순△</option><option value=\"2\">이름순▽</option><option value=\"3\">가격순△</option><option value=\"4\">가격순▽</option></select></td>\n\t\t\t\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t\t\t</table>\n\t\t\t\t\t\t\t\t</td>\n\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t</form>\n\t\t\t\t\t\t\t<tr>\n\t\t\t\t\t\t\t\t<td bgcolor='e1e1e1' height=\"1\" colspan=\"4\"></td>\n\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t<tr valign=\"bottom\">\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=202\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/gd_c44040_5001.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=202\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=202\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=203\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721160622202.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=203\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=203\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=204\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721160635202.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=204\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=204\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=205\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721160635203.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=205\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=205\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t</tr>\n\t<tr>\n\t\t<td height='1' bgcolor='dadada' colspan='4'></td>\n\t</tr>\n\t<tr valign=\"bottom\">\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=206\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161008202.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=206\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=206\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=207\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161008203.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=207\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=207\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=208\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161008204.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=208\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=208\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=209\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161008205.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=209\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=209\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t</tr>\n\t<tr>\n\t\t<td height='1' bgcolor='dadada' colspan='4'></td>\n\t</tr>\n\t<tr valign=\"bottom\">\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=210\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161017202.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=210\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=210\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=211\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161017203.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=211\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=211\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=212\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161017204.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=212\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=212\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=213\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161017205.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=213\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=213\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t</tr>\n\t<tr>\n\t\t<td height='1' bgcolor='dadada' colspan='4'></td>\n\t</tr>\n\t<tr valign=\"bottom\">\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=214\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161017206.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=214\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=214\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=215\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161017207.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=215\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=215\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=216\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161017208.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=216\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=216\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=217\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161017209.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=217\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=217\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t</tr>\n\t<tr>\n\t\t<td height='1' bgcolor='dadada' colspan='4'></td>\n\t</tr>\n\t<tr valign=\"bottom\">\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=218\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161024210.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=218\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=218\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=219\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161024211.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=219\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=219\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=220\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161024212.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=220\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=220\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=221\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161024213.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=221\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=221\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=222\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161024214.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=222\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=222\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=223\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161024215.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=223\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=223\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=224\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161024216.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=224\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=224\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=225\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161024217.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=225\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=225\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=226\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161031218.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=226\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=226\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=227\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161031219.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=227\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=227\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=228\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161031220.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=228\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=228\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=229\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161031221.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=229\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=229\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=230\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161031222.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=230\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=230\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=231\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161031223.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=231\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=231\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=232\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161031224.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=232\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=232\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t<td height=\"180\" valign=\"top\">\n\t\t\t<table style=\"table-layout:fixed;\" width=\"170\" border=\"0\" cellspacing=\"2\" cellpadding=\"0\" align=\"center\"><!-- 목록상에서 상품 1개의 상세정보 출력 include 파일 (바둑판식) -->\n\t<tr>\n\t\t<td valign=\"top\" align=\"center\"><a href=\"goods_detail.php?goodsIdx=233\"><img style=\"border-width:1px;border-color:#eeeeee;border-style:solid;\" src=\"upload/goods/120060721161031225.gif\" width=\"100\" height=\"100\" border=\"0\"></a></td>\n\t</tr>\n\t<tr>\n\t\t<td><div align=\"center\"><a href=\"goods_detail.php?goodsIdx=233\"><font color=\"#000000\">아름다운 풍경사진</font></a></div></td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_price_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF3000\"><b>1,000 원</b></font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\">\n\t\t\t\t<tr>\t\t\t\t\t<td><img src=\"upload/goods_point_img\"></td>\n\t\t\t\t\t<td><font color=\"#FF7E00\">10 원</font></td>\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td>\n\t\t\t<table align=\"center\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\t<tr>\n\t\t<td align=\"center\"><a href=\"goods_detail.php?goodsIdx=233\"><img src=\"image/icon/buy_btn.gif\" border=\"0\"></a></td>\n\t</tr>\t\t\t</table>\n\t\t</td>\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t\t<tr valign=\"bottom\">\n\t\t\t\t\t\t\t\t<td colspan=\"4\" height=\"50\" align=\"center\"><img src='image/board/btn_prev.gif'>&nbsp;&nbsp;&nbsp; 1 <a href='search_result.php?data=offset%3D20%26letter_no%3D12%26pagecnt%3D0%26search%3Dname%26searchstring%3D%27%29+order+by+1%23&position=&sort=&sortStr=&detail=&name=&company=&price=&category='>[2]</a>&nbsp;&nbsp;&nbsp;<img src='image/board/btn_next.gif'></td>\n\t\t\t\t\t\t\t</tr>\n\t\t\t\t\t\t</table><br>\n\t\t\t\t\t</td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\n</table>\n<table width=\"900\" border가0\" cellspacing=\"0\" cellpadding=\"0\">\n\t<tr>\n\t\t<td colspan='2' height='1' bgcolor='e1e1e1'></td>\n\t</tr>\n</table>\n<table width=\"900\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n\t<tr bgcolor=\"#F4F4F4\">\n\t\t<td colspan='2' height=\"35\" style='padding:0 0 0 15'> <a href=\"company.php\"><img src='image/index/copy01.gif' border='0' align='absmiddle'></a>  <a href=\"use_guide.php\"><img src='image/index/copy02.gif' border='0' align='absmiddle'></a>  <a href=\"member_article.php\"><img src='image/index/copy03.gif' border='0' align='absmiddle'></a>  <a href=\"person_guard.php\"><img src='image/index/copy04.gif' border='0' align='absmiddle'></a>  <a href=\"cooperation.php\"><img src='image/index/copy05.gif' border='0' align='absmiddle'></a><a href=\"ask_list.php\"><img src='image/index/copy09.gif' border='0' align='absmiddle'></a></td>\n\t\t<td width='60'><a href='#top'><img src='image/index/btn_top.gif' border='0'></a></td>\n\t</tr>\n</table>\n<table width=\"900\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n\t<tr>\n\t\t<td height='1' bgcolor='e1e1e1'></td>\n\t</tr>\n\t<tr>\n\t\t<td height=\"80\" valign=\"top\" style='padding:5 0 0 0'>\n\t\t\t<table width=\"800\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n\t\t\t\t<tr>\n\t\t\t\t\t<td align='center'><img src=\"upload/design/20060525152033_copy_logo.gif\"></td>\n\t\t\t\t\t<td align='center'><font class='stext' color=\"#000000\">Copyright ⓒ 굿모닝샵 All Rights Reserved Any questions to <a href=\"javascript:sendMail('[REDACTED_EMAIL]');\"><U>[REDACTED_EMAIL]</U></a><br><br>공정거래 위원회에서 인증한 표준약관을 사용합니다. <br>통신판매업신고 제 15219 호,정보 보호 담당자 : 홍길동, 사업자등록번호 : 111-22-33333 대표자 홍길동 <br>Tel : 02-1234-5678~9, Fax : 02-1234-5677, 주소 : 서울 종로구 명륜동2가  13 [110-522 ]</font></td>\n\t\t\t\t</tr>\n\t\t\t</table>\n\t\t</td>\n\t</tr>\n\t<tr>\n\t\t<td align='right'><a href='http://webprogram.co.kr' target='_blank'><img src='image/index/poweredby.gif' border='0'></a></td>\n\t</tr>\n</table></div>\n</body>\n</html>",
    "body_excerpt": "<html>\n<head>\n<style>\n.box {font-size: 9pt; border:1px solid #464646;background-color:white;  } \n.box1 {font-size: 9pt; border:1px solid #d4d0c8;background-color:#F7F7F7;  } \n.graybox {font-size: 9pt; border:1px solid #000000;background-color:#d4d0c8;  } \n.nonbox {font-size: 9pt; border:0px solid #000000;background-color:white;  } \n.radio {font-size: 9pt; border:0px solid #000000;background-color:white;  } \n.text {font-size: 9pt; border:1px solid #000000;}\n.text_l {font-size: 9pt; border:1px solid #ACACAC;}\n.mem {font-size:8pt;font-family: \"돋움\";letter-spacing:-1;color:#464646;}\n.stext{font-size:8pt;font-family: \"돋움\";}\n.sm {font-size:8pt;font-family: \"돋움\";letter-spacing:-1;color:#ff4800;}\n.text1 { FONT-SIZE: 9pt; COLOR: #7C682D; BACKGROUND-COLOR: #F6F4EE; Border:1px SOLID #E1DCCD;}\n.text2 { FONT-SIZE: 9pt; COLOR: #7C682D; BACKGROUND-COLOR: #F6F4EE; Border:1px SOLID #E1DCCD;}\n.select1 {font-size: 8pt; border:0px solid #ffffff;background-color:#638bb7; color:#ffffff;}\n.select {font-size: "
  }
}

    print("🤖 실제 패킷 데이터로 취약점 진단 및 보고서 생성 중...")
    report_file_path = generate_vulnerability_report(sample_packet)
    print(f"✅ 보고서 생성 완료! 저장된 위치: {os.path.abspath(report_file_path)}")