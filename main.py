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
9. Security Misconfiguration

[General Rules]
1. Analyze every supplied HTTP section. The input may contain Request only, Response only, or both.
2. Do not classify a request as vulnerable only because it contains suspicious input.
3. Use observable Request and Response evidence together whenever both are supplied.
4. Do not assume server-side behavior that cannot be observed.
5. If evidence is insufficient, return N/A instead of guessing.
6. Evidence must come from the supplied Request or Response. Do not assume or describe a section that was not supplied.
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
  "vulnerabilities": [
    {
      "vulnerability_name": "Canonical English vulnerability name",
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
  ]
}

Return one array item for every distinct vulnerability assessment that is relevant to the supplied data.
Do not combine different vulnerability types into one item and do not return duplicate vulnerability types.
Do not generate vulnerability_count or choose a representative vulnerability; application code will calculate them.
""".strip()


def parse_incoming_json(json_data: dict) -> str:
    if not isinstance(json_data, dict):
        raise ValueError("LLM 입력은 JSON 객체여야 합니다.")

    sections = []
    req = json_data.get("request")
    res = json_data.get("response")

    if req is not None:
        request_lines = [
            "[HTTP Request (Masked)]",
            f"Method: {req.get('method', 'UNKNOWN')}",
            f"Path: {req.get('path', '/')}",
            f"Query Params: {json.dumps(req.get('query_params', {}), ensure_ascii=False)}",
            f"Headers: {json.dumps(req.get('headers', {}), ensure_ascii=False)}",
        ]
        if req.get('body') is not None:
            request_lines.append(f"Body: {json.dumps(req['body'], ensure_ascii=False)}")
        sections.append("\n".join(request_lines))

    if res is not None:
        response_body = res.get('body_excerpt') or res.get('body', '')
        sections.append(
            "[HTTP Response (Masked)]\n"
            f"Status Code: {res.get('status_code', 'UNKNOWN')}\n"
            f"Headers: {json.dumps(res.get('headers', {}), ensure_ascii=False)}\n"
            f"Body Excerpt: {response_body}"
        )

    if not sections:
        raise ValueError("Request 또는 Response 중 하나 이상이 필요합니다.")

    return "\n\n".join(sections)


VERDICT_KO = {"VULNERABLE": "취약", "SAFE": "양호", "N/A": "판단 불가"}
SEVERITY_KO = {
    "CRITICAL": "매우 심각", "HIGH": "높음", "MEDIUM": "보통",
    "LOW": "낮음", "INFO": "정보",
}
VULNERABILITY_NAME_KO = {
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
OWASP_CATEGORY_KO = {
    "A01 Broken Access Control": "A01 접근 통제 실패",
    "A05 Injection": "A05 인젝션",
}


SEVERITY_RANK = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
}


def _postprocess_vulnerability(vulnerability: dict) -> dict:
    finding = dict(vulnerability)
    verdict = str(finding.get("verdict", "N/A")).upper()
    if verdict not in VERDICT_KO:
        verdict = "N/A"
    finding["verdict"] = verdict
    finding["verdict_ko"] = VERDICT_KO[verdict]

    severity = finding.get("severity")
    if isinstance(severity, str):
        severity = severity.upper()
    if verdict != "VULNERABLE" or severity not in SEVERITY_KO:
        severity = None
    finding["severity"] = severity
    finding["severity_ko"] = SEVERITY_KO.get(severity)

    vulnerability_name = finding.get("vulnerability_name")
    finding["vulnerability_name_ko"] = VULNERABILITY_NAME_KO.get(vulnerability_name)
    owasp_category = finding.get("owasp_category")
    finding["owasp_category_ko"] = OWASP_CATEGORY_KO.get(owasp_category)
    return finding


def select_representative_vulnerability(vulnerabilities: list[dict]) -> dict | None:
    """가장 높은 severity의 VULNERABLE 항목을 선택하고 동률이면 첫 항목을 유지한다."""
    vulnerable_findings = [
        finding for finding in vulnerabilities
        if finding.get("verdict") == "VULNERABLE"
    ]
    if vulnerable_findings:
        return max(
            vulnerable_findings,
            key=lambda finding: SEVERITY_RANK.get(finding.get("severity"), 0),
        )
    return None


def _non_vulnerable_summary(vulnerabilities: list[dict]) -> dict:
    """대표 취약점 없이 SAFE/N/A의 보고서용 근거만 최상위에 유지한다."""
    # 하나라도 판단 불가 항목이 있으면 전체 요약도 보수적으로 N/A로 둔다.
    summary = next(
        (finding for finding in vulnerabilities if finding["verdict"] == "N/A"),
        None,
    )
    if summary is None:
        summary = next(
            (finding for finding in vulnerabilities if finding["verdict"] == "SAFE"),
            None,
        )

    verdict = summary["verdict"] if summary else "N/A"
    result = {
        "vulnerability_name": None,
        "vulnerability_name_ko": None,
        "owasp_category": None,
        "owasp_category_ko": None,
        "verdict": verdict,
        "verdict_ko": VERDICT_KO[verdict],
        "severity": None,
        "severity_ko": None,
        "reason": "분석 가능한 취약점 결과가 없습니다.",
        "evidence": {"request": [], "response": []},
        "impact": None,
        "remediation_summary": None,
        "additional_check": None,
    }
    if summary:
        for key in (
            "reason", "evidence", "impact", "remediation_summary", "additional_check"
        ):
            result[key] = summary.get(key)
    return result


def postprocess_llm_result(llm_result: dict) -> dict:
    """전체 결과를 정규화하고 취약점 건수와 대표 취약점을 Python에서 계산한다."""
    result = dict(llm_result)
    raw_vulnerabilities = result.get("vulnerabilities", [])
    if not isinstance(raw_vulnerabilities, list):
        raw_vulnerabilities = []

    vulnerabilities = [
        _postprocess_vulnerability(item)
        for item in raw_vulnerabilities
        if isinstance(item, dict)
    ]
    result["vulnerabilities"] = vulnerabilities
    result["vulnerability_count"] = sum(
        finding["verdict"] == "VULNERABLE" for finding in vulnerabilities
    )

    if result["vulnerability_count"]:
        representative = select_representative_vulnerability(vulnerabilities)
        result.update(representative)
    else:
        result.update(_non_vulnerable_summary(vulnerabilities))
    return result


def build_openai_request_payload(packet_context: str) -> dict:
    supplied_sections = []
    if "[HTTP Request (Masked)]" in packet_context:
        supplied_sections.append("Request")
    if "[HTTP Response (Masked)]" in packet_context:
        supplied_sections.append("Response")
    scope = " and ".join(supplied_sections)
    user_prompt = f"""Analyze the following supplied masked HTTP {scope} data.

{packet_context}
"""
    return {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }


def run_llm_diagnosis(packet_context: str) -> dict:
    try:
        response = client.chat.completions.create(**build_openai_request_payload(packet_context))
        return postprocess_llm_result(json.loads(response.choices[0].message.content))
    except Exception as e:
        return {"error": str(e)}


def print_terminal_summary(llm_result: dict):
    verdict = llm_result.get("verdict", "UNKNOWN")
    vuln_name = llm_result.get("vulnerability_name", "N/A")
    severity = llm_result.get("severity", "N/A")
    owasp = llm_result.get("owasp_category", "N/A")
    reason = llm_result.get("reason", "근거 없음")
    vulnerability_count = llm_result.get("vulnerability_count", 0)
    
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
    print(f"• 전체 취약점 수: {vulnerability_count}")
    print(f"• 판단 근거   : {reason}")
    print("="*60 + "\n")


def generate_report_html_content(llm_result: dict) -> str:
    vuln_name = llm_result.get("vulnerability_name", "SQL Injection")
    vuln_name_ko = llm_result.get("vulnerability_name_ko")
    if vuln_name_ko:
        vuln_name = f"{vuln_name} / {vuln_name_ko}"
    verdict = llm_result.get("verdict", "VULNERABLE")
    severity = llm_result.get("severity")
    owasp_category = llm_result.get("owasp_category")
    reason = llm_result.get("reason", "근거 없음")
    impact = llm_result.get("impact")
    additional_check = llm_result.get("additional_check")
    remediation_summary = llm_result.get("remediation_summary")
    vulnerabilities = llm_result.get("vulnerabilities", [])
    vulnerability_count = llm_result.get("vulnerability_count", 0)

    # 배지 생성
    if verdict == "VULNERABLE":
        result_badge = '<span class="badge badge-vulnerable">취약 발견 (VULNERABLE)</span>'
    elif verdict == "SAFE":
        result_badge = '<span class="badge badge-safe">양호 (SAFE)</span>'
    else:
        result_badge = '<span class="badge badge-na">판단 불가 (N/A)</span>'

    severity_badge = f'<span class="badge badge-severity">{severity}</span>' if severity and str(severity).upper() not in ["NULL", "NONE", "N/A"] else '<span style="color:#64748b;">-</span>'

    # 분석 근거 데이터 추출
    evidence_dict = llm_result.get("evidence", {})
    req_evidence = "<br>• ".join([""] + evidence_dict.get("request", ["근거 없음"]))
    res_evidence = "<br>• ".join([""] + evidence_dict.get("response", ["근거 없음"]))

    def is_valid(val):
        return val and str(val).strip().upper() not in ["NULL", "NONE", "N/A"]

    all_findings_html = "".join(
        f"""
        <div class="lang-card">
            <div class="lang-title">{index}. {html.escape(str(finding.get('vulnerability_name', 'N/A')))}</div>
            <pre><code>{html.escape(json.dumps(finding, ensure_ascii=False, indent=2))}</code></pre>
        </div>
        """
        for index, finding in enumerate(vulnerabilities, start=1)
    )
    
    # 전체 취약점 분석 결과 섹션은 SAFE가 아닐 때만 노출
    all_findings_section = ""
    if verdict != "SAFE":
        all_findings_section = f"""
        <div class="section">
            <div class="section-title">전체 취약점 분석 결과 ({vulnerability_count}건 탐지)</div>
            {all_findings_html or '<div class="desc-box">탐지된 취약점이 없습니다.</div>'}
        </div>
        """

    # 동적 테이블 행 구성 (SAFE 판정인 경우 판정 근거와 분석 근거만 출력)
    table_rows = ""
    if verdict == "SAFE":
        table_rows += f"""
        <tr>
            <th>판단 근거 요약</th>
            <td>{reason}</td>
        </tr>
        <tr>
            <th>요청 분석 근거 (Request)</th>
            <td>{req_evidence}</td>
        </tr>
        <tr>
            <th>응답 분석 근거 (Response)</th>
            <td>{res_evidence}</td>
        </tr>
        """
    else:
        table_rows += f"""
        <tr>
            <th>취약점 명칭</th>
            <td><b>{vuln_name}</b></td>
        </tr>
        """
        if is_valid(owasp_category):
            table_rows += f"<tr><th>OWASP 분류</th><td>{owasp_category}</td></tr>"
            
        table_rows += f"<tr><th>위험도 (Severity)</th><td>{severity_badge}</td></tr>"

        table_rows += f"""
        <tr>
            <th>판단 근거 요약</th>
            <td>{reason}</td>
        </tr>
        <tr>
            <th>요청 분석 근거 (Request)</th>
            <td>{req_evidence}</td>
        </tr>
        <tr>
            <th>응답 분석 근거 (Response)</th>
            <td>{res_evidence}</td>
        </tr>
        """

        if is_valid(impact):
            table_rows += f"<tr><th>보안 영향 (Impact)</th><td>{impact}</td></tr>"

        if verdict == "N/A" and is_valid(additional_check):
            table_rows += f"<tr><th>추가 확인사항 (N/A 전용)</th><td>{additional_check}</td></tr>"

    # 시큐어코딩 섹션 렌더링 (VULNERABLE인 경우 각 취약점별로 가이드 생성)
    secure_coding_section = ""
    if verdict == "VULNERABLE":
        # 검출된 취약점 리스트(vulnerabilities)를 기반으로 각각 시큐어코딩 가이드 생성 (없으면 기본 대표 취약점 사용)
        target_vulns = vulnerabilities if vulnerabilities else [llm_result]
        multi_vuln_secure_html = ""

        for v_idx, finding in enumerate(target_vulns, start=1):
            current_vuln_name = finding.get("vulnerability_name", vuln_name)
            current_remediation = finding.get("remediation_summary", remediation_summary)

            code_guide = None
            for key in SECURE_CODE_DATABASE:
                if key.lower() in current_vuln_name.lower() or current_vuln_name.lower() in key.lower():
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

            multi_vuln_secure_html += f"""
            <div style="margin-bottom: 25px; border-bottom: 1px dashed #cbd5e1; padding-bottom: 20px;">
                <div style="font-size: 11pt; font-weight: 700; color: #1e293b; margin-bottom: 8px;">
                    {v_idx}. {html.escape(current_vuln_name)} 패치 가이드
                </div>
                <div class="desc-box">
                    <b>대응 방안 요약:</b> {current_remediation if is_valid(current_remediation) else '해당 없음'}
                </div>
                {multi_lang_html}
            </div>
            """

        secure_coding_section = f"""
        <div class="section">
            <div class="section-title">3. 프레임워크별 시큐어코딩 및 패치 가이드</div>
            {multi_vuln_secure_html}
        </div>
        """

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
                    <tr>
                        <th>전체 취약점 건수</th>
                        <td>{vulnerability_count}</td>
                    </tr>
                </table>
                <div class="desc-box">
                    본 보고서는 마스킹 처리된 패킷 데이터를 기반으로 LLM이 진단한 결과 및 판정 근거를 포함합니다.[cite: 1]
                </div>
            </div>

            <div class="section">
                <div class="section-title">2. 진단 결과 요약 및 상세 분석</div>
                <table class="info-table">
                    {table_rows}
                </table>
            </div>

            {all_findings_section}
            {secure_coding_section}
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
        pdf_bytes = page.pdf(
            format="A4",
            print_background=True,
            margin={
                "top": "20px",
                "bottom": "20px",
                "left": "20px",
                "right": "20px"
            }
        )
        browser.close()
        
    return pdf_bytes ,llm_output_json 


def generate_vulnerability_report(masked_json_data: dict, output_dir: str = "./reports") -> str:
    try:
        os.makedirs(output_dir, exist_ok=True)
        cleanup_old_reports(output_dir, max_age_seconds=1800)
        
        unique_filename = f"report_{uuid.uuid4().hex[:8]}.pdf"
        output_path = os.path.join(output_dir, unique_filename)
        
        pdf_bytes, llm_output_json = generate_vulnerability_report_pdf_bytes(masked_json_data)
        
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)
            
        return output_path
    except Exception as e:
        print(f"[Error] 통합 보고서 파일 생성 실패: {str(e)}")
        raise e
