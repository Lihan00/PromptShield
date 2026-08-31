📖 프로젝트 소개 (Overview)
PromptShield는 수집된 HTTP Request/Response 패킷 데이터 내 민감정보(인증 토큰, 개인정보, API 키 등)를 정규 표현식(Regex)으로 안전하게 비식별화(Masking) 처리한 뒤, 외부 LLM(OpenAI GPT API)을 통해 웹 취약점 진단 및 개발자 맞춤형 시큐어코딩 패치 가이드를 자동 생성하는 웹 서비스입니다.

💡 추진 배경 및 필요성 (Background)
외부 LLM 사용 시 민감정보 유출 위험

보안 진단을 위해 패킷 데이터를 외부 LLM API로 전송할 때, Bearer Token, Cookie, API Key, 개인정보(이메일, 주민등록번호 등)가 외부로 유출될 심각한 보안 리스크가 존재합니다.

개발자 친화적 조치 가이드 부재

기존의 취약점 스캐너는 단순히 위험 사실만 전달할 뿐, 개발자가 해당 프레임워크나 언어에 맞춰 즉시 적용할 수 있는 문맥 맞춤형 시큐어코딩 패치 코드(Secure Code Patch)를 제공하지 못합니다.

🎯 핵심 목표 (Key Objectives)
안전한 데이터 전송 (Privacy-First): 정규표현식 기반의 필터링 엔진을 통해 외부 API로 전달되는 모든 데이터의 프라이버시를 완벽히 보호합니다.

정밀 AI 문맥 분석: 단순 상태 코드 비교가 아닌 Request/Response의 전체 교신 문맥을 종합 추론하여 OWASP Top 10 기반 취약점을 분석합니다.

원스톱 리포팅 & 시큐어코딩: 진단 판단 근거 제시와 함께 개발자가 바로 사용할 수 있는 언어별 시큐어코딩 코드 및 PDF 보고서를 제공합니다.

🔄 시스템 파이프라인 (System Pipeline)[1단계: HTTP 패킷 입력]
       │ (.txt, .log 파일 업로드 및 직접 입력)
       ▼
[2단계: 민감정보 마스킹 Engine]
       │ (정규식 기반 JWT, Session, 개인정보, Key 치환 & Side-by-Side 비교)
       ▼
[3단계: OpenAI AI Inference Engine]
       │ (전문 모의해킹 관제사 페르소나 적용 & OWASP Top 10 분석)
       ▼
[4단계: 결과 리포팅 및 시큐어코딩]
       │ (대시보드 시각화, 취약/안전 코드 비교, PDF 보고서 다운로드)

✨ 상세 기능 (Detailed Features)
1단계: HTTP 요청 및 응답 패킷 입력 (Input Stage)
Streamlit 기반 UI: 사용자 친화적인 웹 인터페이스 제공

다양한 입력 지원: 텍스트 직접 입력 및 .txt, .log 파일 형태의 패킷 파일 업로드 지원

2단계: 정규 표현식 기반 민감정보 마스킹 (Data Anonymization)
외부 API로 유출되는 것을 차단하는 보안 레이어 적용

주요 마스킹 대상 패턴:

인증 토큰: JWT Token, Bearer Header ([REDACTED_JWT])

세션 & 쿠키: Set-Cookie, JSESSIONID, PHPSESSID 등 ([REDACTED_SESSION])

개인정보: 이메일 주소, 전화번호, 주민등록번호, IP 주소 ([REDACTED_PII])

API 키 & 비밀번호: OpenAI Key, AWS Access Key, password=... 파라미터 ([REDACTED_KEY])

원본 vs 마스킹 비교 UI: Side-by-Side 뷰로 비식별화 전/후 데이터를 시각적으로 대조하여 안전성 확보

3단계: OpenAI API 취약점 분석 (AI Inference Engine)
전문 모의해킹 관제사(Penetration Tester) 페르소나 프롬프트 적용

OWASP Top 10 중심 진단 항목:

Injection (SQL Injection, Command Injection 등)

Broken Access Control (인증/인가 우회, IDOR)

Server-Side Request Forgery (SSRF)

Security Misconfiguration (민감정보 노출, Path Traversal)

Cross-Site Scripting (XSS)

Unrestricted File Upload

구조화된 분석 결과 구조:

취약점 명칭 및 OWASP 카테고리

위험도 레벨 (Critical / High / Medium / Low / Info)

진단 결과 (Vulnerable / Safe / N/A)

상세 판단 근거 (Request 공격 핑거프린트 + Response 반응 문맥 통합 분석)

4단계: 진단 보고서 및 시큐어코딩 가이드 (Output & Remediation)
취약점 요약 대시보드: 위험도별 배지 및 진단 건수 시각화

맞춤형 시큐어코딩 패치 코드 (Secure Code Patch):

프레임워크/언어별(Node.js, Python/Flask, Java/Spring 등) 대응 조치 코드 자동 생성

취약한 코드 vs 수정된 안전 코드 비교 인터페이스 제공

보고서 내보내기: 진단 결과를 깔끔하게 스타일링된 PDF 보고서 형식으로 생성 및 다운로드

📂 프로젝트 구조 (Project Structure)
Plaintext  
PromptShield/  
├── app.py                   # Streamlit 메인 실행 파일 및 UI 엔트리포인트  
├── orchestrator.py          # 패킷 파싱 및 정규식 마스킹 처리 전처리 모듈  
├── main.py                  # OpenAI API 호출 및 Prompt Engineering / PDF 리포트 생성  
├── requirements.txt         # 프로젝트 의존성 라이브러리 목록  
├── .env                     # API 키 등 환경 변수 관리 파일  
└── README.md                # 프로젝트 안내 문서  