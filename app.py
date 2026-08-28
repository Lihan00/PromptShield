import streamlit as st
import os
import json
import base64
from main import generate_vulnerability_report_pdf_bytes
from orchestrator import process_packet

def na(value, default="해당 없음"):
    """null/빈 값이면 기본 문구로, 값이 있으면 그대로 반환"""
    if value in (None, "", [], {}):
        return default
    return value


# Streamlit UI 메인 화면 구성
st.set_page_config(page_title="PromptShield", page_icon="🛡️", layout="wide")

st.title("🛡️ PromptShield: 패킷 기반 AI 취약점 진단 시스템")
st.markdown("HTTP 요청/응답 패킷의 민감정보를 안전하게 마스킹한 후 AI 기반 취약점 진단 및 시큐어코딩 가이드를 제공합니다.")
# Session State 초기화
if "raw_packet" not in st.session_state:
    st.session_state.raw_packet = ""

# --- [1단계] 패킷 입력 ---
st.subheader("1. HTTP 패킷 입력 및 민감정보 마스킹")
st.write("※ Header 부분은 줄바꿈 해주세요")

req_col, res_col = st.columns(2)
with req_col:
    request_text = st.text_area(
        "HTTP 요청(Request) 패킷",
        height=250,
        placeholder="GET /api/user?id=1 HTTP/1.1\nHost: example.com\nAuthorization: Bearer secret_token...",
    )
with res_col:
    response_text = st.text_area(
        "HTTP 응답(Response) 패킷",
        height=250,
        placeholder="HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\": 1, \"name\": \"...\"}",
    )

st.divider()

# --- 진단 버튼 및 파이프라인 실행 ---
start_clicked = st.button("🚀 취약점 진단 및 시큐어코딩 분석 시작", type="primary")

if start_clicked:
    # 1) raw_packet 구성
    if not request_text and not response_text:
        st.warning("요청 또는 응답 패킷을 하나 이상 입력해주세요.")
        st.stop()
    st.session_state.raw_packet = (
        f"=== REQUEST ===\n{request_text}\n\n=== RESPONSE ===\n{response_text}"
    )

    # 2) 요청/응답 분리 + 마스킹
    packet = st.session_state.raw_packet
    req_part, res_part = packet, ""
    result = None

    if "=== REQUEST ===" in packet and "=== RESPONSE ===" in packet:
        try:
            _, rest = packet.split("=== REQUEST ===\n", 1)
            req_part, res_part = rest.split("\n\n=== RESPONSE ===\n", 1)
            result = process_packet(
    req_part, res_part,
    not request_text,
    not response_text,
)
            if not result["success"]:
                st.error("전처리 실패: " + ", ".join(result["errors"]))
                st.stop()
        except ValueError:
            req_part, res_part = packet, ""

    if not result:
        st.error("패킷 전처리에 실패했습니다.")
        st.stop()

    try:
        masked_req = result["masked_case"].get("request", {})
        masked_res = result["masked_case"].get("response", {})
    except Exception as e:
        st.error(f"마스킹 처리 중 오류 발생: {str(e)}")
        st.stop()

    st.markdown("#### 🔍 Side-by-Side 마스킹 검증")

    st.markdown("**요청(Request) 패킷**")
    req_col1, req_col2 = st.columns(2)
    with req_col1:
        st.caption("🔴 원본")
        st.code(req_part or "(입력된 요청 패킷 없음)", language="http", height=300)
    with req_col2:
        st.caption("🟢 마스킹 처리목록")
        st.code(json.dumps(masked_req, indent=2, ensure_ascii=False), language="json", height=300)

    st.markdown("**응답(Response) 패킷**")
    res_col1, res_col2 = st.columns(2)
    with res_col1:
        st.caption("🔴 원본")
        st.code(res_part or "(입력된 응답 패킷 없음)", language="http", height=300)
    with res_col2:
        st.caption("🟢 마스킹 처리목록")
        st.code(json.dumps(masked_res, indent=2, ensure_ascii=False), language="json", height=300)

    st.divider()

    # 3) 취약점 진단 + PDF 생성 
    with st.spinner("AI가 패킷을 분석하고 PDF 보고서를 생성 중입니다..."):
        try:
            pdf_bytes, diagnosis = generate_vulnerability_report_pdf_bytes(result["llm_payload"])
            st.session_state.diagnosis = diagnosis
            st.session_state.pdf_bytes = pdf_bytes
            st.success("보고서 생성 완료!")
        except Exception as e:
            st.error(f"보고서 생성 실패: {e}")

# 대시보드 출력 
if "diagnosis" in st.session_state:
    st.subheader("2. AI 취약점 진단 결과 대시보드")

    d = st.session_state.diagnosis
    verdict = d.get("verdict", "N/A")
    severity = na(d.get("severity"), "N/A")
    vuln_name = d.get("vulnerability_name", "알 수 없음")

    # 상단 판정 배너
    verdict_config = {
        "VULNERABLE": {"icon": "🔴", "label": "취약 발견", "fn": st.error},
        "SAFE":       {"icon": "🟢", "label": "양호",     "fn": st.success},
        "N/A":        {"icon": "⚪", "label": "판단 불가", "fn": st.warning},
    }
    cfg = verdict_config.get(verdict, verdict_config["N/A"])
    cfg["fn"](f"### {cfg['icon']} {cfg['label']} — {vuln_name}")

    # 핵심 지표 3개 
    severity_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
        "LOW": "#2563eb", "INFO": "#64748b", "N/A": "#94a3b8"
    }
    sev_color = severity_colors.get(severity, "#94a3b8")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**위험도**")
        st.markdown(
            f"<span style='background-color:{sev_color};color:white;padding:5px 12px;"
            f"border-radius:6px;font-weight:bold;font-size:15px;'>{severity}</span>",
            unsafe_allow_html=True
        )
    col2.metric("OWASP 카테고리", na(d.get("owasp_category"), "N/A"))
    col3.metric("판정", f"{cfg['icon']} {verdict}")

    st.divider()

    # 판단 근거 상세
    st.markdown("#### 📋 판단 근거 상세")
    detail_col1, detail_col2 = st.columns(2)
    with detail_col1:
        st.markdown("**🔎 요청(Request) 근거**")
        st.info(na(" / ".join(d.get("evidence", {}).get("request", []))))
        st.markdown("**🔎 응답(Response) 근거**")
        st.info(na(" / ".join(d.get("evidence", {}).get("response", []))))
    with detail_col2:
        st.markdown("**⚠️ 보안 영향**")
        st.warning(na(d.get("impact")))
        st.markdown("**🛠️ 대응 방안**")
        st.success(na(d.get("remediation_summary")))

    if verdict == "N/A":
        st.markdown("**❓ 추가 확인사항**")
        st.info(na(d.get("additional_check")))

    with st.expander("📝 전체 판단 근거 요약 보기"):
        st.write(na(d.get("reason")))

# PDF 다운로드 
if "pdf_bytes" in st.session_state:


    st.download_button(
        label="📄 PDF 보고서 다운로드",
        data=st.session_state.pdf_bytes,
        file_name="PromptShield_Report.pdf",
        mime="application/pdf"
    )