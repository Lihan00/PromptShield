import streamlit as st
from dotenv import load_dotenv
import os
from main import generate_vulnerability_report
from preprocessing.orchestrator import process_packet


# 1. 마스킹 모듈 연동 (masker.py - 윤선우, 박건우)
try:
    from masker import mask_packet
except ImportError:
    def mask_packet(raw_text):
        """masker.py 모듈이 없을 때 동작하는 가상 함수"""
        return raw_text.replace("Bearer ", "Bearer [TOKEN_MASKED_")


## sample data
sample_json = {
        "id": "case_001",
        "source": "DVWA - SQL Injection",
        "request": {
            "method": "GET",
            "path": "/vulnerabilities/sqli/",
            "query_params": {"id": "1' OR '1'='1"}
        },
        "response": {
            "status_code": 200,
            "body_excerpt": "... You have an error in your SQL syntax near '1' ..."
        }
    }



# ---------------------------------------------------------
# Streamlit UI 메인 화면 구성
# ---------------------------------------------------------
st.set_page_config(page_title="PromptShield", page_icon="🛡️", layout="wide")

st.title("🛡️ PromptShield: 패킷 기반 AI 취약점 진단 시스템")
st.markdown("HTTP 요청/응답 패킷의 민감정보를 안전하게 마스킹한 후 AI 기반 취약점 진단 및 시큐어코딩 가이드를 제공합니다.")

# Session State 초기화 (페이지 리로드 시 데이터 유지)
if "raw_packet" not in st.session_state:
    st.session_state.raw_packet = ""
if "analysis_done" not in st.session_state:
    st.session_state.analysis_done = False
if "result_data" not in st.session_state:
    st.session_state.result_data = None

# --- [1단계] 패킷 입력 (버튼 누르기 전까지는 화면에 입력만 받아둠) ---
st.subheader("1. HTTP 패킷 입력 및 민감정보 마스킹")

input_option = st.radio("입력 방식 선택:", ["텍스트 직접 입력", "파일 업로드 (.txt, .log)"])

request_text, response_text = "", ""
request_files, response_files = None, None

if input_option == "텍스트 직접 입력":
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
else:
    request_files = st.file_uploader(
        "패킷 파일 선택 (요청 올려주세요)",
        type=["txt", "log"],
        accept_multiple_files=False,
    )
    response_files = st.file_uploader(
        "패킷 파일 선택 (응답 올려주세요)",
        type=["txt", "log"],
        accept_multiple_files=False,
    )

st.divider()

# --- 버튼은 입력 여부와 상관없이 항상 표시. 누르는 순간 나머지 파이프라인이 실행됨 ---
start_clicked = st.button("🚀 취약점 진단 및 시큐어코딩 분석 시작", type="primary")

if start_clicked:
    # 1) raw_packet 구성 -----------------------------------------------
    if input_option == "텍스트 직접 입력":
        if not request_text and not response_text:
            st.warning("요청 또는 응답 패킷을 하나 이상 입력해주세요.")
            st.stop()
        st.session_state.raw_packet = (
            f"=== REQUEST ===\n{request_text}\n\n=== RESPONSE ===\n{response_text}"
        )
    else:
        if not request_files and not response_files:
            st.warning("요청 또는 응답 패킷 파일을 하나 이상 업로드해주세요.")
            st.stop()
        try:
            request_packet = request_files.read().decode("utf-8") if request_files else ""
            response_packet = response_files.read().decode("utf-8") if response_files else ""
            st.session_state.raw_packet = (
                f"=== REQUEST ===\n{request_packet}\n\n=== RESPONSE ===\n{response_packet}"
            )
        except Exception as e:
            st.error(f"파일을 읽는 중 오류가 발생했습니다: {str(e)}")
            st.stop()

    # 2) 요청/응답 분리 + 마스킹 -----------------------------------------
    packet = st.session_state.raw_packet
    req_part, res_part = packet, ""
    if "=== REQUEST ===" in packet and "=== RESPONSE ===" in packet:
        try:
            _, rest = packet.split("=== REQUEST ===\n", 1)
            req_part, res_part = rest.split("\n\n=== RESPONSE ===\n", 1)
            result=process_packet(req_part,res_part)
            if not result["success"]:
                st.error("전처리 실패: " + ", ".join(result["errors"]))
                st.stop()
        except ValueError:
            req_part, res_part = packet, ""

    try:
        masked_req = result["masked_case"]
        masked_res = result["llm_payload"]
    except Exception as e:
        st.error(f"마스킹 처리 중 오류 발생: {str(e)}")
        masked_req, masked_res = req_part, res_part

    masked_packet = (
        f"=== REQUEST ===\n{masked_req}\n\n=== RESPONSE ===\n{masked_res}"
        if res_part else masked_req
    )

    st.markdown("#### 🔍 Side-by-Side 마스킹 검증")

    st.markdown("**요청(Request) 패킷**")
    req_col1, req_col2 = st.columns(2)
    with req_col1:
        st.caption("🔴 원본")
        st.code(req_part or "(입력된 요청 패킷 없음)", language="http")
    with req_col2:
        st.caption("🟢 마스킹 처리됨")
        st.code(masked_req or "(입력된 요청 패킷 없음)", language="http")

    st.markdown("**응답(Response) 패킷**")
    res_col1, res_col2 = st.columns(2)
    with res_col1:
        st.caption("🔴 원본")
        st.code(res_part or "(입력된 응답 패킷 없음)", language="http")
    with res_col2:
        st.caption("🟢 마스킹 처리됨")
        st.code(masked_res or "(입력된 응답 패킷 없음)", language="http")

    st.divider()


    # 취약점 진단 및 보고서 작성
    st.session_state.analysis_done = True
    if st.session_state.analysis_done:
        try:
            report_path,diagnosis = generate_vulnerability_report(result["llm_payload"])
            st.session_state.report_path = report_path
            st.session_state.diagnosis=diagnosis
            st.success("보고서 생성 완료!")

        except Exception as e:
            st.error(f"보고서 생성 실패: {e}")

if "diagnosis" in st.session_state:
    st.subheader("2. AI 취약점 진단 결과 대시보드")

    d = st.session_state.diagnosis
    badge = {"VULNERABLE": "🔴", "SAFE": "🟢", "N/A": "⚪"}.get(d["verdict"], "⚪")

    col1, col2, col3 = st.columns(3)
    col1.metric("판정", f"{badge} {d['verdict']}")
    col2.metric("위험도", d.get("severity") or "N/A")
    col3.metric("OWASP 카테고리", d.get("owasp_category") or "N/A")

    with st.expander(f"{d['vulnerability_name']} — 판단 근거", expanded=True):
        st.write("**근거:**", d.get("reason") or "없음")
        st.write("**요청 근거:**", " / ".join(d.get("evidence", {}).get("request", [])) or "없음")
        st.write("**응답 근거:**", " / ".join(d.get("evidence", {}).get("response", [])) or "없음")
        st.write("**대응 방안:**", d.get("remediation_summary") or "없음")

if "report_path" in st.session_state:
    with open(st.session_state.report_path, "r", encoding="utf-8") as f:
        html_content = f.read()
        st.components.v1.html(html_content, height=800, scrolling=True)  # 화면에 보고서 표시
        st.download_button("📄 보고서 다운로드", data=html_content,
        file_name="PromptShield_Report.html", mime="text/html")
