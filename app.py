import streamlit as st
import pandas as pd
import json
import os

st.set_page_config(page_title="EMBER2024 Malware Scanner", page_icon="🛡️", layout="wide")

st.title("🛡️ EMBER2024 PE File Scanner")
st.markdown("Upload a PE file (`.exe`, `.dll`, etc.) to get an ML-based maliciousness score using the EMBER2024 model. Files with a high score will optionally be checked against VirusTotal.")

# Initialize Scanner
@st.cache_resource
def load_scanner():
    # Ensure model directory exists
    os.makedirs('models', exist_ok=True)
    # Autodownload just the PE model to avoid downloading everything
    if not os.path.exists('models/EMBER2024_PE.model'):
        st.info("Downloading EMBER2024 PE Model (This only happens once)...")
        import urllib.request
        url = "https://huggingface.co/FutureComputing4AI/EMBER2024/resolve/main/models/EMBER2024_PE.model?download=true"
        urllib.request.urlretrieve(url, "models/EMBER2024_PE.model")
    
    from scanner import Scanner
    return Scanner()

scanner = load_scanner()

with st.sidebar:
    st.header("Settings")
    vt_api_key = st.text_input("VirusTotal API Key (Optional)", type="password", help="Enter your VT API key to enable reputation checking for suspicious files.")
    threshold = st.slider("ML Suspicion Threshold", min_value=0.0, max_value=1.0, value=0.7, step=0.05, help="If the ML score exceeds this threshold, the file will be checked against VirusTotal.")
    
uploaded_file = st.file_uploader("Choose a PE file", type=['exe', 'dll', 'sys'])

if uploaded_file is not None:
    file_bytes = uploaded_file.read()
    file_name = uploaded_file.name
    
    st.markdown("---")
    st.subheader(f"Results for `{file_name}`")
    
    with st.spinner("Calculating file hashes..."):
        hashes = scanner.get_hashes(file_bytes)
        md5, sha1, sha256 = hashes
        
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**File Hashes:**")
        st.code(f"MD5: {md5}\nSHA1: {sha1}\nSHA256: {sha256}")
        
    with st.spinner("Extracting features and running ML model..."):
        try:
            score = scanner.predict(file_bytes)
            
            with col2:
                st.markdown("**EMBER2024 ML Score:**")
                
                score_percentage = score * 100
                
                # Visual indicator for score
                if score >= threshold:
                    st.error(f"### {score_percentage:.2f}% (Malicious)")
                    st.progress(float(score))
                elif score >= (threshold / 2):
                    st.warning(f"### {score_percentage:.2f}% (Suspicious)")
                    st.progress(float(score))
                else:
                    st.success(f"### {score_percentage:.2f}% (Benign)")
                    st.progress(float(score))
            
            vt_stats = None
            
            st.markdown("---")
            st.subheader("🌐 Reputation Layer (VirusTotal)")
            st.markdown("Check this file against VirusTotal's database. This is recommended if the ML score is suspicious.")
            
            vt_state_key = f"vt_stats_{sha256}"
            if vt_state_key not in st.session_state:
                st.session_state[vt_state_key] = None

            if st.button("Query VirusTotal API", type="primary", help="Query VirusTotal for this file's hash"):
                if vt_api_key:
                    with st.spinner("Checking VirusTotal..."):
                        st.session_state[vt_state_key] = scanner.check_virustotal(sha256, vt_api_key)
                else:
                    st.warning("⚠️ Please enter a VirusTotal API Key in the settings sidebar first.")
            
            vt_data = st.session_state[vt_state_key]
            
            if vt_data is not None:
                if "error" in vt_data:
                    st.error(f"VirusTotal Error: {vt_data['error']}")
                elif "message" in vt_data:
                    st.info(f"VirusTotal: {vt_data['message']}")
                else:
                    # Display VT stats
                    st.markdown("#### Detection Stats")
                    vt_stats = vt_data.get("stats", {})
                    stats_df = pd.DataFrame([vt_stats]).T
                    stats_df.columns = ["Count"]
                    st.table(stats_df)
                    
                    malicious_count = vt_stats.get("malicious", 0)
                    if malicious_count > 0:
                        st.error(f"🚨 **Action:** Block Indicator. File is confirmed malicious by {malicious_count} engines.")
                        st.success(f"✅ Extracted {len(vt_data.get('iocs', {}).get('network_iocs', []))} additional network IOCs from VirusTotal.")
                    else:
                        st.warning("⚠️ **Action:** Alert. File is suspicious to ML but unknown/benign to VirusTotal (possible zero-day or false positive).")
                    
            st.markdown("---")
            st.subheader("📄 Output Layer (OpenIOC)")
            
            vt_state_key = f"vt_stats_{sha256}"
            vt_stats = st.session_state.get(vt_state_key, None)
            
            if st.button("Generate OpenIOC Report"):
                with st.spinner("Generating OpenIOC..."):
                    ioc_path = scanner.generate_ioc(file_name, hashes, vt_stats)
                    with open(ioc_path, "rb") as f:
                        ioc_data = f.read()
                    
                    st.download_button(
                        label="Download OpenIOC XML File",
                        data=ioc_data,
                        file_name=os.path.basename(ioc_path),
                        mime="application/xml"
                    )
                    st.success(f"Successfully generated IOC report!")
                    
        except Exception as e:
            st.error(f"Error analyzing file: {str(e)}")
