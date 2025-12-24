import streamlit as st
import requests
import pandas as pd
import plotly.express as px

# --- CONFIGURATION ---
# Connects to your new AI endpoint
API_URL = "http://127.0.0.1:8000/analyze-traffic"

st.set_page_config(page_title="PhantomNet AI Dashboard", layout="wide", page_icon="👻")

# --- HEADER ---
st.title("👻 PhantomNet: AI Threat Detection")
st.markdown("Real-time network traffic analysis using Random Forest ML.")

# --- SIDEBAR ---
st.sidebar.header("Control Panel")
if st.sidebar.button("🔄 Refresh Traffic"):
    st.rerun()

# --- MAIN LOGIC ---
try:
    response = requests.get(API_URL)
    
    if response.status_code == 200:
        data = response.json()['data']
        
        # Flatten the data for the table
        flat_data = []
        for item in data:
            ai = item['ai_analysis']
            packet = item['packet_info']
            
            row = {
                "Source IP": packet['src'],
                "Dest IP": packet['dst'],
                "Protocol": packet['proto'],
                "Duration": f"{item['packet_info']['end'][-2:]}s", # Showing seconds
                "Prediction": ai['prediction'],
                "Threat Score": ai['threat_score'], # 0.0 - 1.0
                "Confidence": ai['confidence_percent']
            }
            flat_data.append(row)
            
        df = pd.DataFrame(flat_data)

        # --- METRICS ROW ---
        col1, col2, col3, col4 = st.columns(4)
        total_packets = len(df)
        malicious = len(df[df['Prediction'] == 'MALICIOUS'])
        
        col1.metric("📦 Total Packets", total_packets)
        col2.metric("🚨 Threats Detected", malicious, delta=malicious, delta_color="inverse")
        col3.metric("🛡️ Benign Traffic", total_packets - malicious)
        col4.metric("🧠 AI Model Status", "Active")

        # --- VISUALIZATIONS ---
        st.subheader("📊 Live Threat Analysis")
        
        c1, c2 = st.columns(2)
        with c1:
            # Red for Malicious, Green for Benign
            fig_bar = px.bar(df, x='Prediction', color='Prediction', 
                             color_discrete_map={'MALICIOUS': 'red', 'BENIGN': 'green'},
                             title="Threat Distribution")
            st.plotly_chart(fig_bar, use_container_width=True)
            
        with c2:
            fig_hist = px.histogram(df, x="Threat Score", nbins=10, title="Threat Score Confidence")
            st.plotly_chart(fig_hist, use_container_width=True)

        # --- DETAILED LOGS ---
        st.subheader("📝 Traffic Logs with Threat Scores")
        
        # Highlight malicious rows in Red
        def highlight_threat(row):
            if row['Prediction'] == 'MALICIOUS':
                return ['background-color: #ffcccc'] * len(row)
            return [''] * len(row)

        st.dataframe(df.style.apply(highlight_threat, axis=1), use_container_width=True)
        
    else:
        st.error(f"Error: API returned status {response.status_code}")

except requests.exceptions.ConnectionError:
    st.error("🔴 Connection Failed: Is the Backend running?")
    st.info("Run: uvicorn main:app --reload")