import streamlit as st
import pandas as pd
import requests
import plotly.express as px
import time

# --- CONFIGURATION ---
API_URL = "http://phantomnet_api:8000"

st.set_page_config(
    page_title="PhantomNet Defense Platform",
    page_icon="???",
    layout="wide"
)

# --- HEADER ---
st.title("??? PhantomNet: Active Defense Dashboard")
st.markdown(f"**Status:** ?? Connected to Neural Core at {API_URL}")

# --- SIDEBAR ---
with st.sidebar:
    st.header("Control Panel")
    if st.button("?? Refresh Data"):
        st.rerun()
    
    auto_refresh = st.checkbox("Enable Auto-Refresh (5s)", value=True)

# --- FUNCTIONS ---
def fetch_logs():
    try:
        response = requests.get(f"{API_URL}/api/events?limit=200")
        if response.status_code == 200:
            data = response.json()
            if not data:
                return pd.DataFrame()
            
            df = pd.DataFrame(data)
            
            # --- CRITICAL FIX: Rename columns to match Dashboard expectations ---
            # API sends: time, ip, type, details
            # Dashboard wants: timestamp, source_ip, protocol, payload
            column_mapping = {
                'time': 'timestamp',
                'ip': 'source_ip',
                'type': 'protocol',
                'details': 'payload'
            }
            df = df.rename(columns=column_mapping)
            
            # Ensure 'honeypot' column exists (default to 'General' if missing)
            if 'honeypot' not in df.columns:
                df['honeypot'] = 'Network Sensor'
                
            # Ensure 'threat' column exists
            if 'threat' not in df.columns:
                df['threat'] = 'Scanning'

            return df
        else:
            st.error(f"Error fetching logs: {response.status_code}")
            return pd.DataFrame()
    except Exception as e:
        st.error(f"API Unreachable: {e}")
        return pd.DataFrame()

def fetch_stats():
    try:
        return requests.get(f"{API_URL}/api/stats").json()
    except:
        return {"total_events": 0, "threats_blocked": 0}

# --- MAIN DASHBOARD ---
# 1. Top Stats Row
stats = fetch_stats()
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Events", stats.get('total_events', 0))
c2.metric("Threats Detected", stats.get('threats_detected', 0), delta_color="inverse")
c3.metric("Active Honeypots", "4", "SSH, HTTP, FTP, SMTP")
c4.metric("AI Status", "Active", "Isolation Forest v1.0")

# 2. Main Data View
st.subheader("?? Live Threat Feed")
df = fetch_logs()

if not df.empty:
    # Ensure timestamp is datetime for proper sorting
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Create Tabs
    tab1, tab2 = st.tabs(["?? Live Logs", "?? Attack Map"])
    
    with tab1:
        # Define the exact columns we want to show
        display_cols = ['timestamp', 'honeypot', 'source_ip', 'payload', 'threat', 'protocol']
        
        # Filter to only existing columns to prevent KeyErrors
        available_cols = [c for c in display_cols if c in df.columns]
        
        def highlight_threat(row):
            color = '#ff4b4b' if row.get('threat') == 'ANOMALY' else ''
            return [f'background-color: {color}' for _ in row]

        st.dataframe(
            df[available_cols].style.apply(highlight_threat, axis=1),
            use_container_width=True,
            height=400
        )

    with tab2:
        if 'source_ip' in df.columns:
            ip_counts = df['source_ip'].value_counts().reset_index()
            ip_counts.columns = ['IP Address', 'Attack Count']
            
            fig = px.bar(ip_counts, x='IP Address', y='Attack Count', 
                         title="Top Attacking IPs", color='Attack Count',
                         color_continuous_scale='Reds')
            st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No traffic detected yet. Waiting for inputs...")

if auto_refresh:
    time.sleep(5)
    st.rerun()
