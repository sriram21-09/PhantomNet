import os
import pandas as pd
from sqlalchemy import create_engine
from database.models import PacketLog
from dotenv import load_dotenv

# 1. SETUP
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phantomnet.db")
engine = create_engine(DATABASE_URL)

print("🧠 STARTING ML READINESS AUDIT...\n")

def generate_report():
    # Load data into Pandas for analysis
    try:
        df = pd.read_sql("SELECT * FROM packet_logs", engine)
    except Exception as e:
        print(f"❌ CRITICAL: Could not load data. {e}")
        return

    print(f"   📊 Total Dataset Size: {len(df)} rows")

    # ==========================================
    # TASK 1 & 2: Analytics & Distributions
    # ==========================================
    print("\n[PART 1] Data Distributions")
    
    # Class Balance (Malicious vs Normal)
    if 'is_malicious' in df.columns:
        counts = df['is_malicious'].value_counts()
        print("   • Class Balance:")
        print(counts.to_string())
        
        if len(counts) < 2:
            print("     ⚠️ WARNING: Dataset is skewed (Only one class present). AI cannot learn.")
        else:
            print("     ✅ Dataset contains both Normal and Malicious examples.")
    
    # Attack Types
    if 'attack_type' in df.columns:
        print("\n   • Attack Type Distribution:")
        print(df['attack_type'].value_counts().head(5).to_string())

    # ==========================================
    # TASK 3: Current ML Architecture
    # ==========================================
    print("\n[PART 2] ML Architecture Status")
    print("   • Model: Random Forest Classifier (Scikit-Learn)")
    print("   • Features Used: [Source Port, Destination Port, Protocol ID, Packet Length]")
    print("   • Current State: Transient (Trains on startup, not saved to disk)")
    print("   • Assumptions: High packet frequency from single IP = Attack.")

    # ==========================================
    # TASK 4: Dataset Readiness Confirmation
    # ==========================================
    print("\n[PART 3] Readiness Verdict")
    if len(df) > 100:
        print("   ✅ STATUS: READY FOR MONTH 2")
        print("      (Sufficient data points for initial training/testing)")
    else:
        print("   ❌ STATUS: NOT READY")
        print("      (Need more data. Run Sniffer for 10+ minutes)")

    # ==========================================
    # TASK 5: Month 2 ML Task List
    # ==========================================
    month_2_tasks = """
    Month 2 ML Objectives:
    1. [ ] Model Persistence: Save trained model to .pkl file (Pickle).
    2. [ ] Feature Engineering: Add 'Time Between Packets' and 'Byte Frequency'.
    3. [ ] Evaluation: Implement Confusion Matrix & F1-Score metrics.
    4. [ ] Retraining Pipeline: API endpoint to trigger re-training on new DB data.
    """
    print("\n[PART 4] Month 2 Plan")
    print(month_2_tasks)

if __name__ == "__main__":
    generate_report()
