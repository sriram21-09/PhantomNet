from database import SessionLocal
from app_models import PacketLog

db = SessionLocal()

print("📧 Testing SMTP Data Insertion...")

try:
    # Create a fake Phishing Log
    phishing_log = PacketLog(
        src_ip="10.0.0.5",           # Attacker
        dst_ip="10.0.0.1",           # Server
        protocol="SMTP",
        length=512,
        is_malicious=True,
        attack_type="PHISHING_ATTEMPT",
        
        # New Fields
        mail_from="attacker@evil-corp.com",
        rcpt_to="ceo@victim-company.com",
        email_subject="URGENT: Password Reset Required",
        body_len=1024
    )

    db.add(phishing_log)
    db.commit()
    print("   ✅ SUCCESS: Inserted SMTP log with email details.")

    # Verify we can read it back
    saved_log = db.query(PacketLog).filter_by(mail_from="attacker@evil-corp.com").first()
    if saved_log:
        print(f"   🔎 Verification: Found email subject '{saved_log.email_subject}'")
    else:
        print("   ❌ ERROR: Could not find the log we just saved.")

except Exception as e:
    print(f"   ❌ FAILED: {e}")
    db.rollback()
finally:
    db.close()
