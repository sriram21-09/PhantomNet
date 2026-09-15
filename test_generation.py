import os

os.environ["SENTINEL_LLM_ENABLED"] = "true"
os.environ["SENTINEL_LLM_HOST"] = "http://localhost:11434"
os.environ["SENTINEL_LLM_MODEL"] = "mistral"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"

from backend.sentinel.llm_service import LLMService

def test():
    llm = LLMService()
    context = {
        "attack_type": "SSH_AUTH_FAILURE",
        "severity": "HIGH",
        "src_ip": "10.10.10.10",
        "dst_port": 22,
        "protocol": "TCP",
        "technique_id": "T1110.001",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "threat_score": 95,
        "event_count": 100,
        "campaign_id": "CAMP-001"
    }
    narrative = llm.generate_narrative(context)
    print("NARRATIVE OUTPUT:")
    print(narrative)
    if "Local Fallback" in narrative:
        print("SUCCESS: Fallback narrative generated!")
    else:
        print("FAILED: No fallback found")

if __name__ == "__main__":
    test()
