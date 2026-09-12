import os
import asyncio

os.environ["SENTINEL_LLM_ENABLED"] = "true"
os.environ["SENTINEL_LLM_HOST"] = "http://localhost:11434"
os.environ["SENTINEL_LLM_MODEL"] = "mistral"
os.environ["DATABASE_URL"] = "sqlite:///./phantomnet.db"

from backend.sentinel.llm_service import LLMService
from backend.sentinel.mitre_mapper import get_all_mappings

def run():
    llm = LLMService()
    mappings = get_all_mappings()
    
    with open("prompts_out.md", "w", encoding="utf-8") as f:
        for sig_name, tech in mappings.items():
            f.write(f"==================================================\n")
            f.write(f"Evaluating: {sig_name}\n")
            context = {
                "attack_type": sig_name,
                "severity": tech.get("severity", "HIGH"),
                "src_ip": "10.10.10.10",
                "dst_port": 80,
                "protocol": "TCP",
                "technique_id": tech.get("technique_id"),
                "technique_name": tech.get("technique_name"),
                "tactic": tech.get("tactic"),
                "threat_score": 95,
                "event_count": 100,
                "campaign_id": f"CAMP-{sig_name}-001"
            }
            
            prompt = llm._build_context_prompt(context)
            f.write("--- PROMPT ---\n")
            f.write(prompt + "\n")
            f.write("--------------------------------------------------\n\n")

if __name__ == "__main__":
    run()
