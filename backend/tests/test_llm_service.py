import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from sqlalchemy.orm import Session
from sentinel.llm_service import (
    build_prompt,
    generate_fallback_narrative,
    generate_playbook_summary,
)

# Mock playbook structure
class MockPlaybook:
    def __init__(self):
        self.id = 1
        self.playbook_name = "SSH Brute Force Mitigations"
        self.attack_type = "Brute Force"
        self.technique_id = "T1021.004"
        self.technique_name = "SSH"
        self.tactic = "Lateral Movement"
        self.severity = "high"
        self.threat_score = 85
        self.src_ip = "192.168.1.100"
        self.dst_port = 22
        self.protocol = "TCP"
        self.llm_narrative = None
        self.updated_at = None

def test_build_prompt():
    playbook = MockPlaybook()
    prompt = build_prompt(playbook)
    assert "SSH Brute Force Mitigations" in prompt
    assert "T1021.004" in prompt

def test_generate_fallback_narrative():
    playbook = MockPlaybook()
    narrative = generate_fallback_narrative(playbook)
    assert "### AI-Powered Playbook Narrative (Local Fallback)" in narrative
    assert "192.168.1.100" in narrative
    assert "85%" in narrative

@pytest.mark.anyio
@patch("sentinel.llm_service.httpx.AsyncClient")
async def test_generate_playbook_summary_success(mock_client_cls):
    # Mock database session
    mock_db = MagicMock(spec=Session)
    playbook = MockPlaybook()
    
    mock_query = mock_db.query.return_value
    mock_filter = mock_query.filter.return_value
    mock_filter.first.return_value = playbook
    
    # Mock httpx AsyncClient
    mock_client = AsyncMock()
    mock_client_cls.return_value.__aenter__.return_value = mock_client
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": "Custom LLM Summary Text"}
    mock_client.post.return_value = mock_response
    
    result = await generate_playbook_summary(1, mock_db)
    
    assert result == "Custom LLM Summary Text"
    assert playbook.llm_narrative == "Custom LLM Summary Text"
    mock_db.commit.assert_called_once()

@pytest.mark.anyio
@patch("sentinel.llm_service.httpx.AsyncClient")
async def test_generate_playbook_summary_fallback_on_error(mock_client_cls):
    # Mock database session
    mock_db = MagicMock(spec=Session)
    playbook = MockPlaybook()
    
    mock_query = mock_db.query.return_value
    mock_filter = mock_query.filter.return_value
    mock_filter.first.return_value = playbook
    
    # Mock httpx AsyncClient throwing exception
    mock_client = AsyncMock()
    mock_client_cls.return_value.__aenter__.return_value = mock_client
    mock_client.post.side_effect = Exception("Ollama offline")
    
    result = await generate_playbook_summary(1, mock_db)
    
    assert "### AI-Powered Playbook Narrative (Local Fallback)" in result
    assert playbook.llm_narrative == result
    mock_db.commit.assert_called_once()
