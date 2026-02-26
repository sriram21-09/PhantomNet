from fastapi import APIRouter, HTTPException, status
from schemas.threat_schema import ThreatInput, ThreatResponse
from ml.threat_scoring_service import score_threat
import ml.model_loader as model_loader

router = APIRouter()

@router.post(
    "/api/v1/analyze/threat-score",
    response_model=ThreatResponse,
    summary="Analyze Threat Score",
    description="Analyzes network traffic features and returns a threat score (0-100) and classification.",
    tags=["Analysis"]
)
async def analyze_threat(input_data: ThreatInput):
    """
    Analyzes the provided network traffic metadata and returns a threat assessment.
    
    This endpoint:
    1. Validates the input schema (15 features context).
    2. Calculates derived features (rates, variances) in-memory.
    3. Runs the ML model prediction.
    4. Returns a normalized score, threat level, and decision.
    """
    
    # 0. Check if Model is Loaded
    # Although load_model() handles this with a print, we want to fail fast for API consumers
    if model_loader.get_model() is None:
         # Try to load it once
         model_loader.load_model()
         if model_loader.get_model() is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ML Model not available. Please ensure the model is trained and registered."
            )

    try:
        # 1. Score the Threat
        result = score_threat(input_data)
        
        # 2. Return Response
        return result
        
    except Exception as e:
        # Log the full error in a real app
        print(f"[API ERROR] Threat analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during analysis."
        )
