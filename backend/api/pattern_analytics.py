from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any
from sqlalchemy.orm import Session

# Local imports
from database.database import get_db
from ml_engine.pattern_detector import AdvancedPatternDetector

router = APIRouter(prefix="/api/v1/patterns", tags=["Advanced Patterns"])


@router.get("/advanced", response_model=Dict[str, Any])
async def get_advanced_patterns(db: Session = Depends(get_db)):
    """
    Analyzes historical packet logs to detect complex, multi-stage,
    or covert threats that evade standard threshold detection.
    """
    try:
        detector = AdvancedPatternDetector(db)
        results = detector.run_all_checks()
        return results
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Pattern detection error: {str(e)}"
        )
