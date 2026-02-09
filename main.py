import sys
import os

# Ensure backend modules can be imported
sys.path.append(os.path.join(os.path.dirname(__file__), "backend"))

from backend.main import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
