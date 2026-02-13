import numpy as np
import pytest
from backend.ml.preprocessor import LogPreprocessor

def test_scaling_logic():
    """Test that the preprocessor actually changes the values."""
    processor = LogPreprocessor()
    
    # Create fake batch of data (2 vectors)
    # Just random numbers simulating [Hour, Day, Delta, IP, Port, ...]
    X_raw = np.array([
        [12.0, 4.0, 0.5, 3232235521.0, 22.0, 1.0, 5.0, 8.0, 3.5, 1.0, 2.0],
        [3.0,  6.0, 5000.0, 167772165.0, 3306.0, 0.0, 12.0, 15.0, 5.5, 0.0, 6.0]
    ])
    
    # Teach the processor
    processor.fit(X_raw)
    
    # Transform the same data
    X_scaled = processor.transform(X_raw)
    
    # Verify shape is preserved
    assert X_scaled.shape == X_raw.shape
    
    # Verify data is normalized (no huge numbers left)
    # The max value shouldn't be 3 billion anymore
    assert np.max(X_scaled) < 10.0 

def test_save_load(tmp_path):
    """Test saving to disk and loading back."""
    processor = LogPreprocessor()
    X_raw = np.zeros((5, 11))
    processor.fit(X_raw)
    
    # Save to temp file
    save_path = tmp_path / "test_model.pkl"
    processor.save(str(save_path))
    
    # Load back
    loaded = LogPreprocessor.load(str(save_path))
    assert loaded is not None
