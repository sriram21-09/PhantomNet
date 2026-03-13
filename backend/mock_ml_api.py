from flask import Flask, jsonify
from flask_cors import CORS
import random
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

@app.route('/api/v1/ml/stats', methods=['GET'])
def get_stats():
    # Return randomized realistic metrics
    return jsonify({
        "version": "v3.0.0",
        "name": "AttackClassifier_Enhanced",
        "metrics": {
            "accuracy": round(random.uniform(0.92, 0.96), 3),
            "f1_score": round(random.uniform(0.91, 0.95), 3),
            "precision": round(random.uniform(0.90, 0.94), 3),
            "recall": round(random.uniform(0.92, 0.96), 3),
            "auc": round(random.uniform(0.96, 0.99), 3)
        },
        "last_updated": datetime.now().isoformat()
    })

@app.route('/api/v1/ml/feature-importance', methods=['GET'])
def get_feature_importance():
    features = [
        "Packet Size Variance", "Connection Duration", 
        "Payload Entropy", "Source Port Frequency", 
        "TCP Flags Count", "HTTP Method Ratio",
        "Inter-arrival Time", "DNS Query Density"
    ]
    # Randomize importance scores
    data = []
    base = 0.9
    for f in features:
        data.append({"name": f, "importance": round(base, 2)})
        base -= random.uniform(0.05, 0.15)
        if base < 0.1: base = 0.1
        
    return jsonify({"features": data})

@app.route('/api/v1/ml/predictions/recent', methods=['GET'])
def get_recent_predictions():
    times = ["10:00", "11:00", "12:00", "13:00", "14:00", "15:00", "16:00"]
    data = []
    for t in times:
        data.append({
            "time": t,
            "benign": random.randint(200, 500),
            "malicious": random.randint(50, 400)
        })
    return jsonify({"data": data})

@app.route('/api/v1/ml/confidence-histogram', methods=['GET'])
def get_confidence_histogram():
    buckets = [
        {"range": "0.0-0.2", "count": random.randint(20, 60)},
        {"range": "0.2-0.4", "count": random.randint(50, 100)},
        {"range": "0.4-0.6", "count": random.randint(120, 200)},
        {"range": "0.6-0.8", "count": random.randint(400, 600)},
        {"range": "0.8-1.0", "count": random.randint(1000, 1500)}
    ]
    return jsonify({"buckets": buckets})

if __name__ == '__main__':
    print("Starting Mock ML API Server on http://localhost:5001")
    app.run(port=5001, debug=True)
