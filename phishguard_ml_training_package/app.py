from flask import Flask, request, jsonify
import joblib

app = Flask(__name__)

model = joblib.load("phishguard_model.joblib")

def extract_features(url):
    length = len(url)
    dots = url.count(".")
    https = 1 if url.startswith("https") else 0
    special = sum(c in "@-_=%" for c in url)
    
    return [[length, dots, https, special]]

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    url = data["url"]
    
    features = extract_features(url)
    
    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0][1]
    
    return jsonify({
        "prediction": int(prediction),
        "probability": float(probability)
    })

app.run()