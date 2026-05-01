import joblib
import pandas as pd

# Load trained model
model = joblib.load("phishing_model.pkl")

def detect_phishing(features):

    # Convert input features to dataframe
    df = pd.DataFrame([features])

    # Prediction
    prediction = model.predict(df)[0]

    if prediction == 1:
        return "Phishing"
    else:
        return "Legitimate"