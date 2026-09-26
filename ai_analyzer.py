import os
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neural_network import MLPClassifier

MODEL_PATH = "dnn_model.pkl"
VECTORIZER_PATH = "dnn_vectorizer.pkl"

def train_dnn_model():
    """Initializes and trains a Deep Neural Network (MLP) with a baseline corpus if no model exists."""
    X_train = [
        "Urgent update required verify your bank account login credentials immediately",
        "Hey meeting schedule for tomorrow at 10 AM in the conference room",
        "Win a free iPhone click this malicious link to claim your prize now",
        "Project report attached for your review please check the figures",
        "Security alert your password has expired reset it through this link",
        "Team lunch on Friday afternoon hope you can make it"
    ]
    y_train = [1, 0, 1, 0, 1, 0] # 1: Phishing / Malicious, 0: Benign
    
    # Text Vectorization
    vectorizer = TfidfVectorizer(max_features=2000, ngram_range=(1, 2))
    X_vectors = vectorizer.fit_transform(X_train).toarray()
    
    # Deep Neural Network Architecture: 
    # Two hidden layers with 64 and 32 neurons respectively, using ReLU activation
    dnn_model = MLPClassifier(
        hidden_layer_sizes=(64, 32), 
        activation='relu', 
        solver='adam', 
        max_iter=500, 
        random_state=42
    )
    dnn_model.fit(X_vectors, y_train)
    
    # Persist the model and vectorizer locally
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(dnn_model, f)
    with open(VECTORIZER_PATH, "wb") as f:
        pickle.dump(vectorizer, f)
        
    return dnn_model, vectorizer

def load_dnn_model():
    """Loads the trained DNN model from disk, or triggers training if missing."""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        return train_dnn_model()
    
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    with open(VECTORIZER_PATH, "rb") as f:
        vectorizer = pickle.load(f)
    return model, vectorizer

def analyze_email_content(subject, body):
    """Feeds email subject and body through the Deep Neural Network to predict phishing probability."""
    try:
        model, vectorizer = load_dnn_model()
        text_content = f"{subject} {body}"
        
        if not text_content.strip():
            return {"percentage": "0.0%", "score_raw": 0.0, "architecture": "DNN (MLP)"}
            
        # Transform text features
        vectorized_text = vectorizer.transform([text_content]).toarray()
        
        # Predict probabilities from the neural network layers
        probabilities = model.predict_proba(vectorized_text)[0]
        phishing_prob = float(probabilities[1]) if len(probabilities) > 1 else float(model.predict(vectorized_text)[0])
        
        percentage_str = f"{phishing_prob * 100:.1f}%"
        
        return {
            "percentage": percentage_str,
            "score_raw": round(phishing_prob, 4),
            "architecture": "Deep Neural Network (64x32 MLP)"
        }
    except Exception as e:
        return {"error": str(e), "percentage": "0.0%", "score_raw": 0.0}