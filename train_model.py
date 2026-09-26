import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
import joblib

def train_and_save_model():
    # Expanded dataset with much clearer distinctions between Safe and Phishing
    data = {
        "text": [
            # Clean / Safe Emails (Label 0)
            "Project Update: The new server is up and running. Access the dashboard here.",
            "Meeting at 3 PM: Please bring the quarterly reports to the conference room.",
            "Lunch today? Let me know if you want to grab sandwiches at noon.",
            "Following up on our conversation yesterday regarding the Q3 marketing budget.",
            "Here are the meeting notes from this morning's sync. Let me know if I missed anything.",
            "Approved: Your PTO request for next Friday has been approved.",
            "Happy birthday! Wishing you a great day from the whole team.",
            "Can you review the attached draft before we send it to the client?",
            "Weekly Newsletter: Top 10 industry trends to watch this month.",
            "Just checking in to see if you need any help with the onboarding process.",
            
            # Phishing / Malicious Emails (Label 1)
            "URGENT: Your account has been suspended. Click here to verify your password immediately!",
            "Invoice Overdue: Please open the attached document to pay your outstanding balance.",
            "Security Alert: Unauthorized login attempt detected. Secure your account now via this link.",
            "Action Required: Update your billing credentials immediately to prevent service interruption.",
            "Final Warning: Your mailbox is full. Click here to upgrade your quota or lose access.",
            "Verify your bank account immediately. Unusual activity detected.",
            "You have a secure document waiting. Sign in with your email password to view it.",
            "Your package could not be delivered. Click the tracking link to reschedule and pay the fee.",
            "IT Helpdesk: We are migrating servers. Enter your credentials in the portal to migrate your data.",
            "Winner! You have been selected for a $500 gift card. Claim your prize now."
        ],
        "label": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    }
    
    df = pd.DataFrame(data)
    
    # C=10 reduces regularization, forcing the model to make more extreme/confident predictions (closer to 0% or 100%)
    model_pipeline = make_pipeline(
        TfidfVectorizer(stop_words='english', ngram_range=(1, 2)),
        LogisticRegression(C=10, class_weight='balanced')
    )
    
    print("Training the upgraded AI model...")
    model_pipeline.fit(df['text'], df['label'])
    
    joblib.dump(model_pipeline, 'phishing_model.pkl')
    print("Model successfully saved as 'phishing_model.pkl'")

if __name__ == "__main__":
    train_and_save_model()