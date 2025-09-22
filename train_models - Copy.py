phishing_samples = [
    "http://login.mypaypal.com/login",
    "http://secure-bank.com/login",
    "http://example-phishingsite.com",
    "http://free-giftcard.com",
    "http://fake-update.microsoft.com",
    "http://web.whatsapp.com",
    "https://amaz0n-update.net/login",
    "http://paypal-secure.com/account",
    "http://lottery-win.com/prize",
    "https://secure-login-gmail.com",
    "http://update-your-email.com",
    "http://bankofamerica.com.phish",
    "https://secure-paypal-login.com",
    "http://verify-account-facebook.com",
    "https://secure-instagram-login.net",
    "http://fake-ebay-login.com",
    # add more URLs or email text samples as needed...
]

legitimate_samples = [
    "https://www.paypal.com",
    "https://www.amazon.com",
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.facebook.com",
    "https://www.twitter.com",
    "https://www.linkedin.com",
    "https://www.intuit.com",
    "https://www.ebay.com",
    "https://www.dropbox.com",
    "https://github.com",
    "https://www.netflix.com",
    "https://www.spotify.com",
    "https://www.whatsapp.com",
    # add more legitimate URLs or email texts...
]

training_samples = phishing_samples + legitimate_samples
labels = [1] * len(phishing_samples) + [0] * len(legitimate_samples)

# Proceed with vectorization and training:

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
import joblib

vectorizer = TfidfVectorizer()
clf = RandomForestClassifier(n_estimators=100, random_state=42)

pipeline = Pipeline([
    ('vectorizer', vectorizer),
    ('classifier', clf)
])

pipeline.fit(training_samples, labels)

joblib.dump(pipeline, "models/url_classifier.joblib")
print("Model trained and saved successfully.")
