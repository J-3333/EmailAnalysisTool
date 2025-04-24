import pandas as pd
import numpy as np
from transformers import BertTokenizer, BertModel
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import torch

# Load dataset
print("Loading dataset...")
data = pd.read_csv('datasets_clean.csv')
data['sender_domain'] = data['sender_domain'].fillna("unknown")
data['subject'] = data['subject'].fillna("No Subject")
data['url'] = data['url'].fillna("no_url")
print("Missing values handled.")

# Load BERT tokenizer and model
print("Loading BERT model...")
tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
bert_model = BertModel.from_pretrained("bert-base-uncased")

# Function to get BERT embeddings (handles batch processing)
def get_bert_embeddings_batch(texts):
    inputs = tokenizer(texts, return_tensors="pt", truncation=True, padding=True, max_length=128)
    with torch.no_grad():
        outputs = bert_model(**inputs)
    return outputs.last_hidden_state.mean(dim=1).numpy()

# Compute and save embeddings for subjects
print("Computing and saving subject embeddings...")
subject_embeddings = []
batch_size = 32
for i in range(0, len(data), batch_size):
    batch = data['subject'][i:i+batch_size].tolist()
    subject_embeddings.append(get_bert_embeddings_batch(batch))
subject_embeddings = np.vstack(subject_embeddings)  
np.save("subject_embeddings.npy", subject_embeddings)  
print("Subject embeddings saved!")

# Compute and save embeddings for body
print("Computing and saving body embeddings...")
body_embeddings = []
for i in range(0, len(data), batch_size):
    batch = data['body'][i:i+batch_size].tolist()
    body_embeddings.append(get_bert_embeddings_batch(batch))
body_embeddings = np.vstack(body_embeddings)  
np.save("body_embeddings.npy", body_embeddings)  
print("Body embeddings saved!")

# Scale numerical features
print("Scaling numerical features...")
scaler = StandardScaler()
data['url_count_scaled'] = scaler.fit_transform(data[['url_count']])
print("Numerical features scaled.")

# Encode sender domain
print("Encoding categorical features...")
encoder = OneHotEncoder(handle_unknown='ignore')
sender_domains_encoded = encoder.fit_transform(data[['sender_domain']]).toarray()
print("Categorical features encoded.")

# Combine all features
print("Combining features into a single feature vector...")
feature_vectors = np.hstack([
    subject_embeddings,
    body_embeddings,
    data[['url_count_scaled']].values,
    sender_domains_encoded
])

# Labels
labels = data['label'].values

# Train-test split
print("Splitting dataset into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(feature_vectors, labels, test_size=0.2, random_state=42)

# Train Random Forest
print("Training Random Forest model...")
clf = RandomForestClassifier()
clf.fit(X_train, y_train)

# Evaluate
print("Evaluating model on test set...")
predictions = clf.predict(X_test)
print(classification_report(y_test, predictions))

# Save model and preprocessors
print("Saving model and preprocessors...")
joblib.dump(clf, "hybrid_model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(encoder, "encoder.pkl")
print("Model and preprocessors saved successfully!")
