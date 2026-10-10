import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

print("Loading cleaned dataset...")
df = pd.read_csv("cleaned_dataset.csv")

# Selected features that are realistically extractable via Scapy live capture
selected_features = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Min Packet Length',
    'Max Packet Length',
    'Packet Length Mean',
    'Packet Length Std',
    'Packet Length Variance',
    'Average Packet Size',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
    'Down/Up Ratio',
]

X = df[selected_features]
y = df['Binary_Label']

print("Selected feature count:", len(selected_features))
print("Total samples:", X.shape[0])

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Training Random Forest with selected features...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced'
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model and feature list together
joblib.dump({'model': model, 'features': selected_features}, "selected_features_model.pkl")
print("\nModel saved as selected_features_model.pkl")
print("Features used:", selected_features)