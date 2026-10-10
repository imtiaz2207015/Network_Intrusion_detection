import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
import joblib

print("Loading cleaned dataset...")
df = pd.read_csv("cleaned_dataset.csv")

# Drop non-numeric / label columns from features
feature_cols = [c for c in df.columns if c not in ['Label', 'Binary_Label']]
X = df[feature_cols]
y = df['Binary_Label']

print("Feature count:", len(feature_cols))
print("Total samples:", X.shape[0])

# Split into train/test (stratify to keep class ratio)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Train size:", X_train.shape[0])
print("Test size:", X_test.shape[0])

# Train Isolation Forest ONLY on benign data (unsupervised anomaly detection)
X_train_benign = X_train[y_train == 0]
print("Training Isolation Forest on benign-only data:", X_train_benign.shape[0], "samples")

model = IsolationForest(
    n_estimators=100,
    contamination=0.197,   # rough estimate, will tune later
    random_state=42,
    n_jobs=-1
)
model.fit(X_train_benign)

# Predict on test set: IsolationForest gives 1 (normal) / -1 (anomaly)
raw_preds = model.predict(X_test)
# Convert to our label format: 0 = benign, 1 = attack
y_pred = np.where(raw_preds == -1, 1, 0)

print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model
joblib.dump(model, "isolation_forest_model.pkl")
print("\nModel saved as isolation_forest_model.pkl")