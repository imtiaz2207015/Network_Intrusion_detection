import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

print("Loading cleaned dataset...")
df = pd.read_csv("cleaned_dataset.csv")

feature_cols = [c for c in df.columns if c not in ['Label', 'Binary_Label']]
X = df[feature_cols]
y = df['Binary_Label']

print("Feature count:", len(feature_cols))
print("Total samples:", X.shape[0])

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Train size:", X_train.shape[0])
print("Test size:", X_test.shape[0])

print("Training Random Forest...")
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

# Feature importance - top 10
importances = pd.Series(model.feature_importances_, index=feature_cols)
print("\nTop 10 Important Features:")
print(importances.sort_values(ascending=False).head(10))

joblib.dump(model, "random_forest_model.pkl")
print("\nModel saved as random_forest_model.pkl")