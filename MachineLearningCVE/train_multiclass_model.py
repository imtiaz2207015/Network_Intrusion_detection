import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

print("Loading cleaned dataset...")
df = pd.read_csv("cleaned_dataset.csv")

# Keep only ATTACK rows
df_attacks = df[df['Binary_Label'] == 1].copy()

print("Attack label distribution before filtering:")
print(df_attacks['Label'].value_counts())

# Remove classes with too few samples (need at least ~50 for reliable train/test split)
label_counts = df_attacks['Label'].value_counts()
valid_labels = label_counts[label_counts >= 50].index
df_attacks = df_attacks[df_attacks['Label'].isin(valid_labels)]

print("\nAttack label distribution after filtering (min 50 samples):")
print(df_attacks['Label'].value_counts())

feature_cols = [c for c in df_attacks.columns if c not in ['Label', 'Binary_Label']]
X = df_attacks[feature_cols]
y = df_attacks['Label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("\nTrain size:", X_train.shape[0])
print("Test size:", X_test.shape[0])

print("Training Random Forest (multi-class)...")
model = RandomForestClassifier(
    n_estimators=150,
    max_depth=25,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced'
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

joblib.dump(model, "multiclass_model.pkl")
print("\nModel saved as multiclass_model.pkl")