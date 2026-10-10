import os, joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import (confusion_matrix, classification_report,
                             accuracy_score, precision_score, recall_score, f1_score)

DATA = "cleaned_dataset.csv"
OUT = "metrics_out"
os.makedirs(OUT, exist_ok=True)

df = pd.read_csv(DATA)
df.columns = df.columns.str.strip()
print("Columns (last 5):", list(df.columns[-5:]))

# Find the label column
LABEL = next((c for c in ["Label", "label", "Attack", "binary_label"] if c in df.columns), df.columns[-1])
print("Using label column:", LABEL)


def plot_cm(cm, classes, title, path):
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(classes))); ax.set_yticks(range(len(classes)))
    ax.set_xticklabels(classes, rotation=45, ha="right"); ax.set_yticklabels(classes)
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=8)
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(title)
    plt.tight_layout(); plt.savefig(path, dpi=150); plt.close()


def evaluate(model_file, name):
    model = joblib.load(model_file)
    feats = [f.strip() for f in model.feature_names_in_]
    X = df[feats].replace([np.inf, -np.inf], np.nan).fillna(0)

    y = df[LABEL]
    # Binary models: map text labels to 0/1 if needed
    if y.dtype == object and y.nunique() > 2 and name != "multiclass":
        y = (y.str.upper() != "BENIGN").astype(int)
    elif y.dtype == object and name != "multiclass":
        y = (y.str.upper() != "BENIGN").astype(int)

    _, Xt, _, yt = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    pred = model.predict(Xt)

    classes = sorted(pd.unique(yt))
    cm = confusion_matrix(yt, pred, labels=classes)
    plot_cm(cm, [str(c) for c in classes], f"{name} - confusion matrix", f"{OUT}/{name}_cm.png")

    print(f"\n===== {name} =====")
    print(classification_report(yt, pred, digits=4))

    avg = "binary" if len(classes) == 2 else "weighted"
    return {
        "model": name,
        "accuracy": accuracy_score(yt, pred),
        "precision": precision_score(yt, pred, average=avg, zero_division=0),
        "recall": recall_score(yt, pred, average=avg, zero_division=0),
        "f1": f1_score(yt, pred, average=avg, zero_division=0),
    }


rows = []
for f, n in [("random_forest_model.pkl", "binary_78_features"),
             ("selected_features_model.pkl", "binary_23_live")]:
    if os.path.exists(f):
        rows.append(evaluate(f, n))

# Multiclass only works if the label column holds attack names
if os.path.exists("multiclass_model.pkl") and df[LABEL].dtype == object and df[LABEL].nunique() > 2:
    rows.append(evaluate("multiclass_model.pkl", "multiclass"))

summary = pd.DataFrame(rows).round(4)
summary.to_csv(f"{OUT}/metrics_summary.csv", index=False)
print("\n", summary.to_string(index=False))
print(f"\nSaved to ./{OUT}/")