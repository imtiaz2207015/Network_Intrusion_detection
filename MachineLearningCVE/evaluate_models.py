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
print("Rows:", len(df))


def plot_cm(cm, classes, title, path):
    size = 6 if len(classes) <= 2 else 11
    fig, ax = plt.subplots(figsize=(size, size * 0.85))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(classes))); ax.set_yticks(range(len(classes)))
    ax.set_xticklabels(classes, rotation=60, ha="right", fontsize=7)
    ax.set_yticklabels(classes, fontsize=7)
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=6,
                    color="white" if cm[i, j] > cm.max() / 2 else "black")
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(title)
    plt.tight_layout(); plt.savefig(path, dpi=150); plt.close()


def evaluate(model_file, name, label_col, attacks_only=False):
    obj = joblib.load(model_file)
    if isinstance(obj, dict):
        print("Dict keys in", model_file, ":", list(obj.keys()))
        model = next(v for v in obj.values() if hasattr(v, "predict"))
        feats = next(v for v in obj.values() if isinstance(v, (list, tuple)))
    else:
        model = obj
        feats = model.feature_names_in_
    feats = [f.strip() for f in feats]
    d = df[df["Label"] != "BENIGN"] if attacks_only else df
    X = d[feats].replace([np.inf, -np.inf], np.nan).fillna(0)
    y = d[label_col]
    if hasattr(model, "classes_"):
        print("Model classes:", list(model.classes_))

    _, Xt, _, yt = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    pred = model.predict(Xt)

    # if multiclass model was trained on encoded numbers, decode them (alphabetical guess)
    if not pd.api.types.is_numeric_dtype(yt) and pd.api.types.is_numeric_dtype(pd.Series(pred)):
        names = sorted(df[label_col].unique())
        pred = np.array(names)[pred.astype(int)]
        print("WARNING: decoded numeric predictions using alphabetical class order")

    classes = sorted(pd.unique(yt))
    cm = confusion_matrix(yt, pred, labels=classes)
    plot_cm(cm, [str(c) for c in classes], f"{name} - confusion matrix", f"{OUT}/{name}_cm.png")

    print(f"\n===== {name} =====")
    print(classification_report(yt, pred, digits=4, zero_division=0))

    avg = "binary" if len(classes) == 2 else "weighted"
    return {
        "model": name,
        "test_rows": len(yt),
        "accuracy": accuracy_score(yt, pred),
        "precision": precision_score(yt, pred, average=avg, zero_division=0),
        "recall": recall_score(yt, pred, average=avg, zero_division=0),
        "f1": f1_score(yt, pred, average=avg, zero_division=0),
    }


rows = []
for f, n in [("random_forest_model.pkl", "binary_78_features"),
             ("selected_features_model.pkl", "binary_23_live")]:
    if os.path.exists(f):
        rows.append(evaluate(f, n, "Binary_Label"))

if os.path.exists("multiclass_model.pkl"):
    rows.append(evaluate("multiclass_model.pkl", "multiclass", "Label", attacks_only=True))

summary = pd.DataFrame(rows).round(4)
summary.to_csv(f"{OUT}/metrics_summary.csv", index=False)
print("\n", summary.to_string(index=False))
print(f"\nSaved to ./{OUT}/")