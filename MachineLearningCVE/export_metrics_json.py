import os, gc, json, joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (confusion_matrix, classification_report,
                             accuracy_score, precision_score, recall_score, f1_score)

df = pd.read_csv("cleaned_dataset.csv")
df.columns = df.columns.str.strip()
num_cols = df.select_dtypes("number").columns.difference(["Binary_Label"])
df[num_cols] = df[num_cols].astype("float32")      # half the memory
gc.collect()
print("Loaded", len(df), "rows")


def load(path):
    obj = joblib.load(path)
    if isinstance(obj, dict):
        model, feats = obj["model"], obj["features"]
    else:
        model, feats = obj, obj.feature_names_in_
    return model, [f.strip() for f in feats]


def clean(name):
    return str(name).replace("\ufffd", "-")


def run(path, key, title, desc, label_col, attacks_only=False):
    model, feats = load(path)
    d = df[df["Label"] != "BENIGN"] if attacks_only else df
    y = d[label_col].reset_index(drop=True)

    # same split as before, done on row positions only (cheap on memory)
    _, test_idx = train_test_split(np.arange(len(d)), test_size=0.2,
                                   stratify=y, random_state=42)
    Xt = d.iloc[test_idx][feats].replace([np.inf, -np.inf], np.nan).fillna(0)
    yt = y.iloc[test_idx]
    pred = model.predict(Xt)

    excluded = 0
    if attacks_only:  # score only the classes the model was trained on
        mask = yt.isin(list(model.classes_)).to_numpy()
        excluded = int((~mask).sum())
        yt, pred = yt[mask], pred[mask]

    classes = list(model.classes_)
    names = ["BENIGN", "ATTACK"] if label_col == "Binary_Label" else [clean(c) for c in classes]
    cm = confusion_matrix(yt, pred, labels=classes)
    rep = classification_report(yt, pred, labels=classes, target_names=names,
                                output_dict=True, zero_division=0)
    avg = "binary" if len(classes) == 2 else "weighted"
    print(key, "done")
    result = {
        "key": key, "title": title, "description": desc,
        "test_rows": int(len(yt)), "n_features": len(feats),
        "excluded_rows": excluded,
        "accuracy": float(accuracy_score(yt, pred)),
        "precision": float(precision_score(yt, pred, average=avg, zero_division=0)),
        "recall": float(recall_score(yt, pred, average=avg, zero_division=0)),
        "f1": float(f1_score(yt, pred, average=avg, zero_division=0)),
        "macro_f1": float(f1_score(yt, pred, average="macro", zero_division=0)),
        "classes": names,
        "confusion": cm.tolist(),
        "per_class": [{"name": n, "precision": float(rep[n]["precision"]),
                       "recall": float(rep[n]["recall"]), "f1": float(rep[n]["f1-score"]),
                       "support": int(rep[n]["support"])} for n in names],
    }
    del Xt, model
    gc.collect()
    return result


models = [
    run("random_forest_model.pkl", "binary78", "Binary Random Forest (78 features)",
        "Full-feature benchmark model: BENIGN vs ATTACK.", "Binary_Label"),
    run("selected_features_model.pkl", "binary23", "Live Binary Model (23 features)",
        "Deployed in the live sensor; uses only features extractable from live packets.", "Binary_Label"),
    run("multiclass_model.pkl", "multiclass", "Attack-Type Classifier (11 classes)",
        "Runs after an ATTACK is flagged and names the attack type.", "Label", attacks_only=True),
]

out = {"dataset": "CICIDS2017", "split": "80/20 stratified, random_state=42", "models": models}
target = os.path.join("..", "nids-platform", "frontend", "src")
os.makedirs(target, exist_ok=True)
path = os.path.join(target, "modelMetrics.json")
with open(path, "w") as f:
    json.dump(out, f, indent=1)
print("Saved:", os.path.abspath(path))