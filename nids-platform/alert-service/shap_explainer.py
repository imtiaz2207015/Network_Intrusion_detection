"""
Per-alert SHAP explanation helper for the NIDS 23-feature Random Forest model,
plus structured rule-trigger metadata for rule-based alerts.

TreeExplainer is built ONCE at service startup (init_explainer) and reused for
single-flow explanations during alert ingestion. Any failure is caught and
logged so alert persistence is never blocked.
"""
import json
import math
import os
import warnings

try:
    import numpy as np
except ImportError:
    np = None

try:
    import joblib
except ImportError:
    joblib = None

try:
    import shap
except ImportError:
    shap = None


_MODEL = None
_FEATURES = []
_CLASSES = []
_EXPLAINER = None
_MODEL_PATH = None

RULE_CATALOG = {
    "portscan": {
        "rule": "PortScan",
        "condition": ">= 10 distinct destination ports within 5s",
    },
    "dos/syn flood": {
        "rule": "DoS/SYN Flood",
        "condition": ">= 100 pure TCP SYN packets from one source within 5s",
    },
    "bruteforce": {
        "rule": "BruteForce",
        "condition": ">= 8 pure TCP SYN packets to a login service port (21, 22, 23, 3389, 9999) within 10s",
    },
    "udp flood": {
        "rule": "UDP Flood",
        "condition": ">= 100 unsolicited UDP packets from one source within 5s",
    },
    "icmp flood": {
        "rule": "ICMP Flood",
        "condition": ">= 100 ICMP packets from one source within 5s",
    },
}


def _log(logger, level, msg, *args):
    if logger is not None and hasattr(logger, level):
        getattr(logger, level)(msg, *args)


def is_ready():
    return _MODEL is not None and _EXPLAINER is not None and bool(_FEATURES)


def get_features():
    return list(_FEATURES)


def _is_normal_class(cls_val):
    if isinstance(cls_val, (int, float)) and not isinstance(cls_val, bool):
        return int(cls_val) == 0
    s = str(cls_val).strip().lower()
    return s in ("0", "benign", "normal")


def _class_label(cls_val):
    if isinstance(cls_val, (int, float)) and not isinstance(cls_val, bool):
        return "BENIGN" if int(cls_val) == 0 else "ATTACK"
    return str(cls_val)


def init_explainer(model_path=None, logger=None):
    """Loads the Random Forest model and builds shap.TreeExplainer once at startup."""
    global _MODEL, _FEATURES, _CLASSES, _EXPLAINER, _MODEL_PATH
    path = (model_path or os.environ.get("MODEL_PATH") or "/app/models/selected_features_model.pkl").strip()
    _MODEL_PATH = path

    if not path or not os.path.exists(path):
        _log(logger, "warning", "SHAP explainer disabled: model file not found at %s", path)
        return False
    if joblib is None or np is None or shap is None:
        _log(logger, "warning", "SHAP explainer disabled: missing shap/joblib/numpy dependency")
        return False

    try:
        saved = joblib.load(path)
        if isinstance(saved, dict) and "model" in saved and "features" in saved:
            model = saved["model"]
            features = list(saved["features"])
        else:
            model = saved
            features = list(getattr(model, "feature_names_in_", []))
        if not features:
            raise ValueError("Model bundle has no feature names")
        explainer = shap.TreeExplainer(model)
        classes = list(getattr(model, "classes_", [0, 1]))
        _MODEL = model
        _FEATURES = features
        _CLASSES = classes
        _EXPLAINER = explainer
        _log(
            logger,
            "warning",
            "SHAP TreeExplainer initialized once at startup: %s (%d features, classes=%s)",
            type(model).__name__,
            len(features),
            classes,
        )
        return True
    except Exception as e:
        _MODEL = None
        _FEATURES = []
        _CLASSES = []
        _EXPLAINER = None
        _log(logger, "error", "Failed to initialize SHAP TreeExplainer: %s", e)
        return False


def _extract_class_shap(raw_shap, class_idx, n_features, n_classes):
    """
    Normalizes shap.TreeExplainer.shap_values(X) output for a single sample (row 0)
    across SHAP versions:
      - list of 2D arrays: [array(1, F), ...] indexed by class_idx (older SHAP)
      - 3D ndarray: shape (1, F, C) indexed by [0, :, class_idx] (newer SHAP)
      - 2D ndarray: shape (1, F) (single-output / binary positive class)
      - 1D ndarray: shape (F,)
    """
    if isinstance(raw_shap, list):
        if not raw_shap:
            raise ValueError("Empty SHAP list")
        idx = class_idx if 0 <= class_idx < len(raw_shap) else len(raw_shap) - 1
        arr = np.asarray(raw_shap[idx], dtype=float)
        vec = arr[0] if arr.ndim >= 2 else arr
        if vec.shape[0] != n_features:
            raise ValueError(f"Unexpected SHAP vector shape {vec.shape}, expected ({n_features},)")
        return vec

    arr = np.asarray(raw_shap, dtype=float)
    if arr.ndim == 3:
        # Newer SHAP returns (n_samples, n_features, n_classes)
        if arr.shape[1] == n_features and arr.shape[2] == n_classes:
            return arr[0, :, class_idx]
        # Fallback if shape is (n_classes, n_samples, n_features)
        if arr.shape[0] == n_classes and arr.shape[2] == n_features:
            return arr[class_idx, 0, :]
        raise ValueError(f"Unexpected 3D SHAP shape {arr.shape}")

    if arr.ndim == 2:
        if arr.shape[0] == 1 and arr.shape[1] == n_features:
            vec = arr[0]
            # Binary 2D output typically represents the positive class (index 1)
            return -vec if (n_classes == 2 and class_idx == 0) else vec
        if arr.shape[0] == n_features and arr.shape[1] == n_classes:
            return arr[:, class_idx]
        raise ValueError(f"Unexpected 2D SHAP shape {arr.shape}")

    if arr.ndim == 1 and arr.shape[0] == n_features:
        return -arr if (n_classes == 2 and class_idx == 0) else arr

    raise ValueError(f"Unsupported SHAP output shape {arr.shape}")


def _safe_float(v):
    try:
        f = float(v)
        if math.isnan(f) or math.isinf(f):
            return 0.0
        return f
    except (TypeError, ValueError):
        return 0.0


def explain_ml_flow(features_dict, predicted_class=None, top_k=5, logger=None):
    """
    Computes SHAP values for a single flow feature dict and returns the top-k
    features by absolute contribution. Returns None on any error.
    """
    if not is_ready() or not isinstance(features_dict, dict):
        return None
    try:
        vals = [_safe_float(features_dict.get(f, 0.0)) for f in _FEATURES]
        X = np.array([vals], dtype=float)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if predicted_class is None:
                pred = _MODEL.predict(X)[0]
            else:
                pred = predicted_class

            # Resolve class index inside model.classes_
            class_idx = None
            for i, c in enumerate(_CLASSES):
                if c == pred or str(c) == str(pred):
                    class_idx = i
                    pred = c
                    break
            if class_idx is None:
                pred = _MODEL.predict(X)[0]
                class_idx = list(_CLASSES).index(pred) if pred in _CLASSES else (len(_CLASSES) - 1)

            try:
                raw_shap = _EXPLAINER.shap_values(X, check_additivity=False)
            except TypeError:
                raw_shap = _EXPLAINER.shap_values(X)

        vec = _extract_class_shap(raw_shap, class_idx, len(_FEATURES), len(_CLASSES))
        pred_is_normal = _is_normal_class(pred)

        ranked = sorted(
            range(len(_FEATURES)),
            key=lambda i: abs(float(vec[i])),
            reverse=True,
        )[: max(1, int(top_k))]

        top_features = []
        for idx in ranked:
            sval = float(vec[idx])
            # Positive SHAP pushes toward the explained predicted class.
            pushes_attack = (sval < 0) if pred_is_normal else (sval >= 0)
            top_features.append(
                {
                    "feature": _FEATURES[idx],
                    "value": round(vals[idx], 4),
                    "shap": round(sval, 6),
                    "direction": "toward attack" if pushes_attack else "toward normal",
                }
            )

        pred_json = int(pred) if isinstance(pred, (int, np.integer)) else str(pred)
        return {
            "method": "shap",
            "predicted_class": pred_json,
            "predicted_label": _class_label(pred_json),
            "top_features": top_features,
        }
    except Exception as e:
        _log(logger, "error", "SHAP explanation failed: %s", e)
        return None


def build_rule_explanation(atype, detail="", rule_payload=None):
    """
    Builds structured rule-trigger explanation for rule-based alerts.
    Never fakes SHAP values.
    """
    atype_clean = str(atype or "").strip()[:60]
    detail_clean = str(detail or "").strip()[:300]

    if isinstance(rule_payload, dict):
        name = str(rule_payload.get("name") or rule_payload.get("rule") or atype_clean).strip()[:60]
        condition = str(rule_payload.get("condition") or "").strip()[:200]
        observed = str(rule_payload.get("observed") or detail_clean).strip()[:200]
        if name and condition:
            return {
                "method": "rule",
                "rule": name,
                "condition": condition,
                "observed": observed or detail_clean or "-",
            }

    key = atype_clean.lower()
    known = RULE_CATALOG.get(key)
    if known:
        return {
            "method": "rule",
            "rule": known["rule"],
            "condition": known["condition"],
            "observed": detail_clean or "-",
        }

    return {
        "method": "rule",
        "rule": atype_clean or "Rule",
        "condition": "Rule-based detector threshold triggered",
        "observed": detail_clean or "-",
    }


def sample_attack_flow():
    """Returns a realistic synthetic SYN-flood / high-rate attack flow (23 features) for quick testing."""
    return {
        "Destination Port": 80,
        "Flow Duration": 50000.0,
        "Total Fwd Packets": 250,
        "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 15000,
        "Total Length of Bwd Packets": 0,
        "Fwd Packet Length Max": 60,
        "Fwd Packet Length Min": 60,
        "Fwd Packet Length Mean": 60.0,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0.0,
        "Flow Bytes/s": 300000.0,
        "Flow Packets/s": 5000.0,
        "Min Packet Length": 60,
        "Max Packet Length": 60,
        "Packet Length Mean": 60.0,
        "Packet Length Std": 0.0,
        "Packet Length Variance": 0.0,
        "Average Packet Size": 60.0,
        "Init_Win_bytes_forward": 1024,
        "Init_Win_bytes_backward": 0,
        "Down/Up Ratio": 0.0,
    }


if __name__ == "__main__":
    ok = init_explainer()
    if not ok:
        print("Explainer could not be initialized. Check MODEL_PATH:", _MODEL_PATH)
        raise SystemExit(1)
    result = explain_ml_flow(sample_attack_flow())
    print(json.dumps(result, indent=2))
