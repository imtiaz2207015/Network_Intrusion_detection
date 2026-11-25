import numpy as np
import pytest

KEY = {"X-Service-Key": "test-sensor-key"}


def hdr(make_token, role="admin"):
    return {"Authorization": f"Bearer {make_token(role)}"}


class FakeRF:
    def __init__(self, classes=(0, 1), pred=1):
        self.classes_ = np.array(classes)
        self._pred = pred

    def predict(self, X):
        return np.array([self._pred])


class FakeExplainer:
    def __init__(self, raw_shap, fail=False):
        self._raw = raw_shap
        self._fail = fail

    def shap_values(self, X, check_additivity=False):
        if self._fail:
            raise RuntimeError("boom in SHAP")
        return self._raw


def _configure_fake_shap(alert_mod, monkeypatch, features, classes, pred, raw_shap, fail=False):
    se = alert_mod.shap_explainer
    monkeypatch.setattr(se, "_MODEL", FakeRF(classes=classes, pred=pred))
    monkeypatch.setattr(se, "_FEATURES", list(features))
    monkeypatch.setattr(se, "_CLASSES", list(classes))
    monkeypatch.setattr(se, "_EXPLAINER", FakeExplainer(raw_shap, fail=fail))
    return se


def test_extract_class_shap_handles_list_3d_and_2d_shapes(alert_mod):
    se = alert_mod.shap_explainer

    # 1. Older SHAP: list of (1, F) arrays (3-class multi-class)
    raw_list = [
        np.array([[0.1, -0.2, 0.3, 0.0]]),
        np.array([[-0.5, 0.8, 0.1, -0.2]]),
        np.array([[0.9, 0.1, -0.4, 0.2]]),
    ]
    vec = se._extract_class_shap(raw_list, class_idx=2, n_features=4, n_classes=3)
    assert np.allclose(vec, [0.9, 0.1, -0.4, 0.2])

    # 2. Newer SHAP: 3D ndarray (1, F, C)
    raw_3d = np.zeros((1, 4, 3))
    raw_3d[0, :, 1] = [-0.5, 0.8, 0.1, -0.2]
    vec3d = se._extract_class_shap(raw_3d, class_idx=1, n_features=4, n_classes=3)
    assert np.allclose(vec3d, [-0.5, 0.8, 0.1, -0.2])

    # 3. 2D ndarray (1, F) for binary model
    raw_2d = np.array([[0.4, -0.3, 0.2, 0.1]])
    assert np.allclose(se._extract_class_shap(raw_2d, class_idx=1, n_features=4, n_classes=2), [0.4, -0.3, 0.2, 0.1])
    assert np.allclose(se._extract_class_shap(raw_2d, class_idx=0, n_features=4, n_classes=2), [-0.4, 0.3, -0.2, -0.1])


def test_explain_ml_flow_returns_top_5_sorted_with_directions(alert_mod, monkeypatch):
    feats = ["f0", "f1", "f2", "f3", "f4", "f5", "f6"]
    # 3D SHAP array (1, 7, 2) for binary model predicting class 1 (ATTACK)
    raw_3d = np.zeros((1, 7, 2))
    raw_3d[0, :, 1] = [0.05, -0.40, 0.80, -0.10, 0.25, -0.01, 0.60]
    se = _configure_fake_shap(alert_mod, monkeypatch, feats, [0, 1], pred=1, raw_shap=raw_3d)

    out = se.explain_ml_flow({f: i * 10.0 for i, f in enumerate(feats)}, predicted_class=1)
    assert out["method"] == "shap"
    assert out["predicted_class"] == 1
    assert out["predicted_label"] == "ATTACK"
    top = out["top_features"]
    assert len(top) == 5
    assert [t["feature"] for t in top] == ["f2", "f6", "f1", "f4", "f3"]
    assert top[0] == {"feature": "f2", "value": 20.0, "shap": 0.8, "direction": "toward attack"}
    assert top[2] == {"feature": "f1", "value": 10.0, "shap": -0.4, "direction": "toward normal"}


def test_ingest_ml_alert_stores_shap_json(alerts, alert_client, make_token, monkeypatch):
    feats = ["Destination Port", "Flow Duration", "Flow Packets/s", "Total Fwd Packets", "Average Packet Size", "Down/Up Ratio"]
    raw_list = [
        np.array([[-0.2, -0.1, -0.7, -0.4, -0.3, -0.05]]),
        np.array([[0.2, 0.1, 0.7, 0.4, -0.3, 0.05]]),
    ]
    _configure_fake_shap(alerts, monkeypatch, feats, [0, 1], pred=1, raw_shap=raw_list)

    r = alert_client.post(
        "/ingest",
        headers=KEY,
        json={
            "type": "ML-Detected",
            "src": "10.0.0.99",
            "dst": "10.0.0.5",
            "dport": "80",
            "detail": "pkts=50, confidence=96%",
            "source": "ml",
            "predicted_class": 1,
            "features": {
                "Destination Port": 80,
                "Flow Duration": 40000,
                "Flow Packets/s": 12500.0,
                "Total Fwd Packets": 50,
                "Average Packet Size": 60.0,
                "Down/Up Ratio": 0.0,
            },
        },
    )
    assert r.status_code == 201
    aid = r.get_json()["id"]

    saved = alert_client.get(f"/{aid}", headers=hdr(make_token)).get_json()
    exp = saved["explanation"]
    assert exp is not None
    assert exp["method"] == "shap"
    assert exp["predicted_class"] == 1
    assert len(exp["top_features"]) == 5
    assert exp["top_features"][0]["feature"] == "Flow Packets/s"
    assert exp["top_features"][0]["direction"] == "toward attack"
    assert saved["ingested_at"] is not None


def test_ingest_rule_alert_never_fakes_shap(alerts, alert_client, make_token):
    # With explicit rule metadata from updated sensor
    r1 = alert_client.post(
        "/ingest",
        headers=KEY,
        json={
            "type": "PortScan",
            "src": "10.0.0.50",
            "dst": "-",
            "dport": "-",
            "detail": "14 ports in 5s",
            "source": "rule",
            "rule": {
                "name": "PortScan",
                "condition": ">= 10 distinct destination ports within 5s",
                "observed": "14 ports in 5s",
            },
        },
    )
    assert r1.status_code == 201
    a1 = alert_client.get(f"/{r1.get_json()['id']}", headers=hdr(make_token)).get_json()
    assert a1["explanation"] == {
        "method": "rule",
        "rule": "PortScan",
        "condition": ">= 10 distinct destination ports within 5s",
        "observed": "14 ports in 5s",
    }

    # Backward-compatible legacy rule alert (no source / no rule metadata)
    r2 = alert_client.post(
        "/ingest",
        headers=KEY,
        json={"type": "BruteForce", "src": "10.0.0.51", "dst": "10.0.0.5", "dport": "22", "detail": "9 SYNs in 10s"},
    )
    assert r2.status_code == 201
    a2 = alert_client.get(f"/{r2.get_json()['id']}", headers=hdr(make_token)).get_json()
    assert a2["explanation"]["method"] == "rule"
    assert a2["explanation"]["rule"] == "BruteForce"
    assert "8" in a2["explanation"]["condition"]


def test_ingest_saves_alert_when_shap_fails_or_features_missing(alerts, alert_client, make_token, monkeypatch):
    feats = ["Destination Port", "Flow Duration"]
    _configure_fake_shap(alerts, monkeypatch, feats, [0, 1], pred=1, raw_shap=None, fail=True)

    # 1. SHAP raises exception -> alert MUST still be saved with explanation=None
    r1 = alert_client.post(
        "/ingest",
        headers=KEY,
        json={
            "type": "ML-Detected",
            "src": "10.0.0.77",
            "dst": "10.0.0.5",
            "dport": "443",
            "source": "ml",
            "features": {"Destination Port": 443, "Flow Duration": 1000},
        },
    )
    assert r1.status_code == 201
    a1 = alert_client.get(f"/{r1.get_json()['id']}", headers=hdr(make_token)).get_json()
    assert a1["explanation"] is None

    # 2. Legacy ML-Detected payload without features -> saved with explanation=None (no fake SHAP)
    r2 = alert_client.post(
        "/ingest",
        headers=KEY,
        json={"type": "ML-Detected", "src": "10.0.0.78", "dst": "10.0.0.5", "dport": "80"},
    )
    assert r2.status_code == 201
    a2 = alert_client.get(f"/{r2.get_json()['id']}", headers=hdr(make_token)).get_json()
    assert a2["explanation"] is None
