#!/usr/bin/env python3
"""
CPU Guardian — ML Anomaly Detection Engine

Receives telemetry samples from the C collector over a Unix domain socket,
builds a feature-engineered representation, trains an Isolation Forest +
One-Class SVM ensemble, and outputs JSON alerts.

Usage:
    python3 guardian_ml.py [--socket /tmp/cpu-guardian.sock]
                           [--learning-samples 5000]
                           [--retrain-interval 300]
                           [--log-file guardian_ml.log]
                           [--verbose]
"""

import argparse
import collections
import json
import os
import signal
import socket
import struct
import sys
import time
import threading
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler


WIRE_FMT = "<QQQQQQQfff"
WIRE_SIZE = struct.calcsize(WIRE_FMT)

FIELD_NAMES = [
    "timestamp_ns",
    "cache_references",
    "cache_misses",
    "branch_instructions",
    "branch_misses",
    "cycles",
    "instructions",
    "cache_miss_rate",
    "branch_miss_rate",
    "ipc",
]



ROLLING_WINDOW = 32

FEATURE_NAMES = [
    "cmr", "bmr", "ipc",
    "cmr_rmean", "bmr_rmean", "ipc_rmean",
    "cmr_rstd", "bmr_rstd", "ipc_rstd",
    "cmr_delta", "bmr_delta", "ipc_delta",
    "cmr_x_ipc", "bmr_x_ipc",
]


class FeatureExtractor:
    """Maintains a rolling window and produces 14-dim feature vectors."""

    def __init__(self, window: int = ROLLING_WINDOW):
        self.window = window
        self.buf_cmr = collections.deque(maxlen=window)
        self.buf_bmr = collections.deque(maxlen=window)
        self.buf_ipc = collections.deque(maxlen=window)
        self.prev_cmr = None
        self.prev_bmr = None
        self.prev_ipc = None

    def push(self, cmr: float, bmr: float, ipc: float) -> np.ndarray:
        self.buf_cmr.append(cmr)
        self.buf_bmr.append(bmr)
        self.buf_ipc.append(ipc)

        cmr_arr = np.array(self.buf_cmr)
        bmr_arr = np.array(self.buf_bmr)
        ipc_arr = np.array(self.buf_ipc)

        cmr_rmean = cmr_arr.mean()
        bmr_rmean = bmr_arr.mean()
        ipc_rmean = ipc_arr.mean()

        cmr_rstd = cmr_arr.std() if len(cmr_arr) > 1 else 0.0
        bmr_rstd = bmr_arr.std() if len(bmr_arr) > 1 else 0.0
        ipc_rstd = ipc_arr.std() if len(ipc_arr) > 1 else 0.0

        cmr_delta = cmr - self.prev_cmr if self.prev_cmr is not None else 0.0
        bmr_delta = bmr - self.prev_bmr if self.prev_bmr is not None else 0.0
        ipc_delta = ipc - self.prev_ipc if self.prev_ipc is not None else 0.0

        self.prev_cmr = cmr
        self.prev_bmr = bmr
        self.prev_ipc = ipc

        cmr_x_ipc = cmr * ipc
        bmr_x_ipc = bmr * ipc

        return np.array([
            cmr, bmr, ipc,
            cmr_rmean, bmr_rmean, ipc_rmean,
            cmr_rstd, bmr_rstd, ipc_rstd,
            cmr_delta, bmr_delta, ipc_delta,
            cmr_x_ipc, bmr_x_ipc,
        ], dtype=np.float64)



class EnsembleDetector:
    """Isolation Forest + One-Class SVM ensemble with periodic retraining."""

    def __init__(self, retrain_interval: float = 300.0, retrain_buffer_size: int = 10000):
        self.if_model = None
        self.svm_model = None
        self.scaler = StandardScaler()
        self.trained = False

        self.retrain_interval = retrain_interval
        self.retrain_buffer_size = retrain_buffer_size
        self.retrain_buf = collections.deque(maxlen=retrain_buffer_size)
        self.last_train_time = 0.0
        self._lock = threading.Lock()

    def train(self, X: np.ndarray):
        """Train both models on the provided feature matrix."""
        if len(X) < 50:
            log_warn(f"training skipped: only {len(X)} samples (need >= 50)")
            return

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        diversity_ok = self._check_diversity(X, X_scaled)

        if_model = IsolationForest(
            n_estimators=200,
            contamination=0.01,
            random_state=42,
            n_jobs=-1,
        )
        if_model.fit(X_scaled)

        svm_model = OneClassSVM(
            kernel="rbf",
            gamma="scale",
            nu=0.01,
        )
        svm_model.fit(X_scaled)

        with self._lock:
            self.scaler = scaler
            self.if_model = if_model
            self.svm_model = svm_model
            self.trained = True
            self.last_train_time = time.monotonic()

        n_features = X.shape[1]
        importances = if_model.feature_importances_ if hasattr(if_model, "feature_importances_") else None
        log_info(f"models trained on {len(X)} samples, {n_features} features, diversity={'OK' if diversity_ok else 'LOW'}")
        if importances is not None:
            top_idx = np.argsort(importances)[::-1][:5]
            top_str = ", ".join(f"{FEATURE_NAMES[i]}={importances[i]:.3f}" for i in top_idx if i < len(FEATURE_NAMES))
            log_info(f"top features: {top_str}")

    def predict(self, x: np.ndarray):
        """
        Returns (level, composite_score, if_raw, svm_raw).
        level: "NORMAL", "WARNING", or "CRITICAL"
        """
        with self._lock:
            if not self.trained:
                return "NORMAL", 0.0, 0.0, 0.0
            scaler = self.scaler
            if_model = self.if_model
            svm_model = self.svm_model

        x_scaled = scaler.transform(x.reshape(1, -1))

        if_pred = if_model.predict(x_scaled)[0]       # 1=normal, -1=anomaly
        svm_pred = svm_model.predict(x_scaled)[0]     # 1=normal, -1=anomaly

        if_raw = if_model.decision_function(x_scaled)[0]
        svm_raw = svm_model.decision_function(x_scaled)[0]

        if_score = self._normalize_score(if_raw)
        svm_score = self._normalize_score(svm_raw)
        composite = 0.6 * if_score + 0.4 * svm_score

        if if_pred == -1 and svm_pred == -1:
            level = "CRITICAL"
        elif if_pred == -1 or svm_pred == -1:
            level = "WARNING"
        else:
            level = "NORMAL"

        return level, float(composite), float(if_raw), float(svm_raw)

    def maybe_retrain(self):
        """Retrain if enough time has passed and buffer is large enough."""
        if not self.trained:
            return
        elapsed = time.monotonic() - self.last_train_time
        if elapsed < self.retrain_interval:
            return
        buf_snapshot = list(self.retrain_buf)
        if len(buf_snapshot) < 200:
            return
        X = np.array(buf_snapshot)
        log_info(f"periodic retraining on {len(X)} recent normal samples...")
        self.train(X)
        self.retrain_buf.clear()

    def add_normal_sample(self, x: np.ndarray):
        """Buffer a sample that was classified as normal for future retraining."""
        self.retrain_buf.append(x.copy())

    @staticmethod
    def _normalize_score(raw: float) -> float:
        """Map decision_function output to [0, 1] where 1 = most anomalous."""
        return 1.0 / (1.0 + np.exp(raw))

    @staticmethod
    def _check_diversity(X: np.ndarray, X_scaled: np.ndarray) -> bool:
        """Warn if training data lacks variance in any feature."""
        stds = X.std(axis=0)
        low_var_count = np.sum(stds < 1e-10)
        if low_var_count > 0:
            low_names = [FEATURE_NAMES[i] for i in range(len(stds)) if stds[i] < 1e-10 and i < len(FEATURE_NAMES)]
            log_warn(f"low-diversity features ({low_var_count}): {', '.join(low_names)}")
            log_warn("consider running diverse workloads during learning phase")
            return False
        means = np.abs(X.mean(axis=0))
        cvs = np.where(means > 1e-12, stds / means, 0.0)
        low_cv = np.sum(cvs < 0.01)
        if low_cv > len(stds) // 2:
            log_warn(f"{low_cv}/{len(stds)} features have CV < 0.01 — training data may be too uniform")
            return False
        return True



def build_alert(level: str, timestamp_ns: int, composite: float,
                if_raw: float, svm_raw: float, reason: str) -> str:
    alert = {
        "level": level,
        "timestamp": timestamp_ns,
        "anomaly_score": round(composite, 4),
        "reason": reason,
        "model_agreement": "both" if level == "CRITICAL" else ("single" if level == "WARNING" else "none"),
        "if_score": round(if_raw, 4),
        "svm_score": round(svm_raw, 4),
    }
    return json.dumps(alert)


def classify_reason(x: np.ndarray, scaler, if_model) -> str:
    """Heuristic: check which raw metrics are most deviant."""
    parts = []
    cmr, bmr, ipc = x[0], x[1], x[2]
    cmr_rmean = x[3]
    bmr_rmean = x[4]
    ipc_rmean = x[5]
    cmr_rstd = x[6] if x[6] > 1e-12 else 1e-6
    bmr_rstd = x[7] if x[7] > 1e-12 else 1e-6
    ipc_rstd = x[8] if x[8] > 1e-12 else 0.01

    if cmr_rstd > 0 and (cmr - cmr_rmean) / cmr_rstd > 3.0:
        parts.append("cache_miss_spike")
    if bmr_rstd > 0 and (bmr - bmr_rmean) / bmr_rstd > 3.0:
        parts.append("branch_miss_spike")
    if ipc_rstd > 0 and (ipc - ipc_rmean) / ipc_rstd < -3.0:
        parts.append("ipc_collapse")

    if not parts:
        parts.append("ensemble_anomaly")

    return " ".join(parts)


_log_file = None
_verbose = False


def _log(prefix: str, msg: str):
    line = f"[guardian-ml] {prefix}: {msg}"
    print(line, file=sys.stderr, flush=True)
    if _log_file:
        try:
            with open(_log_file, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


def log_info(msg: str):
    _log("INFO", msg)


def log_warn(msg: str):
    _log("WARN", msg)


def log_alert(json_str: str):
    print(json_str, flush=True)
    if _log_file:
        try:
            with open(_log_file, "a") as f:
                f.write(json_str + "\n")
        except OSError:
            pass



def create_receiver_socket(socket_path: str) -> socket.socket:
    """Create and bind a Unix datagram socket for receiving samples."""
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(socket_path)
    sock.settimeout(1.0)

    log_info(f"listening on {socket_path} (wire size = {WIRE_SIZE} bytes)")
    return sock


def unpack_sample(data: bytes) -> dict:
    """Unpack binary datagram into a dict of field values."""
    if len(data) < WIRE_SIZE:
        return None
    values = struct.unpack(WIRE_FMT, data[:WIRE_SIZE])
    return dict(zip(FIELD_NAMES, values))



def main():
    global _log_file, _verbose

    parser = argparse.ArgumentParser(description="CPU Guardian ML Detection Engine")
    parser.add_argument("--socket", default="/tmp/cpu-guardian.sock",
                        help="Unix domain socket path (default: /tmp/cpu-guardian.sock)")
    parser.add_argument("--learning-samples", type=int, default=5000,
                        help="Number of samples to collect before initial training (default: 5000)")
    parser.add_argument("--retrain-interval", type=float, default=300.0,
                        help="Seconds between periodic retraining (default: 300)")
    parser.add_argument("--retrain-buffer", type=int, default=10000,
                        help="Max normal samples kept for retraining (default: 10000)")
    parser.add_argument("--log-file", default=None,
                        help="Write alerts and logs to this file")
    parser.add_argument("--verbose", action="store_true",
                        help="Print every sample's detection result to stderr")
    args = parser.parse_args()

    _log_file = args.log_file
    _verbose = args.verbose

    log_info("CPU Guardian ML engine starting")
    log_info(f"config: learning_samples={args.learning_samples}, "
             f"retrain_interval={args.retrain_interval}s, "
             f"retrain_buffer={args.retrain_buffer}")

    shutdown = threading.Event()

    def handle_signal(signum, frame):
        log_info("shutdown signal received")
        shutdown.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    sock = create_receiver_socket(args.socket)

    extractor = FeatureExtractor()
    detector = EnsembleDetector(
        retrain_interval=args.retrain_interval,
        retrain_buffer_size=args.retrain_buffer,
    )

    learning_features = []
    total_samples = 0
    anomaly_count = 0
    phase = "LEARNING"

    log_info(f"entering learning phase (collecting {args.learning_samples} samples)...")

    while not shutdown.is_set():
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            if detector.trained:
                detector.maybe_retrain()
            continue
        except OSError:
            if shutdown.is_set():
                break
            continue

        sample = unpack_sample(data)
        if sample is None:
            continue

        total_samples += 1
        cmr = sample["cache_miss_rate"]
        bmr = sample["branch_miss_rate"]
        ipc = sample["ipc"]

        features = extractor.push(cmr, bmr, ipc)

        if phase == "LEARNING":
            if total_samples > ROLLING_WINDOW:
                learning_features.append(features.copy())

            if len(learning_features) >= args.learning_samples:
                X_train = np.array(learning_features)
                log_info(f"learning complete: {len(X_train)} feature vectors collected")
                detector.train(X_train)
                learning_features = None
                phase = "DETECTION"
                log_info("entering detection phase...")
            continue

        level, composite, if_raw, svm_raw = detector.predict(features)

        if level == "NORMAL":
            detector.add_normal_sample(features)
            if _verbose and total_samples % 1000 == 0:
                log_info(f"status: {total_samples} samples, {anomaly_count} anomalies, "
                         f"retrain_buf={len(detector.retrain_buf)}")
        else:
            anomaly_count += 1
            reason = classify_reason(features, detector.scaler, detector.if_model)
            alert_json = build_alert(level, sample["timestamp_ns"],
                                     composite, if_raw, svm_raw, reason)
            log_alert(alert_json)

            if _verbose:
                log_info(f"[{level}] score={composite:.4f} if={if_raw:.4f} "
                         f"svm={svm_raw:.4f} reason={reason}")

        detector.maybe_retrain()

    sock.close()
    try:
        os.unlink(args.socket)
    except OSError:
        pass

    log_info(f"shutdown complete. total={total_samples}, anomalies={anomaly_count}")


if __name__ == "__main__":
    main()
