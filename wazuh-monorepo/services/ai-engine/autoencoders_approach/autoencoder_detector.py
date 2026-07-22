"""
Autoencoder-based Anomaly Detector for Wazuh alerts.

Architecture: 16 → 8 → 4 → 8 → 16 (bottleneck MLP trained to reconstruct input).
Anomaly score = reconstruction MSE, normalized to 0-100.
Higher score = more anomalous (model cannot reconstruct the pattern from its
compressed representation, meaning it has never seen this kind of event during training).

Uses the exact same 16-feature extraction as the Isolation Forest detector so both
models operate on identical input — enabling a fair apples-to-apples comparison.
"""

import json
import ipaddress
import numpy as np
import os
import joblib
from pathlib import Path
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler


def _load_user_benign_ids():
    rules_file = Path(__file__).resolve().parent.parent.parent.parent / "apps" / "backend" / "benign_rules.json"
    try:
        if rules_file.exists():
            with open(rules_file, "r") as f:
                data = json.load(f)
            return set(data.keys())
    except Exception:
        pass
    return set()


def _load_user_suspicious_groups():
    groups_file = Path(__file__).resolve().parent.parent.parent.parent / "apps" / "backend" / "suspicious_groups.json"
    try:
        if groups_file.exists():
            with open(groups_file, "r") as f:
                data = json.load(f)
            return set(data.keys())
    except Exception:
        pass
    return set()


class AutoencoderDetector:
    """Autoencoder anomaly detector using sklearn MLPRegressor as a bottleneck network.

    The model is trained to reconstruct its own input (X → X) on clean Wazuh alerts.
    After training, clean alerts reconstruct with low error.
    Attack alerts — which the model has never seen — reconstruct with high error,
    because the bottleneck (4 neurons) cannot represent patterns outside the
    normal manifold it learned.

    Anomaly score = reconstruction MSE, scaled to 0-100 via calibrated percentiles.
    """

    # Exact same constants as AnomalyDetector — must stay in sync.
    PRIVILEGED_CHANGE_RULE_IDS = frozenset({5901, 5902, 5903, 5904, 5104})
    PRIVILEGED_CHANGE_GROUPS   = frozenset({'adduser', 'groupmod',
                                             'network_changes', 'promisc_mode'})

    SUSPICIOUS_URL_PATTERNS = (
        'wp-login', 'phpmyadmin', 'login.php',
        '/shell', '/cmd', '/exec', '/.git', '/.env',
        '/etc/passwd', '/proc/', '../', '%2e%2e', 'xmlrpc.php',
    )

    _CDN_NETWORKS = None

    def __init__(self, model_path=None):
        self.model_path = model_path or "/var/ossec/ai_models/autoencoder_model.pkl"
        self.scaler = StandardScaler()
        self.model = None
        # Calibration: percentile range of reconstruction errors on clean training data
        self.recon_error_min = None   # 2nd percentile (nearly perfect reconstruction)
        self.recon_error_max = None   # 98th percentile (worst normal reconstruction)
        self.anomaly_threshold = 50   # Normalized score >= this → anomaly
        self.load_model()
        self._effective_benign_ids = _load_user_benign_ids()
        self.SUSPICIOUS_GROUPS = _load_user_suspicious_groups()

    # ------------------------------------------------------------------ #
    #  Model persistence                                                   #
    # ------------------------------------------------------------------ #

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.model = data['model']
                self.scaler = data['scaler']
                self.recon_error_min = data.get('recon_error_min')
                self.recon_error_max = data.get('recon_error_max')
                self.anomaly_threshold = data.get('anomaly_threshold', 50)
                print(f"Loaded autoencoder model (threshold={self.anomaly_threshold})")
            except Exception as e:
                print(f"Error loading autoencoder model: {e}")
                self.model = None
        else:
            print(f"No autoencoder model found at {self.model_path}. Run train_autoencoder.py first.")

    def save_model(self):
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump({
                'model': self.model,
                'scaler': self.scaler,
                'recon_error_min': self.recon_error_min,
                'recon_error_max': self.recon_error_max,
                'anomaly_threshold': self.anomaly_threshold,
            }, self.model_path)
        except Exception as e:
            print(f"Error saving autoencoder model: {e}")

    # ------------------------------------------------------------------ #
    #  CDN / IP helpers (identical to AnomalyDetector)                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _get_cdn_networks():
        if AutoencoderDetector._CDN_NETWORKS is None:
            cdn_cidrs = [
                '162.158.0.0/15', '172.64.0.0/13',
                '104.16.0.0/13',  '104.24.0.0/14',
                '108.162.192.0/18', '141.101.64.0/18',
                '188.114.96.0/20', '103.21.244.0/22',
                '103.22.200.0/22', '103.31.4.0/22',
                '173.245.48.0/20', '198.41.128.0/17',
            ]
            AutoencoderDetector._CDN_NETWORKS = [
                ipaddress.ip_network(c) for c in cdn_cidrs
            ]
        return AutoencoderDetector._CDN_NETWORKS

    @staticmethod
    def _is_external_ip(ip_str: str) -> int:
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return 0
            for net in AutoencoderDetector._get_cdn_networks():
                if ip in net:
                    return 0
            return 1
        except ValueError:
            return 0

    # ------------------------------------------------------------------ #
    #  Feature extraction — identical to AnomalyDetector.extract_features #
    # ------------------------------------------------------------------ #

    def extract_features(self, event):
        """Extract the same 16 features as the Isolation Forest detector."""
        features = []
        rule = event.get('rule', {})

        full_log = str(event.get('full_log', ''))
        message = full_log if full_log else str(event.get('message', event.get('data', {})))
        message_lower = message.lower()

        # 0: Word count (capped at 60)
        features.append(min(len(message.split()), 60))

        # 1: Log size in bytes
        features.append(len(json.dumps(event)))

        # 2: Failed/denied count (CIS compliance transitions excluded)
        is_compliance_transition = ('failed to passed' in message_lower
                                    or 'status changed from failed' in message_lower)
        if is_compliance_transition:
            features.append(0)
        else:
            features.append(
                message_lower.count('failed')
                + message_lower.count('denied')
                + message_lower.count('invalid')
                + message_lower.count('error')
            )

        # 3: Hour of day
        timestamp = event.get('timestamp', event.get('@timestamp', ''))
        hour = 12
        if timestamp:
            try:
                if 'T' in str(timestamp):
                    hour = int(str(timestamp).split('T')[1].split(':')[0])
            except Exception:
                pass
        features.append(hour)

        # 4: Off-hours flag
        features.append(1 if 2 <= hour <= 6 else 0)

        # 5: IP count
        agent = event.get('agent', {})
        ip_count = 0
        if isinstance(agent, dict):
            ip_val = agent.get('ip')
            if isinstance(ip_val, list):
                ip_count = len(ip_val)
            elif isinstance(ip_val, str) and ip_val:
                ip_count = 1
            data_section = event.get('data', {})
            if isinstance(data_section, dict) and data_section.get('srcip'):
                ip_count += 1
        features.append(ip_count)

        # 6: Port count
        port_count = 0
        data_section = event.get('data', {})
        if isinstance(data_section, dict):
            if data_section.get('srcport'):
                port_count += 1
            if data_section.get('dstport'):
                port_count += 1
        if port_count == 0:
            port_count = message_lower.count(' port ')
        features.append(min(port_count, 10))

        # 7: Process count
        features.append(min(
            message_lower.count('process') + message_lower.count('exec'), 5
        ))

        # 8: Rule level
        features.append(rule.get('level', 0))

        # 9: Rule ID (numeric)
        try:
            features.append(int(rule.get('id', 0)))
        except (ValueError, TypeError):
            features.append(0)

        # 10: Suspicious group count
        groups = set(rule.get('groups', []))
        features.append(len(groups & self.SUSPICIOUS_GROUPS))

        # 11: Data field count
        data_section = event.get('data', {})
        features.append(len(data_section) if isinstance(data_section, dict) else 0)

        # 12: External source IP flag
        srcip = ''
        if isinstance(data_section, dict):
            srcip = str(data_section.get('srcip', ''))
        features.append(self._is_external_ip(srcip) if srcip else 0)

        # 13: Suspicious URL pattern flag
        all_text = (full_log + ' ' + json.dumps(data_section)).lower()
        features.append(1 if any(p in all_text for p in self.SUSPICIOUS_URL_PATTERNS) else 0)

        # 14: Unknown user flag
        unknown_signals = (
            str(data_section.get('user_id', '1')) == '0'
            or str(data_section.get('CurrentUserID', '1')) == '0'
            or 'unknown user' in message_lower
            or 'invalid user' in message_lower
            or 'no such user' in message_lower
        )
        features.append(1 if unknown_signals else 0)

        # 15: Privileged account/network change flag
        try:
            rid_int = int(rule.get('id', 0))
        except (ValueError, TypeError):
            rid_int = 0
        rule_groups_set = set(rule.get('groups', []))
        priv_change = (
            rid_int in self.PRIVILEGED_CHANGE_RULE_IDS
            or bool(rule_groups_set & self.PRIVILEGED_CHANGE_GROUPS)
        )
        features.append(1 if priv_change else 0)

        return np.array(features, dtype=float).reshape(1, -1)

    # ------------------------------------------------------------------ #
    #  Scoring                                                             #
    # ------------------------------------------------------------------ #

    def _reconstruction_error(self, X_scaled):
        """Per-sample MSE between input and autoencoder output."""
        reconstructed = self.model.predict(X_scaled)
        return float(np.mean((X_scaled - reconstructed) ** 2))

    def _normalize_score(self, recon_error):
        """Map reconstruction error to 0-100 anomaly score.
        0 = reconstructed perfectly (normal), 100 = high error (anomalous).
        """
        if self.recon_error_min is not None and self.recon_error_max is not None:
            error_range = self.recon_error_max - self.recon_error_min
            if error_range > 0:
                normalized = (recon_error - self.recon_error_min) / error_range * 100
            else:
                normalized = 50.0
        else:
            normalized = min(recon_error * 200, 100.0)
        return max(0, min(100, int(normalized)))

    def detect_anomaly(self, event):
        """Return anomaly detection result for a single Wazuh alert."""
        if self.model is None:
            return {'is_anomaly': False, 'anomaly_score': 0, 'confidence': 0,
                    'reconstruction_error': 0.0}

        try:
            rule = event.get('rule', {})
            rule_id = str(rule.get('id', ''))

            features = self.extract_features(event)
            X = self.scaler.transform(features)
            recon_error = self._reconstruction_error(X)
            normalized_score = self._normalize_score(recon_error)

            # User-defined benign rule ID override
            if rule_id in self._effective_benign_ids:
                normalized_score = min(normalized_score, 35)

            is_anomaly = normalized_score >= self.anomaly_threshold

            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': normalized_score,
                'reconstruction_error': recon_error,
                'confidence': abs(normalized_score - 50) * 2,
            }
        except Exception as e:
            print(f"Autoencoder detection error: {e}")
            return {'is_anomaly': False, 'anomaly_score': 0, 'confidence': 0,
                    'reconstruction_error': 0.0}

    def score_event(self, event):
        return self.detect_anomaly(event)['anomaly_score']

    def multi_dimensional_scoring(self, event):
        """Multi-dimensional scoring: autoencoder + time + frequency + network."""
        if self.model is None:
            return {
                'anomaly_score': 0, 'time_score': 0,
                'frequency_score': 0, 'network_score': 0,
                'combined_score': 0, 'priority_score': 0,
            }

        result = self.detect_anomaly(event)
        anomaly_score = result['anomaly_score']

        # Time-based component (identical weights to IF)
        timestamp = event.get('timestamp', event.get('@timestamp', ''))
        hour = 12
        if timestamp:
            try:
                if 'T' in str(timestamp):
                    hour = int(str(timestamp).split('T')[1].split(':')[0])
            except Exception:
                pass

        if 2 <= hour <= 6:
            time_score = 30
        elif 22 <= hour or hour <= 2:
            time_score = 20
        elif 8 <= hour <= 18:
            time_score = 5
        else:
            time_score = 0

        # Frequency component
        full_log = str(event.get('full_log', ''))
        msg = (full_log if full_log else str(event.get('message', event.get('data', {})))).lower()
        failed_count = msg.count('failed') + msg.count('denied') + msg.count('invalid')
        frequency_score = min(failed_count * 10, 50)

        # Network component
        agent = event.get('agent', {})
        ip_count = 0
        if isinstance(agent, dict):
            ip_val = agent.get('ip')
            if isinstance(ip_val, list):
                ip_count = len(ip_val)
            elif isinstance(ip_val, str) and ip_val:
                ip_count = 1
        data_section = event.get('data', {})
        if isinstance(data_section, dict) and data_section.get('srcip'):
            ip_count += 1
        network_score = min((ip_count - 1) * 5, 20)

        combined_score = min(100, int(
            anomaly_score * 0.5
            + time_score * 0.2
            + frequency_score * 0.2
            + network_score * 0.1
        ))

        return {
            'anomaly_score': anomaly_score,
            'time_score': time_score,
            'frequency_score': frequency_score,
            'network_score': network_score,
            'combined_score': combined_score,
            'priority_score': combined_score,
        }
