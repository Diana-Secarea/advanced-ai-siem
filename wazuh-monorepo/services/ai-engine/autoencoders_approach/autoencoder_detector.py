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

try:                                    # imported as autoencoders_approach.<mod>
    from .score_window import ScoreWindow
except ImportError:                      # …or with this directory on sys.path
    from score_window import ScoreWindow

try:
    from feature_text import message_word_count
except Exception:  # ai-engine root not on path when imported standalone
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    try:
        from feature_text import message_word_count
    except Exception:
        def message_word_count(message, cap=60):
            return min(len(str(message).split()), cap)


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


#: A StandardScaler fitted on the clean-only training set reports a standard
#: deviation near zero for every feature the clean filter selects against.
#: `is_attack_alert()` routes failed logins, off-hours activity and unknown
#: users OUT of the training set, so within it those counts are almost always
#: 0 (measured 2026-09-16 on 2,149 alerts: failed_count sd 0.469 over all data,
#: 0.088 over the clean subset; off_hours and unknown_user collapse to exactly
#: 0.000). Dividing by that sd turns a SINGLE failed login into z ~ 11-37 and
#: the reconstruction error saturates the score at 100 regardless of content.
#:
#: These features are integer counts and flags, where the smallest meaningful
#: difference is 1. An sd below 1 claims a difference of one occurrence is more
#: than a standard deviation of ordinary variation — which is an artefact of
#: how the training set was filtered, not a property of the host. Flooring the
#: scale at 1.0 says "one occurrence is at most one standard deviation" and
#: leaves every genuinely wide feature (event_size sd 588, rule_id sd 8540,
#: hour sd 4.1, word_count sd 10.1) untouched.
#:
#: MEASURED RESULT — DEFAULT OFF. A/B retrain on the 2,149-alert corpus
#: (2026-09-16) showed the floor does NOT reduce saturation:
#:
#:     retrained, no floor   : 31.9% of events score 100, mean MSE  8.65
#:     retrained, floor=1.0  : 31.0% of events score 100, mean MSE 49.97
#:
#: The reason is that saturation is set by the CALIBRATION RANGE, not by the
#: absolute size of z: recon_error_max is the 98th percentile of error on the
#: same clean set, so flooring the scale inflates clean and anomalous error
#: together and their ratio barely moves. It buys 0.9pp of saturation for a 6x
#: larger MSE. Rank scoring is what actually fixes this (see _rank_score).
#:
#: Kept, off by default, because it stops being a no-op once the Tier-2
#: relabelling puts failure-bearing events back into the training set: this
#: clamp is what keeps a genuinely rare-but-real count from dominating then.
#: Set AE_UNIT_SCALE_FLOOR=1.0 to enable — and retrain, never on a live model.
UNIT_SCALE_FLOOR = float(os.environ.get("AE_UNIT_SCALE_FLOOR", "0"))


def apply_variance_floor(scaler, floor=None):
    """Clamp a fitted StandardScaler's per-feature scale to at least `floor`.

    Idempotent — max() of an already-floored scale is unchanged — so it is safe
    to apply both when a model is trained and again when one is loaded. That
    matters: it lets an ALREADY SHIPPED model stop saturating without a retrain.
    """
    floor = UNIT_SCALE_FLOOR if floor is None else float(floor)
    scale = getattr(scaler, "scale_", None)
    if scale is None or floor <= 0:
        return scaler
    floored = np.maximum(np.asarray(scale, dtype=float), floor)
    scaler.scale_ = floored
    # var_ is only reported, never used by transform(), but leaving it
    # inconsistent with scale_ would mislead anyone inspecting the model.
    if getattr(scaler, "var_", None) is not None:
        scaler.var_ = floored ** 2
    return scaler


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
        #: Scale floor this model was TRAINED with; None for pre-floor models.
        self.variance_floor = None
        #: Training provenance. Kept in the artefact because "what did this
        #: model consider normal, and how was that decided" is the first
        #: question worth asking when it starts misbehaving in production.
        self.trained_unsupervised = None
        self.trim_purity = None     # share of dropped rows that were attacks
        self.trim_recall = None     # share of known attacks the trim removed
        self.anomaly_threshold = 50   # Normalized score >= this → anomaly
        # Alert budget: in rank mode the flag is "the worst N% of what this
        # host emitted lately", which is a number an operator can actually
        # choose. The fitted threshold above is kept for the cold-start path.
        self.alert_budget_pct = float(os.environ.get("AE_ALERT_BUDGET_PCT", "5"))
        self.rank_scoring = os.environ.get("AE_RANK_SCORING", "1") != "0"
        self.load_model()
        self.window = ScoreWindow(self._window_path())
        self._effective_benign_ids = _load_user_benign_ids()
        self.SUSPICIOUS_GROUPS = _load_user_suspicious_groups()

    # ------------------------------------------------------------------ #
    #  Model persistence                                                   #
    # ------------------------------------------------------------------ #

    def _window_path(self):
        """Beside the model: the window describes this model on this host."""
        base = os.path.splitext(self.model_path)[0]
        return f"{base}_score_window.json"

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.model = data['model']
                self.scaler = data['scaler']
                self.recon_error_min = data.get('recon_error_min')
                self.recon_error_max = data.get('recon_error_max')
                self.anomaly_threshold = data.get('anomaly_threshold', 50)
                # Only re-applied for a model that was TRAINED with a floor.
                # Flooring a scaler after the fact was measured to make things
                # worse (mean MSE 8.65 -> 13.54 on 2,149 alerts): the network
                # was fitted on the unfloored scale, so changing it at serve
                # time hands the model inputs it has never seen. A model that
                # predates the floor needs a retrain, not a rescale.
                self.variance_floor = data.get('variance_floor')
                self.trained_unsupervised = data.get('trained_unsupervised')
                self.trim_purity = data.get('trim_purity')
                self.trim_recall = data.get('trim_recall')
                if self.variance_floor:
                    apply_variance_floor(self.scaler, self.variance_floor)
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
                'variance_floor': self.variance_floor,
                'trained_unsupervised': self.trained_unsupervised,
                'trim_purity': self.trim_purity,
                'trim_recall': self.trim_recall,
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

        # 0: Word count (capped at 60) — JSON-aware, must stay identical to the
        # IF extractor or the stacker combines two different notions of input.
        features.append(message_word_count(message))

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

    def _calibrated_score(self, recon_error):
        """The original fitted 0-100 scale.

        Kept unchanged because the stacking meta-model was trained on it: feed
        it a differently-shaped input and its learned weights stop meaning
        anything. This is also the cold-start score, before the rolling window
        has enough samples to rank against.

        Its weakness is the reason for _rank_score(): recon_error_max is the
        98th percentile of error on the CLEAN training set, so the whole 0-100
        range spans a fraction of an MSE unit and everything past it clamps
        to 100.
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

    def _rank_score(self, recon_error):
        """0-100 rank of this error against recent traffic, or None if cold.

        Has no ceiling to hit: "worse than 99% of what this host emitted
        lately" is the same statement on any host and stays true as the
        distribution drifts.
        """
        if not self.rank_scoring:
            return None
        window = getattr(self, "window", None)
        if window is None:
            return None
        rank = window.rank(recon_error)
        return None if rank is None else max(0, min(100, int(round(rank))))

    def _normalize_score(self, recon_error):
        """Preferred 0-100 score: rank when the window is warm, else fitted."""
        rank = self._rank_score(recon_error)
        return self._calibrated_score(recon_error) if rank is None else rank

    def detect_anomaly(self, event, learn=True):
        """Return anomaly detection result for a single Wazuh alert.

        learn=False scores without recording the event in the rolling window —
        for evaluation and back-testing, which must not reshape the live
        baseline they are measuring against.
        """
        if self.model is None:
            return {'is_anomaly': False, 'anomaly_score': 0, 'confidence': 0,
                    'calibrated_score': 0, 'scoring_mode': 'unavailable',
                    'reconstruction_error': 0.0}

        try:
            rule = event.get('rule', {})
            rule_id = str(rule.get('id', ''))

            features = self.extract_features(event)
            X = self.scaler.transform(features)
            recon_error = self._reconstruction_error(X)

            # Ranked BEFORE the window is updated, so nothing ranks against
            # itself, and the calibrated score is computed either way — the
            # stacker is only ever shown the scale it was trained on.
            rank_score = self._rank_score(recon_error)
            calibrated_score = self._calibrated_score(recon_error)
            if learn and getattr(self, "window", None) is not None:
                self.window.add(recon_error)

            ranked = rank_score is not None
            normalized_score = rank_score if ranked else calibrated_score

            # User-defined benign rule ID override
            if rule_id in self._effective_benign_ids:
                normalized_score = min(normalized_score, 35)
                calibrated_score = min(calibrated_score, 35)

            if ranked:
                # An explicit budget: flag the worst N% of recent traffic.
                # The fitted threshold is a percentile of CLEAN error, which on
                # a saturated model puts essentially everything above it.
                is_anomaly = normalized_score >= (100.0 - self.alert_budget_pct)
            else:
                is_anomaly = normalized_score >= self.anomaly_threshold

            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': normalized_score,
                'calibrated_score': calibrated_score,
                'scoring_mode': 'rank' if ranked else 'calibrated',
                'reconstruction_error': recon_error,
                'confidence': abs(normalized_score - 50) * 2,
            }
        except Exception as e:
            print(f"Autoencoder detection error: {e}")
            return {'is_anomaly': False, 'anomaly_score': 0, 'confidence': 0,
                    'calibrated_score': 0, 'scoring_mode': 'error',
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
