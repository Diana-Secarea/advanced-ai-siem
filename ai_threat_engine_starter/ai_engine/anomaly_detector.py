"""
Anomaly Detection using Isolation Forest
"""

import json
import ipaddress
import numpy as np
import os
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def _load_user_benign_ids():
    """Read user-defined benign rule IDs from the UI-managed benign_rules.json."""
    rules_file = Path(__file__).resolve().parent.parent.parent / "backend" / "benign_rules.json"
    try:
        if rules_file.exists():
            with open(rules_file, "r") as f:
                data = json.load(f)
            return set(data.keys())
    except Exception:
        pass
    return set()


def _load_user_suspicious_groups():
    """Read user-defined suspicious groups from the UI-managed suspicious_groups.json."""
    groups_file = Path(__file__).resolve().parent.parent.parent / "backend" / "suspicious_groups.json"
    try:
        if groups_file.exists():
            with open(groups_file, "r") as f:
                data = json.load(f)
            return set(data.keys())
    except Exception:
        pass
    return set()

class AnomalyDetector:
    def __init__(self, model_path=None):
        self.model_path = model_path or "/var/ossec/ai_models/anomaly_detector.pkl"
        self.scaler = StandardScaler()
        self.model = None
        # Calibration values for score normalization (set during training)
        self.score_min = None  # Most anomalous raw score seen in training
        self.score_max = None  # Most normal raw score seen in training
        # Anomaly threshold: normalized score >= this value triggers is_anomaly=True
        # Default 50 = anything above the midpoint of the clean data range is anomalous
        self.anomaly_threshold = 50
        self.load_model()
        # Load user-defined exceptions from the UI-managed files.
        self._effective_benign_ids = _load_user_benign_ids()
        self.SUSPICIOUS_GROUPS = _load_user_suspicious_groups()
    
    def load_model(self):
        """Load or create model"""
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.model = data['model']
                self.scaler = data['scaler']
                self.score_min = data.get('score_min')
                self.score_max = data.get('score_max')
                self.anomaly_threshold = data.get('anomaly_threshold', 50)
                print("Loaded existing anomaly detection model")
            except Exception as e:
                print(f"Error loading model: {e}, creating new model")
                self.train_new_model()
        else:
            print("No existing model found, creating new model")
            self.train_new_model()
    
    def train_new_model(self):
        """Train Isolation Forest on sample data"""
        self.model = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100,
            n_jobs=-1
        )
        
        # Generate sample training data (in production, use real Wazuh logs)
        training_data = self.generate_sample_training_data()
        
        if len(training_data) > 0:
            X = np.array(training_data)
            X_scaled = self.scaler.fit_transform(X)
            self.model.fit(X_scaled)
            # Calibrate score range from training data
            raw_scores = self.model.decision_function(X_scaled)
            self.score_min = float(np.percentile(raw_scores, 2))
            self.score_max = float(np.percentile(raw_scores, 98))
            self.save_model()
            print("Anomaly detection model trained and saved")
    
    # Populated at __init__ time from the UI-managed suspicious_groups.json.
    # See suggested_suspicious_groups.json for a curated list of candidates.

    def generate_sample_training_data(self, n_samples=1000):
        """Generate sample training data matching the 13-feature schema (benign baseline)"""
        np.random.seed(42)
        data = []

        for _ in range(n_samples):
            # Simulate normal (benign) Wazuh alerts
            hour = np.random.randint(8, 18)  # Business hours
            features = [
                np.random.poisson(5),                                   # 0: word_count
                np.random.normal(800, 200),                             # 1: event_size
                0,                                                      # 2: failed_count (0 for normal)
                hour,                                                   # 3: hour
                0,                                                      # 4: off_hours flag
                1,                                                      # 5: ip_count
                np.random.poisson(1),                                   # 6: port_count
                np.random.poisson(1),                                   # 7: process_count
                np.random.choice([3, 3, 3, 3, 4]),                      # 8: rule_level (low for benign)
                np.random.choice([501, 502, 530, 531, 5402, 5501]),     # 9: rule_id
                0,                                                      # 10: suspicious_group_count
                np.random.randint(0, 2),                                # 11: data_field_count
                0,                                                      # 12: is_external_srcip (benign = internal)
                0,                                                      # 13: url_suspicious (benign = no attack URLs)
                0,                                                      # 14: unknown_user_flag (benign = known users)
                0,                                                      # 15: privileged_account_change (benign = no group/mode changes)
            ]
            data.append(features)

        return data

    # Rule IDs and groups for privileged OS-level changes that are rare in normal
    # operation but high-value for attackers: group creation, group membership
    # changes, and network interface promiscuous mode (passive sniffing).
    # These need a dedicated feature because their feature vectors (level=8, no
    # IPs, no keywords, no URLs) look almost identical to benign events — only
    # the rule_id itself distinguishes them, and rule_id alone has too high a
    # cardinality for the Isolation Forest to isolate on one-off values.
    PRIVILEGED_CHANGE_RULE_IDS = frozenset({5901, 5902, 5903, 5904, 5104})
    PRIVILEGED_CHANGE_GROUPS   = frozenset({'adduser', 'groupmod',
                                             'network_changes', 'promisc_mode'})

    # URL patterns that appear in web/app attacks regardless of rule classification.
    # These are checked against the full raw text of the alert, so they fire even
    # on completely unknown rules as long as the log contains the pattern.
    # NOTE: 'wp-admin' is intentionally excluded — legitimate WordPress admin sessions
    # always contain it, causing every admin action to score as suspicious.
    SUSPICIOUS_URL_PATTERNS = (
        'wp-login', 'phpmyadmin', 'login.php',
        '/shell', '/cmd', '/exec', '/.git', '/.env',
        '/etc/passwd', '/proc/', '../', '%2e%2e', 'xmlrpc.php',
    )

    # Cloudflare CDN / reverse-proxy IP ranges. Traffic from these addresses is
    # a legitimate CDN hop (WordPress, email delivery, etc.) — not an attacker.
    # We exclude them from the external-IP feature so that WordPress admin events
    # don't get flagged purely because their src IP routes through Cloudflare.
    _CDN_NETWORKS = None  # lazy-initialised on first call

    @staticmethod
    def _get_cdn_networks():
        """Return list of CDN/proxy ipaddress.IPv4Network objects (built once)."""
        if AnomalyDetector._CDN_NETWORKS is None:
            cdn_cidrs = [
                '162.158.0.0/15',   # Cloudflare
                '172.64.0.0/13',    # Cloudflare
                '104.16.0.0/13',    # Cloudflare
                '104.24.0.0/14',    # Cloudflare
                '108.162.192.0/18', # Cloudflare
                '141.101.64.0/18',  # Cloudflare
                '188.114.96.0/20',  # Cloudflare
                '103.21.244.0/22',  # Cloudflare
                '103.22.200.0/22',  # Cloudflare
                '103.31.4.0/22',    # Cloudflare
                '173.245.48.0/20',  # Cloudflare
                '198.41.128.0/17',  # Cloudflare
            ]
            AnomalyDetector._CDN_NETWORKS = [
                ipaddress.ip_network(c) for c in cdn_cidrs
            ]
        return AnomalyDetector._CDN_NETWORKS

    @staticmethod
    def _is_external_ip(ip_str: str) -> int:
        """Return 1 if ip_str is a routable public IP that is NOT a CDN/proxy, 0 otherwise.

        Private/reserved ranges (RFC1918, loopback, link-local) are benign
        internal infrastructure. Known CDN hops (Cloudflare) are also excluded
        so legitimate WordPress or email traffic doesn't inflate anomaly scores.
        """
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return 0
            for net in AnomalyDetector._get_cdn_networks():
                if ip in net:
                    return 0
            return 1
        except ValueError:
            return 0

    def extract_features(self, event):
        """Extract 16 numerical features from a Wazuh alert"""
        features = []
        rule = event.get('rule', {})

        # Use full_log first (where keywords like 'failed', 'denied' actually appear),
        # fall back to message, then data
        full_log = str(event.get('full_log', ''))
        message = full_log if full_log else str(event.get('message', event.get('data', {})))
        message_lower = message.lower()

        # --- Original features (fixed) ---

        # 0: Word count (message complexity) — capped at 60.
        # CIS/SCA compliance scan blobs can exceed 180 words; without capping,
        # a verbose but benign compliance report scores like a complex attack log.
        features.append(min(len(message.split()), 60))

        # 1: Log size in bytes
        features.append(len(json.dumps(event)))

        # 2: Failed/denied count — reads full_log where these keywords actually appear.
        # Exclude "failed → passed" CIS compliance transitions: the word "failed" there
        # describes a previous state, not a current failure event.
        is_compliance_transition = ('failed to passed' in message_lower
                                    or 'status changed from failed' in message_lower)
        if is_compliance_transition:
            failed_count = 0
        else:
            failed_count = (
                message_lower.count('failed')
                + message_lower.count('denied')
                + message_lower.count('invalid')
                + message_lower.count('error')
            )
        features.append(failed_count)

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

        # 5: IP count — fixed to handle string (most common) and list
        agent = event.get('agent', {})
        ip_count = 0
        if isinstance(agent, dict):
            ip_val = agent.get('ip')
            if isinstance(ip_val, list):
                ip_count = len(ip_val)
            elif isinstance(ip_val, str) and ip_val:
                ip_count = 1
            # Also count srcip in data section (attacker IP)
            data_section = event.get('data', {})
            if isinstance(data_section, dict) and data_section.get('srcip'):
                ip_count += 1
        features.append(ip_count)

        # 6: Port count — use data.srcport if available, fall back to heuristic
        port_count = 0
        data_section = event.get('data', {})
        if isinstance(data_section, dict):
            if data_section.get('srcport'):
                port_count += 1
            if data_section.get('dstport'):
                port_count += 1
        if port_count == 0:
            # Fallback heuristic: count 'port' keyword in message
            port_count = message_lower.count(' port ')
        features.append(min(port_count, 10))

        # 7: Process count
        process_count = message_lower.count('process') + message_lower.count('exec')
        features.append(min(process_count, 5))

        # --- New features ---

        # 8: Rule level (Wazuh severity: 3=info, 5-7=warning, 8-12=high, 13+=critical)
        features.append(rule.get('level', 0))

        # 9: Rule ID (numeric — different IDs map to different threat categories)
        try:
            features.append(int(rule.get('id', 0)))
        except (ValueError, TypeError):
            features.append(0)

        # 10: Suspicious group count (how many attack-related groups this alert belongs to)
        groups = set(rule.get('groups', []))
        suspicious_count = len(groups & self.SUSPICIOUS_GROUPS)
        features.append(suspicious_count)

        # 11: Data field count (attacks tend to have richer data: srcip, srcport, srcuser)
        data_section = event.get('data', {})
        if isinstance(data_section, dict):
            features.append(len(data_section))
        else:
            features.append(0)

        # --- Behavioral features (rule-agnostic: fire on content, not metadata) ---
        # These are designed to catch unknown attack types that have no matching rule ID,
        # group name, or keyword — the Isolation Forest can only detect novel attacks if
        # the features themselves are behavioral rather than signature-based.

        # 12: External source IP — 1 if srcip is a routable public address.
        srcip = ''
        if isinstance(data_section, dict):
            srcip = str(data_section.get('srcip', ''))
        features.append(self._is_external_ip(srcip) if srcip else 0)

        # 13: Suspicious URL pattern — 1 if any field contains a web-attack path.
        all_text = (full_log + ' ' + json.dumps(data_section)).lower()
        features.append(1 if any(p in all_text for p in self.SUSPICIOUS_URL_PATTERNS) else 0)

        # 14: Unknown user flag — 1 if auth was attempted with an unrecognized identity.
        unknown_signals = (
            str(data_section.get('user_id', '1')) == '0'
            or str(data_section.get('CurrentUserID', '1')) == '0'
            or 'unknown user' in message_lower
            or 'invalid user' in message_lower
            or 'no such user' in message_lower
        )
        features.append(1 if unknown_signals else 0)

        # 16: Privileged account/network change.
        # "New group added", "Group membership changed", and "Interface entered
        # promiscuous mode" events look exactly like benign alerts (level=8, no IPs,
        # no keywords) — only their rule_id or group tag distinguishes them.
        # A binary feature gives the model a clean signal to isolate on.
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

        return np.array(features).reshape(1, -1)
    
    def _normalize_score(self, raw_score):
        """Convert raw Isolation Forest score to 0-100 scale using calibration data.

        Raw scores: negative = anomalous, positive = normal.
        Normalized: 0 = normal, 100 = highly anomalous.
        """
        if self.score_min is not None and self.score_max is not None:
            # Min-max normalization using calibrated range, then invert
            score_range = self.score_max - self.score_min
            if score_range > 0:
                normalized = (self.score_max - raw_score) / score_range * 100
            else:
                normalized = 50
        else:
            # Fallback: hardcoded range
            normalized = ((-raw_score + 0.5) * 100)
        return max(0, min(100, int(normalized)))

    def detect_anomaly(self, event):
        """Detect if event is anomalous using score-based threshold."""
        try:
            rule = event.get('rule', {})
            rule_id = str(rule.get('id', ''))

            features = self.extract_features(event)
            X = self.scaler.transform(features)
            raw_score = self.model.decision_function(X)[0]
            normalized_score = self._normalize_score(raw_score)

            # Post-inference override: hardcoded + user-defined benign rule IDs.
            # The model may score these high if training data had few examples,
            # but they are definitively routine OS events — not attacks.
            if rule_id in self._effective_benign_ids:
                normalized_score = min(normalized_score, 35)

            is_anomaly = normalized_score >= self.anomaly_threshold

            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': normalized_score,
                'confidence': abs(normalized_score - 50) * 2,
            }
        except Exception as e:
            print(f"Anomaly detection error: {e}")
            return {
                'is_anomaly': False,
                'anomaly_score': 0,
                'confidence': 0,
            }
    
    def save_model(self):
        """Save model and calibration data to disk"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump({
                'model': self.model,
                'scaler': self.scaler,
                'score_min': self.score_min,
                'score_max': self.score_max,
                'anomaly_threshold': self.anomaly_threshold,
            }, self.model_path)
        except Exception as e:
            print(f"Error saving model: {e}")
    
    def score_event(self, event):
        """
        Score event for prioritization (0-100)
        Higher score = higher priority
        """
        anomaly_result = self.detect_anomaly(event)
        return anomaly_result['anomaly_score']
    
    def multi_dimensional_scoring(self, event):
        """
        Multi-dimensional scoring for comprehensive analysis
        
        Returns:
            dict with scores for different dimensions
        """
        features = self.extract_features(event)
        X = self.scaler.transform(features)
        
        # Base anomaly score (uses calibrated normalization)
        anomaly_score_raw = self.model.decision_function(X)[0]
        anomaly_score = self._normalize_score(anomaly_score_raw)
        
        # Time-based scoring
        timestamp = event.get('timestamp', event.get('@timestamp', ''))
        hour = 12
        if timestamp:
            try:
                if 'T' in str(timestamp):
                    hour = int(str(timestamp).split('T')[1].split(':')[0])
            except:
                pass
        
        # Off-hours = higher priority (more suspicious)
        time_score = 0
        if 2 <= hour <= 6:  # Off-hours
            time_score = 30
        elif 22 <= hour or hour <= 2:  # Late night
            time_score = 20
        elif 8 <= hour <= 18:  # Business hours
            time_score = 5
        
        # Frequency scoring — use full_log where 'failed'/'denied' actually appear
        full_log = str(event.get('full_log', ''))
        message = full_log if full_log else str(event.get('message', event.get('data', {})))
        message_lower = message.lower()
        failed_count = (
            message_lower.count('failed')
            + message_lower.count('denied')
            + message_lower.count('invalid')
        )
        frequency_score = min(failed_count * 10, 50)  # Cap at 50

        # Network activity scoring — handle string IP + check data.srcip
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

        network_score = min((ip_count - 1) * 5, 20)  # Multiple IPs = more suspicious
        
        # Combined score
        combined_score = (
            anomaly_score * 0.5 +      # 50% weight on anomaly
            time_score * 0.2 +         # 20% weight on time
            frequency_score * 0.2 +    # 20% weight on frequency
            network_score * 0.1        # 10% weight on network
        )
        combined_score = min(100, int(combined_score))
        
        return {
            'anomaly_score': anomaly_score,
            'time_score': time_score,
            'frequency_score': frequency_score,
            'network_score': network_score,
            'combined_score': combined_score,
            'priority_score': combined_score  # Alias for clarity
        }
    
    def prioritize_events(self, events):
        """
        Prioritize events by scoring them and ranking
        
        Args:
            events: List of event dictionaries
        
        Returns:
            List of events with priority scores and ranks, sorted by priority
        """
        scored_events = []
        
        for event in events:
            scoring = self.multi_dimensional_scoring(event)
            scored_events.append({
                'event': event,
                'priority_score': scoring['combined_score'],
                'anomaly_score': scoring['anomaly_score'],
                'time_score': scoring['time_score'],
                'frequency_score': scoring['frequency_score'],
                'network_score': scoring['network_score'],
                'rank': 0  # Will be set after sorting
            })
        
        # Sort by priority score (descending)
        scored_events.sort(key=lambda x: x['priority_score'], reverse=True)
        
        # Assign ranks
        for i, item in enumerate(scored_events):
            item['rank'] = i + 1
        
        return scored_events
    
    def rank_threats(self, threats_with_scores):
        """
        Rank threats based on multiple scoring criteria
        
        Args:
            threats_with_scores: List of dicts with keys:
                - anomaly_score: float (0-100)
                - pattern_score: float (0-100) 
                - similarity: float (0-1) from RAG
        
        Returns:
            List of threats sorted by combined rank
        """
        if not threats_with_scores:
            return []
        
        # Calculate combined score for each threat
        ranked = []
        for threat in threats_with_scores:
            anomaly = threat.get('anomaly_score', 0)
            pattern = threat.get('pattern_score', 0)
            similarity = threat.get('similarity', 0) * 100  # Convert to 0-100
            
            # Weighted combination
            combined = (
                anomaly * 0.4 +      # 40% anomaly
                pattern * 0.3 +      # 30% pattern match
                similarity * 0.3      # 30% RAG similarity
            )
            
            ranked.append({
                **threat,
                'combined_rank_score': combined,
                'rank': 0  # Will be set after sorting
            })
        
        # Sort by combined score (descending)
        ranked.sort(key=lambda x: x['combined_rank_score'], reverse=True)
        
        # Assign ranks
        for i, item in enumerate(ranked):
            item['rank'] = i + 1
        
        return ranked