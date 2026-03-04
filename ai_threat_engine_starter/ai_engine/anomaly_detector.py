"""
Anomaly Detection using Isolation Forest
"""

import json
import numpy as np
import os
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

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
    
    # Groups that indicate suspicious/attack activity in Wazuh alerts
    SUSPICIOUS_GROUPS = {
        'authentication_failed', 'invalid_login', 'authentication_failures',
        'sshd', 'rootcheck', 'syscheck', 'attack', 'exploit',
        'web_attack', 'sql_injection', 'ids', 'firewall_drop',
    }

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
                0,                                                      # 10: mitre_count (0 for benign)
                0,                                                      # 11: suspicious_group_count
                np.random.randint(0, 2),                                # 12: data_field_count
            ]
            data.append(features)

        return data

    def extract_features(self, event):
        """Extract 13 numerical features from a Wazuh alert"""
        features = []
        rule = event.get('rule', {})

        # Use full_log first (where keywords like 'failed', 'denied' actually appear),
        # fall back to message, then data
        full_log = str(event.get('full_log', ''))
        message = full_log if full_log else str(event.get('message', event.get('data', {})))
        message_lower = message.lower()

        # --- Original features (fixed) ---

        # 0: Word count (message complexity)
        features.append(len(message.split()))

        # 1: Log size in bytes
        features.append(len(json.dumps(event)))

        # 2: Failed/denied count — now reads full_log where these keywords actually appear
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

        # 10: MITRE ATT&CK technique count (attacks have MITRE tags, normal events often don't)
        mitre = rule.get('mitre', {})
        mitre_count = len(mitre.get('technique', []))
        features.append(mitre_count)

        # 11: Suspicious group count (how many attack-related groups this alert belongs to)
        groups = set(rule.get('groups', []))
        suspicious_count = len(groups & self.SUSPICIOUS_GROUPS)
        features.append(suspicious_count)

        # 12: Data field count (attacks tend to have richer data: srcip, srcport, srcuser)
        data_section = event.get('data', {})
        if isinstance(data_section, dict):
            features.append(len(data_section))
        else:
            features.append(0)

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
        """Detect if event is anomalous using score-based threshold"""
        try:
            features = self.extract_features(event)
            X = self.scaler.transform(features)
            raw_score = self.model.decision_function(X)[0]

            normalized_score = self._normalize_score(raw_score)
            # Use score-based threshold instead of model.predict()
            # This gives much better detection since the scores are well-calibrated
            is_anomaly = normalized_score >= self.anomaly_threshold

            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': normalized_score,
                'confidence': abs(normalized_score - 50) * 2
            }
        except Exception as e:
            print(f"Anomaly detection error: {e}")
            return {
                'is_anomaly': False,
                'anomaly_score': 0,
                'confidence': 0
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