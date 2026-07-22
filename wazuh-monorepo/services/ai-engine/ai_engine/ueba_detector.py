"""
UEBA (User and Entity Behavior Analytics) detector for Wazuh alerts.

Instead of looking at the shape of a single alert (like the Isolation Forest
and the Autoencoder do), UEBA tracks WHO and WHAT generated the alert and
compares it against a behavioral baseline learned per entity:

  * users  (data.srcuser / data.dstuser / windows targetUserName)
  * hosts  (agent.name)
  * source IPs (data.srcip)

Baselines are built from CLEAN training alerts only (one-class, same
philosophy as the other two detectors): for every entity we record its
active-hours histogram, the rule IDs it normally triggers, the rule levels
it normally reaches, and which user↔host pairs are normal.

Scoring an alert = summing deviation components:

  unknown user          — user never seen in the baseline
  unknown host          — agent never seen in the baseline
  new source IP         — srcip never seen (extra weight if external)
  rare hour             — entity almost never active at this hour
  new rule for entity   — user/host triggering a rule it never triggered
  level escalation      — rule level above the entity's historical max
  new user-host pair    — known user appearing on a host it never used

The raw component sum is normalized to 0-100 and thresholded like the other
detectors, so the ensemble can treat all three scores uniformly.
"""

import ipaddress
import os
from collections import Counter

import joblib


class UEBADetector:
    """Behavioral-baseline anomaly detector keyed on user / host / source IP."""

    # Deviation component weights (raw points, normalized to 0-100 at the end)
    W_UNKNOWN_USER   = 30
    W_UNKNOWN_HOST   = 25
    W_NEW_SRCIP      = 10
    W_EXTERNAL_SRCIP = 10   # added on top of W_NEW_SRCIP when the IP is public
    W_RARE_HOUR      = 20
    W_NEW_RULE_USER  = 15
    W_NEW_RULE_HOST  = 10
    W_LEVEL_ESCALATION = 15
    W_NEW_USER_HOST_PAIR = 10

    # An entity needs at least this many baseline events before hour-rarity
    # and new-rule deviations are trusted (avoids penalizing sparse profiles).
    MIN_EVENTS_FOR_PROFILE = 5

    def __init__(self, model_path=None):
        self.model_path = model_path or "/var/ossec/ai_models/ueba_model.pkl"
        self.anomaly_threshold = 50
        self._reset_profiles()
        self.load_model()

    def _reset_profiles(self):
        self.user_profiles = {}   # user -> profile dict
        self.host_profiles = {}   # host -> profile dict
        self.known_srcips  = set()
        self.user_host_pairs = set()

    # ------------------------------------------------------------------ #
    #  Persistence                                                        #
    # ------------------------------------------------------------------ #

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.user_profiles     = data['user_profiles']
                self.host_profiles     = data['host_profiles']
                self.known_srcips      = data['known_srcips']
                self.user_host_pairs   = data['user_host_pairs']
                self.anomaly_threshold = data.get('anomaly_threshold', 50)
                print(f"Loaded UEBA baselines ({len(self.user_profiles)} users, "
                      f"{len(self.host_profiles)} hosts, threshold={self.anomaly_threshold})")
            except Exception as e:
                print(f"Error loading UEBA model: {e}")
                self._reset_profiles()
        else:
            print(f"No UEBA model found at {self.model_path}. Run train_ueba.py first.")

    def save_model(self):
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump({
                'user_profiles':     self.user_profiles,
                'host_profiles':     self.host_profiles,
                'known_srcips':      self.known_srcips,
                'user_host_pairs':   self.user_host_pairs,
                'anomaly_threshold': self.anomaly_threshold,
            }, self.model_path)
        except Exception as e:
            print(f"Error saving UEBA model: {e}")

    @property
    def is_trained(self):
        return bool(self.user_profiles or self.host_profiles)

    # ------------------------------------------------------------------ #
    #  Entity extraction                                                  #
    # ------------------------------------------------------------------ #

    @staticmethod
    def extract_entities(alert):
        """Return (users, host, srcip, hour, rule_id, rule_level) for an alert."""
        data = alert.get('data') or {}
        if not isinstance(data, dict):
            data = {}

        users = set()
        for key in ('srcuser', 'dstuser'):
            val = data.get(key)
            if val and isinstance(val, str):
                users.add(val.strip().lower())
        win = data.get('win')
        if isinstance(win, dict):
            eventdata = win.get('eventdata') or {}
            for key in ('targetUserName', 'subjectUserName'):
                val = eventdata.get(key)
                if val and isinstance(val, str) and not val.endswith('$'):
                    users.add(val.strip().lower())

        agent = alert.get('agent') or {}
        host = agent.get('name', '').strip().lower() if isinstance(agent, dict) else ''

        srcip = str(data.get('srcip', '')).strip()

        timestamp = alert.get('timestamp', alert.get('@timestamp', ''))
        hour = None
        if timestamp and 'T' in str(timestamp):
            try:
                hour = int(str(timestamp).split('T')[1].split(':')[0])
            except Exception:
                hour = None

        rule = alert.get('rule') or {}
        rule_id = str(rule.get('id', ''))
        level = rule.get('level', 0)

        return users, host, srcip, hour, rule_id, level

    @staticmethod
    def _is_external_ip(ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback
                        or ip.is_link_local or ip.is_reserved)
        except ValueError:
            return False

    # ------------------------------------------------------------------ #
    #  Baseline building (training)                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _new_profile():
        return {
            'hours': Counter(),      # hour of day -> event count
            'rule_ids': set(),
            'max_level': 0,
            'event_count': 0,
        }

    def _update_profile(self, profile, hour, rule_id, level):
        if hour is not None:
            profile['hours'][hour] += 1
        if rule_id:
            profile['rule_ids'].add(rule_id)
        profile['max_level'] = max(profile['max_level'], level or 0)
        profile['event_count'] += 1

    def build_baselines(self, clean_alerts):
        """Build per-entity behavioral baselines from clean alerts only."""
        self._reset_profiles()
        for alert in clean_alerts:
            users, host, srcip, hour, rule_id, level = self.extract_entities(alert)
            for user in users:
                profile = self.user_profiles.setdefault(user, self._new_profile())
                self._update_profile(profile, hour, rule_id, level)
                if host:
                    self.user_host_pairs.add((user, host))
            if host:
                profile = self.host_profiles.setdefault(host, self._new_profile())
                self._update_profile(profile, hour, rule_id, level)
            if srcip:
                self.known_srcips.add(srcip)

    # ------------------------------------------------------------------ #
    #  Scoring                                                            #
    # ------------------------------------------------------------------ #

    def _hour_rarity(self, profile, hour):
        """0.0 (typical hour) → 1.0 (never active at this hour)."""
        if hour is None or profile['event_count'] < self.MIN_EVENTS_FOR_PROFILE:
            return 0.0
        hours = profile['hours']
        if not hours:
            return 0.0
        peak = max(hours.values())
        return 1.0 - (hours.get(hour, 0) / peak)

    def raw_score(self, alert):
        """Return (raw_points, components dict) — un-normalized deviation sum."""
        users, host, srcip, hour, rule_id, level = self.extract_entities(alert)
        components = {}

        # --- User deviations (take the worst-scoring user on the alert) ---
        worst_user_pts = 0
        for user in users:
            pts = 0
            profile = self.user_profiles.get(user)
            if profile is None:
                pts += self.W_UNKNOWN_USER
            else:
                pts += int(self.W_RARE_HOUR * self._hour_rarity(profile, hour))
                if (rule_id and rule_id not in profile['rule_ids']
                        and profile['event_count'] >= self.MIN_EVENTS_FOR_PROFILE):
                    pts += self.W_NEW_RULE_USER
                if level and level > profile['max_level']:
                    pts += self.W_LEVEL_ESCALATION
                if host and (user, host) not in self.user_host_pairs:
                    pts += self.W_NEW_USER_HOST_PAIR
            worst_user_pts = max(worst_user_pts, pts)
        if worst_user_pts:
            components['user'] = worst_user_pts

        # --- Host deviations ---
        host_pts = 0
        if host:
            profile = self.host_profiles.get(host)
            if profile is None:
                host_pts += self.W_UNKNOWN_HOST
            else:
                host_pts += int(self.W_RARE_HOUR * 0.5 * self._hour_rarity(profile, hour))
                if (rule_id and rule_id not in profile['rule_ids']
                        and profile['event_count'] >= self.MIN_EVENTS_FOR_PROFILE):
                    host_pts += self.W_NEW_RULE_HOST
                if level and level > profile['max_level']:
                    host_pts += self.W_LEVEL_ESCALATION
        if host_pts:
            components['host'] = host_pts

        # --- Network deviations ---
        net_pts = 0
        if srcip and srcip not in self.known_srcips:
            net_pts += self.W_NEW_SRCIP
            if self._is_external_ip(srcip):
                net_pts += self.W_EXTERNAL_SRCIP
        if net_pts:
            components['network'] = net_pts

        return worst_user_pts + host_pts + net_pts, components

    def detect_anomaly(self, alert):
        """Return anomaly detection result for a single Wazuh alert.

        Same result contract as the IF and AE detectors so the ensemble can
        consume all three uniformly.
        """
        if not self.is_trained:
            return {'is_anomaly': False, 'anomaly_score': 0, 'confidence': 0,
                    'components': {}}
        try:
            raw, components = self.raw_score(alert)
            score = max(0, min(100, int(raw)))
            return {
                'is_anomaly': score >= self.anomaly_threshold,
                'anomaly_score': score,
                'confidence': abs(score - 50) * 2,
                'components': components,
            }
        except Exception as e:
            print(f"UEBA detection error: {e}")
            return {'is_anomaly': False, 'anomaly_score': 0, 'confidence': 0,
                    'components': {}}

    def score_event(self, alert):
        return self.detect_anomaly(alert)['anomaly_score']
