"""
Pattern Analyzer - Detects known attack patterns
Analyzes text from RAG (threat intelligence) to identify attack types
"""

import re
from typing import Dict, List, Optional


class PatternAnalyzer:

    def __init__(self):
        """Initialize pattern analyzer with known attack patterns"""
        self.patterns = [
            {
                'name': 'SSH Brute Force',
                'pattern': r'(?i)(failed|invalid|authentication failure).*(ssh|login)',
                'description': 'Multiple failed authentication attempts',
                'risk_score': 75
            },
            {
                'name': 'SQL Injection',
                'pattern': r"(?i)(union.*select|drop.*table|';.*--|exec.*xp_)",
                'description': 'Potential SQL injection attempt',
                'risk_score': 90
            },
            {
                'name': 'PowerShell Obfuscation',
                'pattern': r'(?i)(powershell.*-enc|base64|encoded|obfuscat)',
                'description': 'Suspicious PowerShell execution',
                'risk_score': 85
            },
            {
                'name': 'Port Scanning',
                'pattern': r'(?i)(port.*scan|connection.*refused|multiple.*ports)',
                'description': 'Potential port scanning activity',
                'risk_score': 60
            },
            {
                'name': 'Privilege Escalation',
                'pattern': r'(?i)(sudo|su -|privilege|escalation|root.*access)',
                'description': 'Privilege escalation attempt',
                'risk_score': 80
            },
            {
                'name': 'File Integrity Violation',
                'pattern': r'(?i)(file.*modified|integrity.*violation|checksum.*mismatch)',
                'description': 'File integrity check failure',
                'risk_score': 85
            },
            {
                'name': 'Malware Execution',
                'pattern': r'(?i)(malware|virus|trojan|backdoor|rootkit)',
                'description': 'Potential malware activity',
                'risk_score': 95
            },
            {
                'name': 'Lateral Movement',
                'pattern': r'(?i)(lateral.*movement|psexec|wmic|remote.*execution)',
                'description': 'Potential lateral movement',
                'risk_score': 80
            },
            {
                'name': 'Data Exfiltration',
                'pattern': r'(?i)(exfiltrat|data.*export|large.*transfer|unauthorized.*access)',
                'description': 'Potential data exfiltration',
                'risk_score': 90
            },
            {
                'name': 'Command Injection',
                'pattern': r'(?i)(;.*rm|;.*cat|;.*wget|command.*injection)',
                'description': 'Potential command injection',
                'risk_score': 85
            },
        ]

    def analyze(self, event: Dict) -> Dict:
        """
        Analyze event for known attack patterns (legacy method)
        For new implementation, use analyze_rag_text()
        """
        message = str(event.get('message', ''))
        if not message:
            message = str(event.get('data', ''))
        return self._analyze_text(message)

    def analyze_rag_text(self, threat_intel_results: List) -> Dict:
        """
        Analyze text from RAG (threat intelligence) to identify attack patterns

        Args:
            threat_intel_results: List of threat intelligence results from RAG
                Each dict should have:
                - 'description': str - threat description text
                - 'severity': str - threat severity
                - 'similarity': float - similarity score from RAG (0-1)
                - 'ioc': list - indicators of compromise (optional)
                - 'mitigation': str - mitigation steps (optional)

        Returns:
            dict with pattern identification results:
            - 'pattern': str - identified pattern name
            - 'risk_score': int - risk score (0-100)
            - 'confidence': float - confidence from RAG similarity (0-1)
            - 'description': str - pattern description
            - 'matched_threats': list - threats that matched
            - 'severity': str - severity from RAG
        """
        if not threat_intel_results:
            return {
                'pattern': 'No known pattern',
                'risk_score': 0,
                'confidence': 0.0,
                'description': 'No threat intelligence found',
                'matched_threats': [],
                'severity': 'LOW',
                'suspicious': False,
                'pattern_matches': 0,
                'all_patterns': []
            }

        # Combine all RAG descriptions into one text
        combined_text = self._combine_rag_descriptions(threat_intel_results)

        # Analyze combined text
        result = self._analyze_text(combined_text)

        # Get RAG confidence (similarity score)
        confidence = threat_intel_results[0].get('similarity', 0.0)
        severity = threat_intel_results[0].get('severity', 'MEDIUM')

        # Boost risk score based on severity
        risk_score = result.get('risk_score', 0)
        if severity == 'CRITICAL':
            risk_score = int(min(risk_score + 15, 100))
        elif severity == 'HIGH':
            risk_score = int(min(risk_score + 10, 100))
        elif severity == 'MEDIUM':
            risk_score = int(min(risk_score + 5, 100))

        result['confidence'] = confidence
        result['severity'] = severity
        result['risk_score'] = risk_score
        result['matched_threats'] = threat_intel_results[:3]
        result['suspicious'] = risk_score > 70 or confidence > 0.7

        return result

    def _combine_rag_descriptions(self, threat_intel_results: List) -> str:
        """
        Combine threat descriptions from RAG into a single text for analysis

        Args:
            threat_intel_results: List of threat intelligence results

        Returns:
            Combined text string
        """
        parts = []
        for result in threat_intel_results:
            description = result.get('description', '')
            if description:
                parts.append(description)
            ioc = result.get('ioc', '')
            if ioc:
                if isinstance(ioc, list):
                    parts.append(' '.join(ioc))
                else:
                    parts.append(str(ioc))
            mitigation = result.get('mitigation', '')
            if mitigation:
                parts.append(mitigation)
        return ' '.join(parts).lower()

    def _analyze_text(self, text: str) -> Dict:
        """
        Analyze text and identify matching patterns

        Args:
            text: Text to analyze (lowercase)

        Returns:
            dict with pattern analysis results
        """
        text = text.lower()
        matched = []

        for p in self.patterns:
            if re.search(p['pattern'], text):
                matched.append(p)

        if matched:
            # Return highest risk pattern
            best = max(matched, key=lambda x: x['risk_score'])
            return {
                'pattern': best['name'],
                'risk_score': best['risk_score'],
                'description': best['description'],
                'pattern_matches': len(matched),
                'all_patterns': [m['name'] for m in matched],
                'suspicious': True
            }

        return {
            'pattern': 'No known pattern',
            'risk_score': 0,
            'description': 'No matching attack pattern detected',
            'pattern_matches': 0,
            'all_patterns': [],
            'suspicious': False
        }
