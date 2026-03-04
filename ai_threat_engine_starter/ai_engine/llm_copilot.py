"""
LLM Copilot - Optional LLM integration for advanced threat analysis
Requires LLM API (Ollama, OpenAI, etc.)
"""

import json
import requests
from typing import Dict, List, Optional


class LLMCopilot:

    def __init__(self, api_url: str = "http://localhost:11434/v1/chat/completions",
                 model: str = "llama3.2", timeout: int = 30):
        """
        Initialize LLM Copilot

        Args:
            api_url: LLM API endpoint (e.g., http://localhost:11434/v1/chat/completions for Ollama)
            model: Model name to use
            timeout: Request timeout in seconds
        """
        self.api_url = api_url
        self.model = model
        self.timeout = timeout
        self.enabled = self.test_connection()
        if self.enabled:
            print("LLM Copilot connected to " + api_url)
        else:
            print("Warning: LLM Copilot not available at " + api_url)

    def test_connection(self) -> bool:
        """Test if LLM API is available"""
        try:
            # Try Ollama tags endpoint
            health_url = self.api_url.replace('/v1/chat/completions', '/api/tags')
            response = requests.get(health_url, timeout=5)
            if response.status_code == 200:
                return True
        except:
            pass

        try:
            # Try a simple completion
            response = requests.post(
                self.api_url,
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": "test"}],
                },
                timeout=self.timeout
            )
            return response.status_code == 200
        except:
            return False

    def analyze_threat(self, event: Dict, threat_intel: List) -> Dict:
        """Use LLM to analyze threat and provide recommendations"""
        if not self.enabled:
            return self._fallback_analysis(event, threat_intel)

        # Build threat context
        threat_context = ""
        if threat_intel:
            parts = []
            for i, t in enumerate(threat_intel):
                parts.append(
                    "Known Threat " + str(i + 1) + ": " +
                    t.get('description', '') +
                    " (Severity: " + t.get('severity', '') +
                    ", Similarity: " + format(t.get('similarity', 0), '.2%') + ")"
                )
            threat_context = "\n".join(parts)
        else:
            threat_context = "No similar known threats found."

        prompt = (
            "You are an AI Security Analyst. Analyze this security event and provide recommendations.\n\n"
            "Event:\n" + json.dumps(event)[:1000] +
            "\n\nSimilar Known Threats:\n" + threat_context +
            "\n\nProvide a JSON response with:\n"
            "1. threat_level: \"LOW\", \"MEDIUM\", \"HIGH\", or \"CRITICAL\"\n"
            "2. confidence: 0-100 integer\n"
            "3. pattern_match: Brief description of matched pattern\n"
            "4. recommendations: Array of 2-3 actionable recommendations\n"
            "5. risk_assessment: One sentence risk assessment\n\n"
            "Format as JSON only, no additional text."
        )

        try:
            response = requests.post(
                self.api_url,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert. Always respond with valid JSON only."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 500
                },
                timeout=self.timeout
            )

            if response.status_code == 200:
                content = response.json().get('choices', [{}])[0].get('message', {}).get('content', '')

                # Extract JSON from response
                start = content.find('{')
                end = content.rfind('}')
                if start != -1 and end != -1:
                    return json.loads(content[start:end + 1])

            return self._fallback_analysis(event, threat_intel)
        except Exception as e:
            print(f"LLM API error: {e}")
            return self._fallback_analysis(event, threat_intel)

    def _fallback_analysis(self, event: Dict, threat_intel: List) -> Dict:
        """Fallback analysis when LLM is not available"""
        threat_level = "MEDIUM"
        confidence = 50

        if threat_intel:
            severity = threat_intel[0].get('severity', 'MEDIUM')
            if severity in ('CRITICAL', 'HIGH'):
                threat_level = "HIGH"
                confidence = 85 if severity == 'CRITICAL' else 70

        return {
            "threat_level": threat_level,
            "confidence": confidence,
            "pattern_match": "LLM analysis unavailable",
            "recommendations": ["Requires manual investigation"],
            "risk_assessment": "LLM analysis unavailable"
        }
