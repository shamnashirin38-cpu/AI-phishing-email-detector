"""
Ollama Local AI API Client.

Connects to the locally running Ollama daemon (default: http://localhost:11434).
Features:
- Service health & model presence checking
- Resilient JSON request and response parsing
- JSON repairing and sanitization (handles markdown code fences)
- Strict validation and score bounding
- Graceful degradation when Ollama is offline or times out (never crashes)
"""

import json
import logging
import re
import time
import requests
from app.ai.prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE

logger = logging.getLogger(__name__)


class OllamaClient:
    """Client for querying the local Ollama LLM service."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2:3b", timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def check_status(self) -> dict:
        """
        Pings Ollama server to verify if daemon is active and checks if the configured model is installed.
        Returns a descriptive status dictionary.
        """
        start_time = time.time()
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3)
            latency_ms = int((time.time() - start_time) * 1000)

            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                
                # Check if exact model or base name is available
                model_installed = any(
                    self.model == m or self.model in m or m.startswith(self.model.split(":")[0])
                    for m in models
                )

                if model_installed:
                    return {
                        "available": True,
                        "status": "online",
                        "base_url": self.base_url,
                        "selected_model": self.model,
                        "model_installed": True,
                        "available_models": models,
                        "latency_ms": latency_ms,
                        "message": f"Ollama is running and '{self.model}' is ready."
                    }
                else:
                    return {
                        "available": True,
                        "status": "model_missing",
                        "base_url": self.base_url,
                        "selected_model": self.model,
                        "model_installed": False,
                        "available_models": models,
                        "latency_ms": latency_ms,
                        "message": f"Ollama is running, but model '{self.model}' is not pulled yet. Run: 'ollama pull {self.model}'"
                    }
            else:
                return {
                    "available": False,
                    "status": "error",
                    "base_url": self.base_url,
                    "selected_model": self.model,
                    "model_installed": False,
                    "available_models": [],
                    "latency_ms": latency_ms,
                    "message": f"Ollama responded with HTTP {resp.status_code}."
                }
        except requests.exceptions.ConnectionError:
            return {
                "available": False,
                "status": "offline",
                "base_url": self.base_url,
                "selected_model": self.model,
                "model_installed": False,
                "available_models": [],
                "latency_ms": None,
                "message": "Ollama local service is not running. Please start Ollama via 'ollama serve'."
            }
        except requests.exceptions.Timeout:
            return {
                "available": False,
                "status": "timeout",
                "base_url": self.base_url,
                "selected_model": self.model,
                "model_installed": False,
                "available_models": [],
                "latency_ms": None,
                "message": "Connection to Ollama timed out after 3 seconds."
            }
        except Exception as e:
            return {
                "available": False,
                "status": "error",
                "base_url": self.base_url,
                "selected_model": self.model,
                "model_installed": False,
                "available_models": [],
                "latency_ms": None,
                "message": f"Error contacting Ollama: {str(e)}"
            }

    def analyze_email(self, sender: str, subject: str, body: str, rule_indicators: list = None) -> dict:
        """
        Sends email content to local Ollama model with structured JSON prompting.
        Returns a validated dictionary of AI findings, or a graceful fallback if Ollama is unavailable.
        """
        # Format rule context for LLM if available
        rule_context = ""
        if rule_indicators:
            indicator_names = [f"- {ind['name']} ({ind['severity']})" for ind in rule_indicators]
            rule_context = "--- PRELIMINARY RULE INDICATORS DETECTED ---\n" + "\n".join(indicator_names)

        user_prompt = USER_PROMPT_TEMPLATE.format(
            sender=sender or "Not provided",
            subject=subject or "No subject",
            body=(body[:4000] if body else "No email body provided"),
            rule_context=rule_context
        )

        payload = {
            "model": self.model,
            "system": SYSTEM_PROMPT,
            "prompt": user_prompt,
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 512
            }
        }

        start_time = time.time()
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            elapsed_sec = round(time.time() - start_time, 2)

            if response.status_code != 200:
                logger.warning(f"Ollama returned HTTP status {response.status_code}")
                return self._fallback_response(
                    f"Ollama returned HTTP error {response.status_code}: {response.text[:200]}",
                    status="http_error"
                )

            data = response.json()
            raw_ai_text = data.get("response", "").strip()
            
            # Parse and validate structured output
            parsed_data = self._clean_and_parse_json(raw_ai_text)
            validated_result = self._validate_ai_response(parsed_data)
            validated_result["available"] = True
            validated_result["status"] = "success"
            validated_result["model"] = self.model
            validated_result["response_time_sec"] = elapsed_sec
            return validated_result

        except requests.exceptions.ConnectionError:
            return self._fallback_response(
                "Ollama daemon is offline. Start the service using 'ollama serve' and ensure model is installed.",
                status="offline"
            )
        except requests.exceptions.Timeout:
            return self._fallback_response(
                f"Ollama analysis timed out after {self.timeout} seconds. The local machine may be under heavy load.",
                status="timeout"
            )
        except Exception as e:
            logger.error(f"Unexpected error in Ollama client: {str(e)}", exc_info=True)
            return self._fallback_response(
                f"AI analysis encountered an unexpected error: {str(e)}",
                status="error"
            )

    def _clean_and_parse_json(self, raw_text: str) -> dict:
        """Strips markdown code blocks, fixes common trailing characters, and parses JSON."""
        cleaned = raw_text.strip()
        # Remove markdown code fences if present
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
        
        # Extract the outermost JSON object if surrounded by preamble/postscript
        json_match = re.search(r'(\{[\s\S]*\})', cleaned)
        if json_match:
            cleaned = json_match.group(1)

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Fallback regex extraction for robust recovery
            verdict_match = re.search(r'"verdict"\s*:\s*"([^"]+)"', cleaned)
            score_match = re.search(r'"ai_risk_score"\s*:\s*(\d+)', cleaned)
            conf_match = re.search(r'"confidence"\s*:\s*([0-9.]+)', cleaned)
            reason_match = re.search(r'"reasoning"\s*:\s*"([^"]+)"', cleaned)

            return {
                "verdict": verdict_match.group(1) if verdict_match else "Suspicious",
                "ai_risk_score": int(score_match.group(1)) if score_match else 20,
                "confidence": float(conf_match.group(1)) if conf_match else 0.5,
                "reasoning": reason_match.group(1) if reason_match else "Partial AI output parsed from response.",
                "evidence": ["AI raw response formatted with irregularities"],
                "recommended_actions": ["Review email manually with caution"]
            }

    def _validate_ai_response(self, data: dict) -> dict:
        """Validates types and clamps numeric ranges for the AI output."""
        # 1. Verdict
        verdict = str(data.get("verdict", "Suspicious")).capitalize()
        if verdict not in ["Safe", "Suspicious", "Phishing"]:
            verdict = "Suspicious"

        # 2. AI Risk Score (0 - 40)
        try:
            ai_score = int(data.get("ai_risk_score", 20))
            ai_score = max(0, min(40, ai_score))
        except (ValueError, TypeError):
            ai_score = 20

        # 3. Confidence (0.0 - 1.0)
        try:
            confidence = float(data.get("confidence", 0.7))
            confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 0.7

        # 4. Reasoning
        reasoning = str(data.get("reasoning", "No detailed reasoning provided by the AI model."))

        # 5. Evidence
        evidence = data.get("evidence", [])
        if not isinstance(evidence, list):
            evidence = [str(evidence)]
        evidence = [str(e) for e in evidence if str(e).strip()]

        # 6. Recommended Actions
        actions = data.get("recommended_actions", [])
        if not isinstance(actions, list):
            actions = [str(actions)]
        actions = [str(a) for a in actions if str(a).strip()]

        return {
            "verdict": verdict,
            "ai_risk_score": ai_score,
            "confidence": round(confidence, 2),
            "reasoning": reasoning,
            "evidence": evidence,
            "recommended_actions": actions
        }

    def _fallback_response(self, error_message: str, status: str = "offline") -> dict:
        """Returns a non-crashing fallback dictionary when Ollama cannot be reached."""
        return {
            "available": False,
            "status": status,
            "model": self.model,
            "ai_risk_score": None,
            "confidence": None,
            "verdict": "Unavailable",
            "reasoning": f"Local AI analysis was unavailable: {error_message}",
            "evidence": ["AI service offline - relied strictly on Rule-Based engine"],
            "recommended_actions": [
                "Verify sender identity through independent out-of-band communication",
                "Ensure local Ollama service is running via 'ollama serve'",
                "Do not click unverified links or enter credentials"
            ],
            "error": error_message
        }
