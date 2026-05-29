import asyncio
import json
import time
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from google.genai.errors import APIError

from backend.config import settings
from backend.broker import broker, Event

class ThreatResponseSchema(BaseModel):
    category: str = Field(description="Security category: SSH Brute Force, Web Exploit, Privilege Escalation, Scanning, False Positive")
    severity: str = Field(description="Severity grade: low, medium, high, critical")
    confidence: float = Field(description="Confidence rating from 0.0 to 1.0")
    explanation: str = Field(description="Explanation of the threat classification")
    requires_investigation: bool = Field(description="True if severity is medium, high or critical and needs forensics")

class ThreatClassifierAgent:
    def __init__(self):
        self.running = False
        self.queue_task = None
        self.client = None
        self.alert_history: Dict[str, List[Dict[str, Any]]] = {} # IP -> list of recent alert data
        
        # Initialize Gemini client if key is present and looks like a real Google API key (starts with AIzaSy)
        if settings.gemini_api_key and settings.gemini_api_key.startswith("AIzaSy"):
            try:
                self.client = genai.Client(api_key=settings.gemini_api_key)
            except Exception as e:
                print(f"Failed to initialize Gemini Client: {e}")

    async def start(self):
        self.running = True
        self.queue_task = asyncio.create_task(self._process_queue())
        await broker.publish(Event(
            event_type="agent_thought",
            source="threat_classifier",
            data={"text": "Threat Classifier Agent active. Listening for log alerts..."}
        ))

    async def stop(self):
        self.running = False
        if self.queue_task:
            self.queue_task.cancel()
            
    async def _process_queue(self):
        alert_queue = broker.subscribe("log_alert")
        try:
            while self.running:
                event: Event = await alert_queue.get()
                asyncio.create_task(self._analyze_alert(event))
                alert_queue.task_done()
        except asyncio.CancelledError:
            pass
        finally:
            broker.unsubscribe("log_alert", alert_queue)

    async def _analyze_alert(self, event: Event):
        ip = event.data.get("ip", "unknown")
        alert_type = event.data.get("alert_type")
        message = event.data.get("message")
        details = event.data.get("details", {})
        
        # 1. Update IP history context (keep last 10 alerts in 60s window)
        now = time.time()
        if ip not in self.alert_history:
            self.alert_history[ip] = []
        self.alert_history[ip].append({
            "timestamp": now,
            "type": alert_type,
            "message": message,
            "details": details
        })
        # Clean old alerts (> 60s)
        self.alert_history[ip] = [a for a in self.alert_history[ip] if now - a["timestamp"] < 60]
        
        # Group similar alerts for classification context
        ip_alerts = self.alert_history[ip]
        alert_count = len(ip_alerts)

        await broker.publish(Event(
            event_type="agent_thought",
            source="threat_classifier",
            data={"text": f"Analyzing threat profile for IP: {ip}. Active alerts in 60s window: {alert_count}"}
        ))
        
        # 2. Run Classification (LLM or Fallback)
        classification = None
        if self.client:
            classification = await self._query_gemini(ip, ip_alerts)
            
        if not classification:
            # Fallback to local heuristic classifier if LLM failed or isn't configured
            classification = self._heuristic_classify(ip, alert_type, alert_count, details)

        # 3. Publish findings
        severity = classification.get("severity", "low")
        category = classification.get("category", "False Positive")
        explanation = classification.get("explanation", "")
        requires_investigation = classification.get("requires_investigation", False)
        
        await broker.publish(Event(
            event_type="threat_classification",
            source="threat_classifier",
            severity=severity,
            data={
                "ip": ip,
                "category": category,
                "confidence": classification.get("confidence", 0.5),
                "explanation": explanation,
                "requires_investigation": requires_investigation,
                "alert_count": alert_count,
                "trigger_alert": event.data
            }
        ))
        
        thought_msg = f"Classification complete for {ip}: Category={category}, Severity={severity.upper()}."
        if requires_investigation:
            thought_msg += " Dispatching Forensic Investigator Agent."
        else:
            thought_msg += " Action threshold not reached."
            
        await broker.publish(Event(
            event_type="agent_thought",
            source="threat_classifier",
            data={"text": thought_msg}
        ))

    async def _query_gemini(self, ip: str, ip_alerts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Queries Gemini LLM for cognitive log categorization and severity grading."""
        # Convert alerts list to a formatted string
        alert_dump = json.dumps([
            {"timestamp": datetime.fromtimestamp(a["timestamp"]).strftime('%Y-%m-%d %H:%M:%S'), 
             "type": a["type"], "message": a["message"], "line": a["details"].get("line")}
            for a in ip_alerts
        ], indent=2)
        
        prompt = f"""
        You are an expert Cyber Security Threat Intelligence Agent.
        Analyze the following real-time alert logs generated by our system for IP: {ip}.
        Based on the frequency, log lines, and attack indicators, classify the activity.
        
        Alert Logs:
        {alert_dump}
        """

        try:
            # Call Gemini using the native async client with a 10s timeout wrapper
            response = await asyncio.wait_for(
                self.client.aio.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=ThreatResponseSchema,
                        temperature=0.1
                    )
                ),
                timeout=10.0
            )
            
            result = json.loads(response.text)
            return result
        except asyncio.TimeoutError:
            await broker.publish(Event(
                event_type="agent_thought",
                source="threat_classifier",
                data={"text": "Gemini API request timed out (10s limit). Switching to local heuristic engine."}
            ))
        except APIError as e:
            # Google API Specific errors (auth, quota, network)
            await broker.publish(Event(
                event_type="agent_thought",
                source="threat_classifier",
                data={"text": f"Gemini API Error: {e.message}. Switching to local heuristic engine."}
            ))
        except Exception as e:
            await broker.publish(Event(
                event_type="agent_thought",
                source="threat_classifier",
                data={"text": f"Error running LLM threat classification: {e}. Switching to local heuristic engine."}
            ))
        return None

    def _heuristic_classify(self, ip: str, alert_type: str, count: int, details: dict) -> Dict[str, Any]:
        """Local rule-based classification fallback."""
        category = "False Positive"
        severity = "low"
        confidence = 0.6
        explanation = "Classified using local regex/frequency rule heuristic engine."
        requires_investigation = False
        
        if alert_type == "ssh_failed_login":
            if count >= 6:
                category = "SSH Brute Force"
                severity = "critical"
                requires_investigation = True
                explanation = f"Critical SSH brute force signature detected. {count} failed login attempts from {ip} in under 60 seconds."
            elif count >= 3:
                category = "SSH Brute Force"
                severity = "high"
                requires_investigation = True
                explanation = f"High SSH brute force signature. {count} failed login attempts from {ip} in under 60 seconds."
            else:
                category = "Reconnaissance"
                severity = "medium"
                requires_investigation = True
                explanation = f"Low-frequency SSH failed login attempts ({count}) from {ip}."
                
        elif alert_type == "web_exploit_attempt":
            category = "Web Exploit"
            severity = "high"
            requires_investigation = True
            explanation = f"Web application exploit attempt matching known signature (e.g. webshell command/payload) detected from {ip}."
            
        elif alert_type == "sudo_auth_fail":
            category = "Privilege Escalation"
            severity = "critical"
            requires_investigation = True
            explanation = f"Unauthorized local root command execution by compromised user: '{details.get('user')}' executing '{details.get('command')}'."
            
        elif alert_type == "web_scan":
            category = "Scanning"
            severity = "low"
            requires_investigation = False
            explanation = f"Low severity probe for configuration files on sensitive web path: '{details.get('path')}'."
            
        return {
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "explanation": explanation,
            "requires_investigation": requires_investigation
        }
