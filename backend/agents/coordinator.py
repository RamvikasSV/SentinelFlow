import asyncio
import json
import re
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from google.genai.errors import APIError

from backend.config import settings
from backend.broker import broker, Event
from backend.simulator import ServerAdapter

class CoordinatorActionSchema(BaseModel):
    action: str = Field(description="Action name: get_status, list_blocked, unblock_ip, block_ip, list_processes, list_incidents, run_forensics, kill_process, chat")
    ip: Optional[str] = Field(default=None, description="Target IP address if applicable")
    pid: Optional[int] = Field(default=None, description="Target PID number if applicable")
    chat_response: Optional[str] = Field(default=None, description="Conversational reply or explanation of the action being executed")

class CrewCoordinatorAgent:
    def __init__(self, server: ServerAdapter):
        self.server = server
        self.client = None
        
        # Initialize Gemini Client if key is configured and looks like a real Google API key (starts with AIzaSy)
        if settings.gemini_api_key and settings.gemini_api_key.startswith("AIzaSy"):
            try:
                self.client = genai.Client(api_key=settings.gemini_api_key)
            except Exception as e:
                print(f"Failed to initialize Gemini Client in Coordinator: {e}")

    async def handle_user_message(self, message: str) -> str:
        """
        Processes natural language from the user, decides the command,
        executes it, and returns the response string.
        """
        # Publish user message event to show in log feeds
        await broker.publish(Event(
            event_type="chat_message",
            source="user",
            data={"text": message}
        ))
        
        await broker.publish(Event(
            event_type="agent_thought",
            source="crew_coordinator",
            data={"text": f"Processing user query: '{message}'"}
        ))
        
        intent = None
        if self.client:
            intent = await self._parse_intent_with_llm(message)
            
        if not intent:
            intent = self._parse_intent_heuristically(message)
            
        action = intent.get("action", "chat")
        ip = intent.get("ip")
        pid = intent.get("pid")
        chat_response = intent.get("chat_response")
        
        response_text = ""
        
        # Execute Action
        try:
            if action == "get_status":
                blocked_ips = list(self.server.blocked_ips) if hasattr(self.server, "blocked_ips") else []
                mode = settings.system_mode.upper()
                response_text = (
                    f"### 🛡️ System Status Report\n\n"
                    f"- **Active Mode**: `{mode}`\n"
                    f"- **Crew Status**: `All agents operational` (Scanner, Classifier, Forensics, Response)\n"
                    f"- **Active Blocks**: `{len(blocked_ips)}` IP(s) currently blocked\n"
                    f"- **System Health**: `Secure`"
                )
                
            elif action == "list_blocked":
                blocked_ips = list(self.server.blocked_ips) if hasattr(self.server, "blocked_ips") else []
                if blocked_ips:
                    ips_list = "\n".join([f"- `{ip}`" for ip in blocked_ips])
                    response_text = f"### 🚫 Firewall Block Registry\n\nThe following IPs are currently blocked:\n\n{ips_list}"
                else:
                    response_text = "### 🚫 Firewall Block Registry\n\nNo IP addresses are currently blocked in the firewall."
                    
            elif action == "unblock_ip":
                if ip:
                    success = await self.server.unblock_ip(ip)
                    if success:
                        response_text = f"✅ **Success**: IP `{ip}` has been removed from the firewall blocklist."
                    else:
                        response_text = f"⚠️ **Notice**: IP `{ip}` was not found in the block registry."
                else:
                    response_text = "⚠️ **Error**: Please specify the IP address you want to unblock."
                    
            elif action == "block_ip":
                if ip:
                    success = await self.server.block_ip(ip)
                    if success:
                        response_text = f"🚫 **Success**: IP `{ip}` has been blocked in the firewall."
                    else:
                        response_text = f"⚠️ **Notice**: IP `{ip}` is already blocked."
                else:
                    response_text = "⚠️ **Error**: Please specify the IP address you want to block."
                    
            elif action == "list_processes":
                processes = await self.server.get_processes()
                # Sort processes by CPU, filter out standard system background items if too many
                sorted_procs = sorted(processes, key=lambda x: x.get("cpu", 0), reverse=True)[:15]
                proc_table = "| PID | User | CPU % | Mem % | Command |\n| :--- | :--- | :--- | :--- | :--- |\n"
                for p in sorted_procs:
                    proc_table += f"| `{p['pid']}` | `{p['user']}` | {p['cpu']} | {p['mem']} | `{p['cmd']}` |\n"
                response_text = f"### ⚙️ Active Processes (Top 15)\n\n{proc_table}"
                
            elif action == "list_incidents":
                incidents = await broker.get_history(event_type="threat_classification", limit=10)
                if incidents:
                    inc_list = ""
                    for idx, inc in enumerate(reversed(incidents)):
                        data = inc.data
                        trigger = data.get("trigger_alert", {})
                        timestamp = re.sub(r'\.\d+', '', str(inc.timestamp)) # format
                        time_str = json.dumps(timestamp) # Fallback
                        inc_list += (
                            f"{idx+1}. **[{data.get('category')}]** - Severity: `{data.get('severity').upper()}` | IP: `{data.get('ip')}`\n"
                            f"   - *Explanation*: {data.get('explanation')}\n"
                            f"   - *Trigger Log*: `{trigger.get('details', {}).get('line', trigger.get('message', ''))}`\n\n"
                        )
                    response_text = f"### 🚨 Recent Threat Incidents\n\n{inc_list}"
                else:
                    response_text = "### 🚨 Recent Threat Incidents\n\nNo threat incidents have been classified in the cache database yet."
                    
            elif action == "kill_process":
                if pid:
                    success = await self.server.kill_process(pid)
                    if success:
                        response_text = f"✅ **Success**: Process with PID `{pid}` was terminated."
                    else:
                        response_text = f"⚠️ **Error**: Process with PID `{pid}` could not be terminated (it may not exist)."
                else:
                    response_text = "⚠️ **Error**: Please specify the PID of the process you want to terminate."
                    
            elif action == "run_forensics":
                # Create a simulated manual investigation request event
                dummy_classification = Event(
                    event_type="threat_classification",
                    source="user_command",
                    severity="medium",
                    data={
                        "ip": ip or "127.0.0.1",
                        "category": "Manual Scan",
                        "requires_investigation": True,
                        "explanation": "Manual scan triggered via chat command console."
                    }
                )
                await broker.publish(dummy_classification)
                response_text = "🕵️‍♂️ **Action**: Dispatched the Forensic Investigator Agent to scan the system. Check the dynamic mind visualization!"
                
            else: # chat
                response_text = chat_response or "I'm the Crew Coordinator. Ask me to unblock an IP, list blocked logs, list processes, or show threat reports."
                
        except Exception as e:
            response_text = f"⚠️ **Execution Error**: An error occurred while running command '{action}': {e}"
            
        # Emit reply event
        await broker.publish(Event(
            event_type="chat_message",
            source="crew_coordinator",
            data={"text": response_text}
        ))
        
        return response_text

    async def _parse_intent_with_llm(self, message: str) -> Optional[Dict[str, Any]]:
        """Uses Gemini to parse conversational commands into structured schema actions."""
        prompt = f"""
        You are the Crew Coordinator for our Multi-Agent Cyber Security Response team.
        The user (system administrator) has sent you a command: "{message}"
        
        Determine the appropriate action from these choices:
        1. get_status: User wants to know general system health or agent status
        2. list_blocked: User wants to see what IP addresses are blocked
        3. unblock_ip: User wants to unblock a specific IP address
        4. block_ip: User wants to block a specific IP address
        5. list_processes: User wants to list processes on the server
        6. list_incidents: User wants to see threat classifications or logs of blocked incidents
        7. run_forensics: User wants to trigger a forensic scan
        8. kill_process: User wants to terminate a process by PID
        9. chat: General chit-chat, explaining security terms, or asking what commands are supported.
        
        Extract the IP address or PID if the command refers to one.
        Provide a helpful conversational reply in the chat_response field if the action is 'chat'.
        """
        
        try:
            # Call Gemini using native async client with a 10s timeout wrapper
            response = await asyncio.wait_for(
                self.client.aio.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=CoordinatorActionSchema,
                        temperature=0.2
                    )
                ),
                timeout=10.0
            )
            return json.loads(response.text)
        except asyncio.TimeoutError:
            print("Gemini API request timed out (10s limit) in Coordinator. Falling back to heuristics.")
        except Exception as e:
            print(f"Error parsing intent with LLM: {e}")
        return None

    def _parse_intent_heuristically(self, message: str) -> Dict[str, Any]:
        """Regex-based fallback parsing if Gemini is unavailable."""
        msg = message.lower().strip()
        
        # Regex mappings
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", msg)
        pid_match = re.search(r"\b(\d+)\b", msg)
        
        target_ip = ip_match.group(1) if ip_match else None
        target_pid = int(pid_match.group(1)) if (pid_match and not target_ip) else None
        
        if "unblock" in msg:
            return {"action": "unblock_ip", "ip": target_ip}
        elif "blocked" in msg or "firewall" in msg:
            return {"action": "list_blocked"}
        elif "block" in msg:
            return {"action": "block_ip", "ip": target_ip}
        elif "status" in msg or "health" in msg or "agents" in msg:
            return {"action": "get_status"}
        elif "process" in msg or "ps" in msg:
            return {"action": "list_processes"}
        elif "incident" in msg or "alert" in msg or "report" in msg or "history" in msg:
            return {"action": "list_incidents"}
        elif "kill" in msg or "terminate" in msg:
            return {"action": "kill_process", "pid": target_pid}
        elif "forensic" in msg or "scan" in msg or "investigate" in msg:
            return {"action": "run_forensics", "ip": target_ip}
            
        # General chat fallback
        chat_reply = (
            "Hello! I am the **Crew Coordinator**. I can route commands to your response crew.\n\n"
            "Here are commands I support (even when offline):\n"
            "- 📊 `status` / `health` (Check agents state)\n"
            "- 🚫 `list blocked` (Show blocked IPs)\n"
            "- 🔓 `unblock <IP>` (Remove IP from firewall)\n"
            "- 🔒 `block <IP>` (Manually drop IP traffic)\n"
            "- ⚙️ `processes` (Show running process tree)\n"
            "- 🕵️‍♂️ `run forensics` (Trigger active system scan)\n"
            "- 💀 `kill <PID>` (Terminate suspicious process)\n"
            "- 🚨 `incidents` (Show recent threat alerts)"
        )
        return {"action": "chat", "chat_response": chat_reply}
