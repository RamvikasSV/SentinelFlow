import asyncio
from typing import Dict, Any, List
from backend.simulator import ServerAdapter
from backend.broker import broker, Event

class ForensicInvestigatorAgent:
    def __init__(self, server: ServerAdapter):
        self.server = server
        self.running = False
        self.queue_task = None

    async def start(self):
        self.running = True
        self.queue_task = asyncio.create_task(self._process_queue())
        await broker.publish(Event(
            event_type="agent_thought",
            source="forensics_investigator",
            data={"text": "Forensic Investigator Agent active. Ready to run system scans..."}
        ))

    async def stop(self):
        self.running = False
        if self.queue_task:
            self.queue_task.cancel()

    async def _process_queue(self):
        threat_queue = broker.subscribe("threat_classification")
        try:
            while self.running:
                event: Event = await threat_queue.get()
                if event.data.get("requires_investigation", False):
                    asyncio.create_task(self._run_forensics(event))
                threat_queue.task_done()
        except asyncio.CancelledError:
            pass
        finally:
            broker.unsubscribe("threat_classification", threat_queue)

    async def _run_forensics(self, event: Event):
        ip = event.data.get("ip")
        category = event.data.get("category")
        severity = event.data.get("severity")
        trigger_alert = event.data.get("trigger_alert", {})
        
        await broker.publish(Event(
            event_type="agent_thought",
            source="forensics_investigator",
            data={"text": f"Initiating live forensics on target server for IP: {ip}. Category: {category}."}
        ))
        
        # Simulating analysis delay
        await asyncio.sleep(1.5)
        
        # 1. Investigate running processes
        suspicious_processes = []
        try:
            processes = await self.server.get_processes()
            for p in processes:
                cmd = p["cmd"].lower()
                # Check for reverse shell indicators, bash executions by daemon users, or suspicious binaries
                is_suspicious = False
                if any(ind in cmd for ind in ["/bin/sh", "/bin/bash", "nc -e", "netcat", "/dev/tcp"]):
                    is_suspicious = True
                if "backdoor" in cmd or "shell.php" in cmd or "backdoor.php" in cmd:
                    is_suspicious = True
                # www-data user running bash/sh is highly abnormal in web environments
                if p["user"] in ["www-data", "nginx", "apache"] and any(sh in cmd for sh in ["sh", "bash", "python", "perl"]):
                    is_suspicious = True
                    
                if is_suspicious:
                    suspicious_processes.append(p)
        except Exception as e:
            await broker.publish(Event(
                event_type="agent_thought",
                source="forensics_investigator",
                data={"text": f"Forensics process scan failed: {e}"}
            ))

        # 2. Investigate active socket connections
        suspicious_sockets = []
        try:
            sockets = await self.server.get_active_connections()
            for s in sockets:
                remote = s["remote"]
                # Sockets talking to attacker IP or listening on reverse shell standard ports (e.g. 4444)
                is_suspicious = False
                if remote.startswith(f"{ip}:") or ":4444" in remote:
                    is_suspicious = True
                
                # Check if it connects to standard attacker ranges
                if is_suspicious:
                    suspicious_sockets.append(s)
        except Exception as e:
            await broker.publish(Event(
                event_type="agent_thought",
                source="forensics_investigator",
                data={"text": f"Forensics socket scan failed: {e}"}
            ))

        # 3. Investigate recently modified files
        suspicious_files = []
        try:
            # Check last 10 minutes in web root and etc directory
            web_files = await self.server.get_modified_files("/var/www", minutes=10)
            etc_files = await self.server.get_modified_files("/etc", minutes=10)
            
            for f in (web_files + etc_files):
                # Backdoors, altered configs, or scripts modified recently
                path = f["path"].lower()
                is_suspicious = False
                if any(ind in path for ind in ["backdoor", "shell", ".php", "sudoers", "passwd", "shadow"]):
                    is_suspicious = True
                    
                if is_suspicious:
                    suspicious_files.append(f)
        except Exception as e:
            await broker.publish(Event(
                event_type="agent_thought",
                source="forensics_investigator",
                data={"text": f"Forensics file scan failed: {e}"}
            ))

        # 4. Generate forensic report & publish
        findings_summary = (
            f"Forensics completed. Sockets={len(suspicious_sockets)}, "
            f"Processes={len(suspicious_processes)}, Files={len(suspicious_files)}."
        )
        
        await broker.publish(Event(
            event_type="agent_thought",
            source="forensics_investigator",
            data={"text": f"{findings_summary} Routing evidence to Response Agent."}
        ))
        
        # Publish Forensic Report
        await broker.publish(Event(
            event_type="forensic_investigation",
            source="forensics_investigator",
            severity=severity,
            data={
                "ip": ip,
                "category": category,
                "findings": {
                    "processes": suspicious_processes,
                    "sockets": suspicious_sockets,
                    "files": suspicious_files
                },
                "summary": findings_summary,
                "trigger_classification": event.data
            }
        ))
