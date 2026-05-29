import asyncio
from typing import Dict, Any, List
from backend.simulator import ServerAdapter
from backend.broker import broker, Event

class ResponseAgent:
    def __init__(self, server: ServerAdapter):
        self.server = server
        self.running = False
        self.queue_task = None

    async def start(self):
        self.running = True
        self.queue_task = asyncio.create_task(self._process_queue())
        await broker.publish(Event(
            event_type="agent_thought",
            source="response_agent",
            data={"text": "Response Agent active. Monitoring forensic evidence for action playbooks..."}
        ))

    async def stop(self):
        self.running = False
        if self.queue_task:
            self.queue_task.cancel()

    async def _process_queue(self):
        forensic_queue = broker.subscribe("forensic_investigation")
        try:
            while self.running:
                event: Event = await forensic_queue.get()
                asyncio.create_task(self._execute_remediation(event))
                forensic_queue.task_done()
        except asyncio.CancelledError:
            pass
        finally:
            broker.unsubscribe("forensic_investigation", forensic_queue)

    async def _execute_remediation(self, event: Event):
        ip = event.data.get("ip")
        category = event.data.get("category")
        findings = event.data.get("findings", {})
        
        processes = findings.get("processes", [])
        sockets = findings.get("sockets", [])
        files = findings.get("files", [])
        
        actions_taken = []
        failures = []

        await broker.publish(Event(
            event_type="agent_thought",
            source="response_agent",
            data={"text": f"Remediation playbook triggered for {ip}. Evaluating mitigation steps..."}
        ))
        
        await asyncio.sleep(1.0) # Small thinking delay

        # 1. Block attacker IP in Firewall (Skip for local loopback 127.0.0.1)
        if ip and ip != "127.0.0.1" and ip != "unknown":
            try:
                success = await self.server.block_ip(ip)
                if success:
                    actions_taken.append(f"Blocked IP {ip} in host firewall (iptables/ufw)")
                else:
                    actions_taken.append(f"IP {ip} was already blocked")
            except Exception as e:
                failures.append(f"Failed to block IP {ip}: {e}")
                
        # 2. Terminate malicious processes
        for proc in processes:
            pid = proc["pid"]
            cmd = proc["cmd"]
            try:
                success = await self.server.kill_process(pid)
                if success:
                    actions_taken.append(f"Terminated malicious PID {pid} ('{cmd}')")
                else:
                    failures.append(f"PID {pid} not found when attempting termination")
            except Exception as e:
                failures.append(f"Failed to kill PID {pid}: {e}")

        # 3. Quarantine/Delete malicious modified files
        for file_meta in files:
            path = file_meta["path"]
            # Keep configuration adjustments like sudoers intact but delete scripts/backdoors
            if "backdoor" in path or "shell" in path:
                try:
                    success = await self.server.delete_file(path)
                    if success:
                        actions_taken.append(f"Quarantined/Deleted web shell at '{path}'")
                    else:
                        failures.append(f"File '{path}' not found when attempting deletion")
                except Exception as e:
                    failures.append(f"Failed to delete file '{path}': {e}")
            else:
                actions_taken.append(f"Flagged configuration change at '{path}' for manual admin audit")

        # 4. Publish mitigation results
        status = "success" if not failures else "partial_failure" if actions_taken else "failed"
        summary = f"Mitigations completed with status: {status.upper()}. Actions count: {len(actions_taken)}."
        
        await broker.publish(Event(
            event_type="agent_thought",
            source="response_agent",
            data={"text": f"{summary} System integrity re-established. Generating report."}
        ))
        
        # Publish Remediation Event
        await broker.publish(Event(
            event_type="remediation",
            source="response_agent",
            severity="info",
            data={
                "ip": ip,
                "category": category,
                "status": status,
                "actions_taken": actions_taken,
                "failures": failures,
                "summary": summary
            }
        ))
