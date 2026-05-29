import asyncio
import time
import uuid
from typing import Dict, Any, List, Set, Callable, Optional
from pydantic import BaseModel, Field

class Event(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    event_type: str  # e.g., "log_line", "log_alert", "threat_classification", "forensic_investigation", "remediation", "agent_thought", "system_state"
    source: str      # e.g., "log_scanner", "threat_classifier", "forensics_investigator", "response_agent", "system_simulator"
    data: Dict[str, Any]
    severity: Optional[str] = None  # "info", "low", "medium", "high", "critical"

class EventBroker:
    def __init__(self, max_history: int = 1000):
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self.history: List[Event] = []
        self.max_history = max_history
        self._lock = asyncio.Lock()

    async def publish(self, event: Event):
        """
        Publishes an event to all active subscribers of the event_type
        and wildcard '*' subscribers.
        """
        async with self._lock:
            # Store in history
            self.history.append(event)
            if len(self.history) > self.max_history:
                self.history.pop(0)

        # Distribute to subscribers
        target_types = {event.event_type, "*"}
        for t_type in target_types:
            if t_type in self._subscribers:
                for queue in list(self._subscribers[t_type]):
                    try:
                        queue.put_nowait(event)
                    except asyncio.QueueFull:
                        # Queue is full, drain oldest element or ignore
                        pass

    def subscribe(self, event_type: str) -> asyncio.Queue:
        """
        Subscribe to a specific event type. Returns an asyncio.Queue that
        will receive events of this type.
        """
        queue = asyncio.Queue(maxsize=100)
        if event_type not in self._subscribers:
            self._subscribers[event_type] = set()
        self._subscribers[event_type].add(queue)
        return queue

    def unsubscribe(self, event_type: str, queue: asyncio.Queue):
        """
        Unsubscribe a queue from the specified event type.
        """
        if event_type in self._subscribers and queue in self._subscribers[event_type]:
            self._subscribers[event_type].remove(queue)
            if not self._subscribers[event_type]:
                del self._subscribers[event_type]

    async def get_history(self, event_type: Optional[str] = None, limit: int = 100) -> List[Event]:
        """
        Retrieve cached event logs.
        """
        async with self._lock:
            if event_type:
                filtered = [e for e in self.history if e.event_type == event_type]
            else:
                filtered = self.history
            return filtered[-limit:]

# Global broker instance
broker = EventBroker()
