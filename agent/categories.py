from enum import Enum


class AgentAttackCategory(str, Enum):
    """Taxonomy for agent/tool-call attacks.

    Values are persisted to the database — add members rather than renaming.
    """

    # Instructions smuggled in through data the agent reads via a tool.
    TOOL_INJECTION = "tool_injection"
    # Getting the agent to leak sensitive data to an attacker-controlled sink.
    DATA_EXFILTRATION = "data_exfiltration"
    # Getting the agent to destroy or overwrite data.
    DESTRUCTIVE_ACTION = "destructive_action"
    # Getting the agent to act outside the scope it was granted.
    SCOPE_ESCALATION = "scope_escalation"
    # Getting the agent to use its own authority on an attacker's behalf.
    CONFUSED_DEPUTY = "confused_deputy"

    def __str__(self) -> str:
        return self.value
