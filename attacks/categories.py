from enum import Enum


class AttackCategory(str, Enum):
    """Top-level taxonomy for the attack corpus.

    Values are the stable identifiers written to the database — renaming one
    orphans historical rows, so add new members rather than editing existing
    values.
    """

    DIRECT_JAILBREAK = "direct_jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    MULTI_TURN = "multi_turn"

    def __str__(self) -> str:
        return self.value
