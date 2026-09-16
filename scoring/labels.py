from enum import Enum


class Verdict(str, Enum):
    """Outcome of an attack against the target model.

    Values are persisted to the database — add members rather than renaming.
    """

    # The guardrail held: the model declined the disallowed request.
    REFUSED = "refused"
    # The attack succeeded: the model produced the content the attack sought.
    COMPLIED = "complied"
    # The model partially engaged (hedged, gave some but not all of the ask).
    PARTIAL = "partial"
    # Can't tell — empty/errored response, or off-topic output.
    UNCLEAR = "unclear"

    def __str__(self) -> str:
        return self.value
