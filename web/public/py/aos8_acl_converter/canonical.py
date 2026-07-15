"""Canonical security-policy model (AOS 8 ``acl_sess`` -> Aruba Central policy).

Standalone re-implementation of the HPE Networking MCP ``CanonicalPolicy`` model.
The original used ``pydantic``; this tool keeps dependencies minimal, so the same
shape is expressed with a stdlib ``dataclass``. The semantics are identical:

* ``rules`` holds the finished Central ``policy-rule[]`` array produced by the
  reader (address / service / protocol / action already translated).
* ``unmapped_actions`` records any AOS 8 action string that had **no** Central
  mapping. When it is non-empty the rule was *fail-closed* to ``ACTION_DENY`` and
  the policy is flagged unresolved -- never a silent fall-through to
  ``ACTION_ALLOW`` (the classic security-inverting migration bug).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

# Association tells Central how the policy is applied.
ASSOCIATION_ROLE = "ASSOCIATION_ROLE"            # bound to a user-role
ASSOCIATION_INTERFACE = "ASSOCIATION_INTERFACE"  # bound to an interface (e.g. validuser)


@dataclass
class CanonicalPolicy:
    """A Central security policy with its ordered rules + role/interface association."""

    name: str
    association: str = ASSOCIATION_ROLE
    rules: List[Dict[str, Any]] = field(default_factory=list)
    unmapped_actions: List[str] = field(default_factory=list)

    @property
    def is_unresolved(self) -> bool:
        """True when at least one AOS 8 action could not be mapped (fail-closed)."""
        return bool(self.unmapped_actions)
