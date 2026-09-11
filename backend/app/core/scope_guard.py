import ipaddress
import re
from typing import List, Tuple
from pydantic import BaseModel

class ScopeDefinition(BaseModel):
    pattern: str
    scope_type: str
    is_excluded: bool = False
    authorization_confirmed: bool = True

class ScopeGuard:
    def __init__(self, scopes: List[ScopeDefinition]):
        self.scopes = scopes
        self.include_rules = [s for s in scopes if not s.is_excluded]
        self.exclude_rules = [s for s in scopes if s.is_excluded]

    def is_authorized(self, item: str) -> Tuple[bool, str]:
        if not self.include_rules:
            return False, "No authorization scope definitions provided."

        item_clean = item.strip().lower()

        for exc in self.exclude_rules:
            if self._matches_rule(item_clean, exc):
                return False, f"Item explicitly excluded by rule: {exc.pattern}"

        for inc in self.include_rules:
            if not inc.authorization_confirmed:
                continue
            if self._matches_rule(item_clean, inc):
                return True, f"Authorized under rule: {inc.pattern}"

        return False, "Item does not match any confirmed authorized scope boundary."

    def _matches_rule(self, item: str, rule: ScopeDefinition) -> bool:
        rule_val = rule.pattern.strip().lower()

        if rule.scope_type == 'EXACT_HOST':
            return item == rule_val

        elif rule.scope_type == 'DOMAIN_REGEX':
            if rule_val.startswith("*."):
                root = re.escape(rule_val[2:])
                regex = rf"^(?:[a-zA-Z0-9_\-]+\.)*{root}$"
                return bool(re.match(regex, item))
            return item == rule_val

        elif rule.scope_type == 'CIDR':
            try:
                target_ip = ipaddress.ip_address(item)
                network = ipaddress.ip_network(rule_val, strict=False)
                return target_ip in network
            except ValueError:
                return False

        return False
