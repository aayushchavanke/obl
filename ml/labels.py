from enum import Enum


class AttackType(Enum):
    """Canonical attack-type class labels used across the project.

    Values are plain strings to remain sklearn-friendly while providing
    a single source of truth for available classes.
    """

    WEB_BROWSER = 'web_browser'
    DDOS = 'ddos_attack'
    PORT_SCAN = 'port_scan'
    BOTNET = 'botnet'
    APT_EXFILTRATION = 'apt_exfiltration'
    BRUTE_FORCE_SSH = 'brute_force_ssh'
    MALWARE_C2 = 'malware_c2'

    @classmethod
    def values(cls):
        return [e.value for e in cls]

    @classmethod
    def from_string(cls, s: str):
        if s is None:
            return None
        s = str(s).strip()
        for e in cls:
            if s == e.value or s.lower() == e.name.lower():
                return e
        # Fallback: try to match by substring
        for e in cls:
            if e.value in s.lower() or e.name.lower() in s.lower():
                return e
        return None
