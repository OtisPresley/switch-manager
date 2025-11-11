
from __future__ import annotations
import ipaddress
from typing import Optional, Dict, Any

def _abbr_from_speed_or_name(name: str) -> str:
    n = (name or "").lower()
    if n.startswith("gi"):
        return "Gi"
    if n.startswith("te"):
        return "Te"
    if n.startswith("tw"):
        return "Tw"
    if n.startswith("fa"):
        return "Fa"
    if n.startswith("po") or n.startswith("port-channel") or n.startswith("portchannel"):
        return "Po"
    if n.startswith("lo"):
        return "Lo"
    if n.startswith("vl"):
        return "Vl"
    if "10g" in n: return "Te"
    if "20g" in n: return "Tw"
    if "1g" in n or "1000" in n: return "Gi"
    return "Gi"

def format_interface_name(raw_name: str, unit: int=1, slot: int=0, port: Optional[int]=None) -> str:
    rn = (raw_name or "").strip()
    lower = rn.lower()

    if lower.startswith("vl"):
        return rn
    if lower.startswith("link aggregate"):
        try:
            num = int(rn.split()[-1])
            return f"Po{num}"
        except Exception:
            return rn
    if lower.startswith("port-channel") or lower.startswith("po"):
        return rn if rn[:2].lower() == "po" else "Po" + rn.split()[-1]

    if lower.startswith("lo"):
        return "Lo0"

    if port is not None:
        abbr = _abbr_from_speed_or_name(rn)
        return f"{abbr}{unit}/{slot}/{port}"
    return rn

def ip_to_cidr(ip: str, mask: str) -> Optional[str]:
    try:
        net = ipaddress.IPv4Network((ip, mask), strict=False)
        return f"{ip}/{net.prefixlen}"
    except Exception:
        return None
