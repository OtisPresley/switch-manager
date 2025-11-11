
from __future__ import annotations

DOMAIN = "switch_manager"

CONF_HOST = "host"
CONF_PORT = "port"
CONF_COMMUNITY = "community"
CONF_NAME = "name"

DEFAULT_PORT = 161
DEFAULT_POLL_INTERVAL = 10  # seconds

PLATFORMS = ["sensor", "switch"]

# OIDs
OID_sysDescr = "1.3.6.1.2.1.1.1.0"
OID_sysName = "1.3.6.1.2.1.1.5.0"
OID_sysUpTime = "1.3.6.1.2.1.1.3.0"

# IF-MIB
OID_ifIndex = "1.3.6.1.2.1.2.2.1.1"
OID_ifDescr = "1.3.6.1.2.1.2.2.1.2"
OID_ifType = "1.3.6.1.2.1.2.2.1.3"
OID_ifAdminStatus = "1.3.6.1.2.1.2.2.1.7"
OID_ifOperStatus = "1.3.6.1.2.1.2.2.1.8"
OID_ifName = "1.3.6.1.2.1.31.1.1.1.1"
OID_ifAlias = "1.3.6.1.2.1.31.1.1.1.18"

# IP-MIB (legacy IPv4 table)
OID_ipAdEntAddr = "1.3.6.1.2.1.4.20.1.1"
OID_ipAdEntIfIndex = "1.3.6.1.2.1.4.20.1.2"
OID_ipAdEntNetMask = "1.3.6.1.2.1.4.20.1.3"
