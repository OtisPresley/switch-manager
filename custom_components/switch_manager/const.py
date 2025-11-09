"""Constants for Switch Manager integration."""

DOMAIN = "switch_manager"
PLATFORMS = ["switch"]
DEFAULT_PORT = 161
CONF_COMMUNITY = "community"
DEFAULT_SCAN_INTERVAL = 30
REQUIREMENTS = ["pysnmp>=4.4.12,<5"]
ATTR_PORT = "port"
ATTR_DESCRIPTION = "description"
ATTR_SPEED = "speed"
ATTR_ADMIN_STATUS = "admin_status"
ATTR_OPER_STATUS = "oper_status"
ATTR_IMAGE_URL = "image_url"
ATTR_MODEL = "model"
ATTR_SERIAL = "serial"
ATTR_FIRMWARE = "firmware"
SERVICE_SET_PORT_DESCRIPTION = "set_port_description"
SERVICE_FIELD_ENTITY_ID = "entity_id"
SERVICE_FIELD_DESCRIPTION = "description"

SNMP_OIDS = {
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
}
