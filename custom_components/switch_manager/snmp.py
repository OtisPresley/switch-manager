# ... (header and earlier content unchanged)

    def _get_ipv4_table(self) -> Dict[int, List[Dict[str, str]]]:
        """
        Build { ifIndex: [ {address, netmask}, ... ] } from legacy IP-MIB ipAddrTable.
        """
        by_addr_if = {str(addr): int(idx) for addr, idx in self.walk(self.OID_ipAdEntIfIndex)}
        by_addr_mask = {str(addr): str(mask) for addr, mask in self.walk(self.OID_ipAdEntNetMask)}
        result: Dict[int, List[Dict[str, str]]] = {}
        for addr, ifindex in by_addr_if.items():
            result.setdefault(ifindex, []).append({
                "address": addr,
                "netmask": by_addr_mask.get(addr, ""),
            })
        return result

    def _get_ipv4_table_v2(self) -> Dict[int, List[Dict[str, str]]]:
        """
        Fallback for devices that only populate IP-MIBv2 ipAddressTable (RFC 4293).

        We parse:
          ipAddressIfIndex:      1.3.6.1.2.1.4.34.1.3
          ipAddressPrefixLength: 1.3.6.1.2.1.4.34.1.5    (for IPv4 rows)

        Index is (addrType, addrBytes...). We only keep addrType==2 (IPv4).
        """
        IFIDX_OID = "1.3.6.1.2.1.4.34.1.3"
        PLEN_OID  = "1.3.6.1.2.1.4.34.1.5"

        def _parse_ipv4_from_index(oid_str: str) -> str | None:
            # Extract suffix after the base OID and try to decode IPv4 bytes
            try:
                parts = [int(x) for x in oid_str.split(".")]
                base = [int(x) for x in IFIDX_OID.split(".")]
                # handle also PLEN_OID length; decide shorter of two bases
                if len(parts) <= len(base):
                    base = [int(x) for x in PLEN_OID.split(".")]
                suffix = parts[len(base):]
                if not suffix:
                    return None
                addr_type = suffix[0]  # InetAddressType: 2 == ipv4
                if addr_type != 2 or len(suffix) < 5:
                    return None
                # next part is address length followed by that many bytes, *or*
                # some stacks omit the length and put 4 addr octets directly.
                # Try both.
                if len(suffix) >= 6 and suffix[1] == 4 and len(suffix) >= 6:
                    octets = suffix[2:6]
                else:
                    octets = suffix[1:5]
                return ".".join(str(b) for b in octets)
            except Exception:
                return None

        by_addr_if: Dict[str, int] = {}
        for oid, ifidx in self.walk(IFIDX_OID):
            addr = _parse_ipv4_from_index(oid)
            if addr:
                try:
                    by_addr_if[addr] = int(ifidx)
                except Exception:
                    continue

        by_addr_plen: Dict[str, int] = {}
        for oid, plen in self.walk(PLEN_OID):
            addr = _parse_ipv4_from_index(oid)
            if addr:
                try:
                    by_addr_plen[addr] = int(plen)
                except Exception:
                    continue

        result: Dict[int, List[Dict[str, str]]] = {}
        for addr, ifindex in by_addr_if.items():
            plen = by_addr_plen.get(addr)
            netmask = ""
            if plen is not None and 0 <= plen <= 32:
                try:
                    import ipaddress as _ip
                    netmask = str(_ip.IPv4Network(f"0.0.0.0/{plen}").netmask)
                except Exception:
                    netmask = ""
            result.setdefault(ifindex, []).append({"address": addr, "netmask": netmask})
        return result

    def get_port_data(self) -> Dict[int, Dict[str, Any]]:
        descr = {int(oid.split(".")[-1]): str(val) for oid, val in self.walk(self.OID_ifDescr)}
        admin = {int(oid.split(".")[-1]): int(val) for oid, val in self.walk(self.OID_ifAdminStatus)}
        oper  = {int(oid.split(".")[-1]): int(val) for oid, val in self.walk(self.OID_ifOperStatus)}
        alias = {int(oid.split(".")[-1]): str(val) for oid, val in self.walk(self.OID_ifAlias)}

        ipv4 = self._get_ipv4_table()
        # If legacy table is empty, try the v2 table
        if not ipv4:
            try:
                ipv4 = self._get_ipv4_table_v2()
            except Exception as exc:
                _LOGGER.debug("ipAddressTable (v2) parse failed: %s", exc)

        indices = set(descr) | set(admin) | set(oper) | set(alias) | set(ipv4)
        out: Dict[int, Dict[str, Any]] = {}
        for idx in sorted(indices):
            out[idx] = {
                "index": idx,
                "name": descr.get(idx, ""),
                "admin": admin.get(idx, 0),
                "oper": oper.get(idx, 0),
                "alias": alias.get(idx, ""),
                "ipv4": ipv4.get(idx, []),
            }
        return out
