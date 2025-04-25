/*
 * intf-win32.c
 *
 * Copyright (c) 2023-2024 Oliver Falk <oliver@linux-kernel.at>
 *
 */

#include "config.h"

#include <netioapi.h>
#include <iphlpapi.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

/* XXX - ipifcons.h incomplete, use IANA ifTypes MIB */
#define MIB_IF_TYPE_TUNNEL	131
#define MIB_IF_TYPE_MAX		259 /* According to ipifcons.h */

#define _set_ifindex(index, ptr) \
	do { \
		(ptr)->InterfaceIndex = (index); \
		(ptr)->InterfaceLuid.Value = 0; \
	} while (0)

struct intf_handle {
	MIB_IF_TABLE2 *table;
	MIB_UNICASTIPADDRESS_TABLE *addrs;
};

static char *
_ifcombo_name(int type)
{
	char *name = "eth";	/* XXX */

	if (type == MIB_IF_TYPE_TOKENRING) {
		name = "tr";
	} else if (type == MIB_IF_TYPE_FDDI) {
		name = "fddi";
	} else if (type == MIB_IF_TYPE_PPP) {
		name = "ppp";
	} else if (type == MIB_IF_TYPE_LOOPBACK) {
		name = "lo";
	} else if (type == MIB_IF_TYPE_SLIP) {
		name = "sl";
	} else if (type == MIB_IF_TYPE_TUNNEL) {
		name = "tun";
	}
	return (name);
}

static int _unicastaddr_to_addr(const MIB_UNICASTIPADDRESS_ROW *iprow, struct addr *addr)
{
	if (iprow->Address.si_family == AF_INET) {
		return addr_ston((struct sockaddr *)&iprow->Address.Ipv4, addr);
	} else if (iprow->Address.si_family == AF_INET6) {
		return addr_ston((struct sockaddr *)&iprow->Address.Ipv6, addr);
	} else {
		return (-1);
	}

	addr->addr_bits = iprow->OnLinkPrefixLength;

	return (0);
}

static int _addr_to_unicastaddr(const struct addr *addr, NET_IFINDEX index, MIB_UNICASTIPADDRESS_ROW *iprow)
{
	InitializeUnicastIpAddressEntry(iprow);
	_set_ifindex(index, iprow);

	iprow->OnLinkPrefixLength = addr->addr_bits;
	iprow->PreferredLifetime = ULONG_MAX;
	iprow->ValidLifetime = ULONG_MAX;

	if (addr->addr_type == ADDR_TYPE_IP) {
		return addr_ntos(addr, (struct sockaddr *)&iprow->Address.Ipv4);
	} else if (addr->addr_type == ADDR_TYPE_IP6) {
		return addr_ntos(addr, (struct sockaddr *)&iprow->Address.Ipv6);
	} else {
		return (-1);
	}

	return (0);
}

static void
_ifrow2_to_entry(intf_t *intf, MIB_IF_ROW2 *ifrow, struct intf_entry *entry)
{
	struct addr *ap, *lap;
	ULONG i;

	/* The total length of the entry may be passed in inside entry.
	   Remember it and clear the entry. */
	u_int intf_len = entry->intf_len;
	memset(entry, 0, sizeof(*entry));
	/* Restore the length. */
	entry->intf_len = intf_len;

	/* XXX - Type matches MIB-II ifType. */
	snprintf(entry->intf_name, sizeof(entry->intf_name), "%s%lu",
	    _ifcombo_name(ifrow->Type), ifrow->InterfaceIndex);
	entry->intf_type = ifrow->Type;

	/* Get interface flags. */
	entry->intf_flags = 0;

	if (ifrow->AdminStatus == NET_IF_ADMIN_STATUS_UP &&
	    (ifrow->OperStatus == IfOperStatusUp ||
	     ifrow->MediaConnectState == MediaConnectStateConnected))
		entry->intf_flags |= INTF_FLAG_UP;
	if (ifrow->Type == IF_TYPE_SOFTWARE_LOOPBACK)
		entry->intf_flags |= INTF_FLAG_LOOPBACK;
	else
		entry->intf_flags |= INTF_FLAG_MULTICAST;

	/* Get interface MTU. */
	entry->intf_mtu = ifrow->Mtu;

	/* Get hardware address. */
	if (ifrow->PhysicalAddressLength == ETH_ADDR_LEN) {
		entry->intf_link_addr.addr_type = ADDR_TYPE_ETH;
		entry->intf_link_addr.addr_bits = ETH_ADDR_BITS;
		memcpy(&entry->intf_link_addr.addr_eth, ifrow->PhysicalAddress,
		    ETH_ADDR_LEN);
	}

	/* Get addresses. */
	ap = entry->intf_alias_addrs;
	lap = ap + ((entry->intf_len - sizeof(*entry)) /
			sizeof(entry->intf_alias_addrs[0]));

	for (i = 0; i < intf->addrs->NumEntries; ++i) {
		if (intf->addrs->Table[i].InterfaceIndex != ifrow->InterfaceIndex) {
			continue;
		}

		if (entry->intf_addr.addr_type == ADDR_TYPE_NONE) {
			/* Set primary address if unset. */
			_unicastaddr_to_addr(&intf->addrs->Table[i], &entry->intf_addr);
		} else if (ap < lap) {
			if (_unicastaddr_to_addr(&intf->addrs->Table[i], ap) == 0) {
					entry->intf_alias_num++;
					ap++;
			}
		}
	}
	entry->intf_len = (u_char *)ap - (u_char *)entry;
}

static void
_free_table(void** p)
{
	if (*p) {
		FreeMibTable(*p);
		*p = NULL;
	}
}

static void
_free_tables(intf_t *intf)
{
	_free_table((void **)&intf->table);
	_free_table((void **)&intf->addrs);
}

static int
_refresh_tables(intf_t *intf)
{
	_free_tables(intf);

	if (GetIfTable2(&intf->table) != NO_ERROR) {
		return (-1);
	} else if (GetUnicastIpAddressTable(AF_UNSPEC, &intf->addrs) != NO_ERROR) {
		return (-1);
	}

	return (0);
}

static int
_find_ifindex(intf_t* intf, const char *device)
{
	const char *p = device;

	for (; *p && isalpha(*p); ++p);

	if (*p) {
		return atoi(p);
	}

	return (0);
}

int
_ifindex_to_entry(intf_t *intf, NET_IFINDEX index, struct intf_entry *entry)
{
	MIB_IF_ROW2 ifrow;

	_set_ifindex(index, &ifrow);

	if (GetIfEntry2(&ifrow) != NO_ERROR) {
		return (-1);
	}

	_ifrow2_to_entry(intf, &ifrow, entry);

	return (0);
}

int
_entry_to_ipinterface(intf_t *intf, const struct intf_entry *entry, MIB_IPINTERFACE_ROW *row)
{
  NET_IFINDEX index = _find_ifindex(intf, entry->intf_name);

	_set_ifindex(index, row);
	if (GetIpInterfaceEntry(row) != NO_ERROR) {
		return (-1);
	}

	return 0;
}

int
_intf_delete_unicast_addrs(intf_t *intf, NET_IFINDEX index)
{
	MIB_UNICASTIPADDRESS_ROW *addr;
	ULONG i;

	for (i = 0; i < intf->addrs->NumEntries; ++i) {
		addr = &intf->addrs->Table[i];

		if (addr->InterfaceIndex == index) {
			DeleteUnicastIpAddressEntry(addr);
		}
	}

	return (0);
}

static int
_intf_add_unicast_addr(intf_t *intf, NET_IFINDEX index, const struct addr *addr)
{
	MIB_UNICASTIPADDRESS_ROW addrrow;

	_addr_to_unicastaddr(addr, index, &addrrow);
	if (CreateUnicastIpAddressEntry(&addrrow) != NO_ERROR) {
		return (-1);
	}

	return (0);
}

static int
_intf_add_unicast_addrs(intf_t *intf, const struct intf_entry *entry)
{
	MIB_IPINTERFACE_ROW intfrow;
	ULONG dad_transmits_orig;
	const struct addr *addr;
	u_int i;
	int ret;

	if (_entry_to_ipinterface(intf, entry, &intfrow) < 0) {
		return (-1);
	}

	/* The address added by CreateUnicastIpAddressEntry isn't immediately
	 * available for use, due to Windows' Duplicate Address Detection (DAD),
	 * which uses ARP to check if an address is claimed by another device.
	 *
	 * The docs recommend pausing "for one to three seconds" (!) after calling
	 * CreateUnicastIpAddressEntry, before checking the DAD status[1]. This
	 * is unacceptably long, so we temporarily disable DAD by setting
	 * DadTransmits to 0 (ignoring potential errors from SetIpInterfaceEntry).
	 *
	 * [1] https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry
	 */

	dad_transmits_orig = intfrow.DadTransmits;

	intfrow.DadTransmits = 0;
	SetIpInterfaceEntry(&intfrow);

	ret = 0;
	i = 0;
	addr = &entry->intf_addr;

	do {
		if (_intf_add_unicast_addr(intf, intfrow.InterfaceIndex, addr) < 0) {
			ret = -1;
			break;
		}

		addr = &entry->intf_alias_addrs[i];
	} while (i++ < entry->intf_alias_num);

	intfrow.DadTransmits = dad_transmits_orig;
	SetIpInterfaceEntry(&intfrow);

	return (ret);
}

intf_t *
intf_open(void)
{
	return (calloc(1, sizeof(intf_t)));
}

int
intf_get(intf_t *intf, struct intf_entry *entry)
{
	if (_refresh_tables(intf) < 0)
		return (-1);

	return _ifindex_to_entry(intf, _find_ifindex(intf, entry->intf_name), entry);
}

int
intf_get_src(intf_t *intf, struct intf_entry *entry, struct addr *src)
{
	struct addr addr;
	ULONG i;

	if (_refresh_tables(intf) < 0)
		return (-1);

	for (i = 0; i < intf->addrs->NumEntries; i++) {
		_unicastaddr_to_addr(&intf->addrs->Table[i], &addr);
		if (!addr_cmp(src, &addr)) {
			return _ifindex_to_entry(intf, intf->addrs->Table[i].InterfaceIndex, entry);
		}
	}
	errno = ENXIO;
	return (-1);
}

int
intf_get_dst(intf_t *intf, struct intf_entry *entry, struct addr *dst)
{
	DWORD index;
	struct sockaddr sa;

	if (addr_ntos(dst, &sa) != 0) {
		return (-1);
	}

	if (GetBestInterfaceEx(&sa, &index) != NO_ERROR) {
		return (-1);
	}

	return _ifindex_to_entry(intf, index, entry);
}

int
intf_set(intf_t *intf, const struct intf_entry *entry)
{
	const struct addr *addr;
	MIB_IPINTERFACE_ROW iprow;
	MIB_IFROW ifrow1;
	MIB_IF_ROW2 ifrow2;
	NET_IFINDEX index;

	if (_refresh_tables(intf) < 0) {
		return (-1);
	}

	index = _find_ifindex(intf, entry->intf_name);
	if (!index) {
		return (-1);
	}

	/* Delete all existing addrs. */
	if (_intf_delete_unicast_addrs(intf, index) < 0) {
		return (-1);
	}

	/* Add all addrs from entry. */
	if (_intf_add_unicast_addrs(intf, entry) < 0) {
		return (-1);
	}

	/* Begin Get/SetIpInterfaceEntry */

	_set_ifindex(index, &iprow);
	if (GetIpInterfaceEntry(&iprow) != NO_ERROR) {
		return (-1);
	}

	/* Set interface MTU. */
	if (entry->intf_mtu != 0) {
		iprow.NlMtu = entry->intf_mtu;
	}

	if (SetIpInterfaceEntry(&iprow) != NO_ERROR) {
		return (-1);
	}

	/* End Get/SetIpInterfaceEntry */

	_set_ifindex(index, &ifrow2);
	if (GetIfEntry2(&ifrow2) != NO_ERROR) {
		return (-1);
	}

	/* Set hardware address. */
	if (entry->intf_link_addr.addr_type == ADDR_TYPE_ETH) {
		if (memcmp(&addr->addr_eth, &ifrow2.PhysicalAddress, ETH_ADDR_LEN) != 0) {
			/* XXX - not yet implemented. We'd have to modify the registry for that */
			errno = ENOSYS;
			SetLastError(ERROR_NOT_SUPPORTED);
			return (-1);
		}
	}

	/* Set point-to-point destination. */
	if (entry->intf_dst_addr.addr_type != ADDR_TYPE_NONE) {
		/* XXX - not yet implemented. */
		errno = ENOSYS;
		SetLastError(ERROR_NOT_SUPPORTED);
		return (-1);
	}

	/* Set flags. */
	memset(&ifrow1, 0, sizeof(ifrow1));
	ifrow1.dwIndex = index;

	if (entry->intf_flags & INTF_FLAG_UP) {
		ifrow1.dwAdminStatus = MIB_IF_ADMIN_STATUS_UP;
	} else {
		ifrow1.dwAdminStatus = MIB_IF_ADMIN_STATUS_DOWN;
	}

	if (SetIfEntry(&ifrow1) != NO_ERROR) {
		return (-1);
	}

	if (entry->intf_flags & INTF_FLAG_NOARP) {
		errno = ENOSYS;
		SetLastError(ERROR_NOT_SUPPORTED);
		return (-1);
	}

	return (0);
}

int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
	struct intf_entry *entry;
	u_char ebuf[1024];
	ULONG i;
	int ret = -1;

	if (_refresh_tables(intf) < 0)
		return (-1);

	entry = (struct intf_entry *)ebuf;

	for (i = 0; i < intf->table->NumEntries; ++i) {
		entry->intf_len = sizeof(ebuf);
		_ifrow2_to_entry(intf, &intf->table->Table[i], entry);
		if ((ret = (*callback)(entry, arg)) != 0)
			break;
	}

	return ret;
}

intf_t *
intf_close(intf_t *intf)
{
	_free_tables(intf);
	return (NULL);
}
