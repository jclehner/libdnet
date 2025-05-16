/*
 * intf-win32.c
 *
 * Copyright (c) 2023-2024 Oliver Falk <oliver@linux-kernel.at>
 * Copyright (c) 2025 Joseph C. Lehner <joseph.c.lehner@gmail.com>
 *
 */

#include "config.h"


#include <ws2ipdef.h>
#include <iphlpapi.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

struct ifcombo {
	NET_IFINDEX *idx;
	int cnt;
	int max;
};

/* XXX - ipifcons.h incomplete, use IANA ifTypes MIB */
#define MIB_IF_TYPE_TUNNEL	131
#define MIB_IF_TYPE_MAX		259 /* According to ipifcons.h */

#define _set_ifindex(index, ptr) \
	do { \
		(ptr)->InterfaceIndex = (index); \
		(ptr)->InterfaceLuid.Value = 0; \
	} while (0)

struct intf_handle {
	struct ifcombo ifcombo[MIB_IF_TYPE_MAX];
	MIB_IF_TABLE2 *iftable;
	MIB_UNICASTIPADDRESS_TABLE *addrs;
};

static inline void
_set_error(int err, DWORD winerr)
{
	errno = err;
	SetLastError(winerr);
}

static u_short
_ifcombo_mapped_type(ULONG type)
{
	if (type < MIB_IF_TYPE_MAX) {
		switch (type) {
			case IF_TYPE_IEEE80211:
			case IF_TYPE_ETHERNET_CSMACD:
				return INTF_TYPE_ETH;
			case IF_TYPE_TUNNEL:
				return INTF_TYPE_TUN;
			case IF_TYPE_ISO88025_TOKENRING:
			case IF_TYPE_FDDI:
			case IF_TYPE_PPP:
			case IF_TYPE_SOFTWARE_LOOPBACK:
			case IF_TYPE_SLIP:
				return type;
		}
	}

	return INTF_TYPE_OTHER;
}

const char* _ifcombo_prefixes[MIB_IF_TYPE_MAX] = {
	[INTF_TYPE_ETH] = "eth",
	[INTF_TYPE_FDDI] = "fddi",
	[INTF_TYPE_LOOPBACK] = "lo",
	[INTF_TYPE_OTHER] = "intf",
	[INTF_TYPE_PPP] = "ppp",
	[INTF_TYPE_SLIP] = "sl",
	[INTF_TYPE_TOKENRING] = "tr",
	[INTF_TYPE_TUN] = "tun",
};

static const char *
_ifcombo_name(u_short type)
{
	if (type < MIB_IF_TYPE_MAX) {
		const char* ret = _ifcombo_prefixes[type];
		if (ret) {
			return ret;
		}
	}

	return _ifcombo_prefixes[INTF_TYPE_OTHER];
}

static u_short
_ifcombo_type(const char *device)
{
	const char* p;
	u_short type;

	for (type = 0; type < MIB_IF_TYPE_MAX; ++type) {
		p = _ifcombo_prefixes[type];
		if (p && strncmp(device, p, strlen(p)) == 0) {
			return type;
		}
	}

	return INTF_TYPE_OTHER;
}

static void
_ifcombo_add(struct ifcombo *ifc, NET_IFINDEX idx)
{
	if (ifc->cnt == ifc->max) {
		if (ifc->idx) {
			ifc->max *= 2;
			ifc->idx = realloc(ifc->idx,
			    sizeof(ifc->idx[0]) * ifc->max);
		} else {
			ifc->max = 8;
			ifc->idx = malloc(sizeof(ifc->idx[0]) * ifc->max);
		}
	}
	ifc->idx[ifc->cnt++] = idx;
}

static int
_intf_loop_ipaddrs(const struct intf_entry* entry, int (*callback)(const struct addr*, u_int))
{
	const struct addr* addr;
	int ret;
	u_int i = 0;

	addr = &entry->intf_addr;

	do {
		if (addr->addr_type != ADDR_TYPE_NONE) {
			ret = callback(addr, entry->intf_index);
			if (ret < 0) {
				return ret;
			}
		}

		addr = &entry->intf_alias_addrs[i];
	} while (i++ < entry->intf_alias_num);

	return 0;
}

static int
_unicastaddr_to_addr(const MIB_UNICASTIPADDRESS_ROW* row, struct addr* addr)
{
	if (row->Address.si_family == AF_INET) {
		return addr_ston((struct sockaddr*)&row->Address.Ipv4, addr);
	} else if (row->Address.si_family == AF_INET6) {
		return addr_ston((struct sockaddr*)&row->Address.Ipv6, addr);
	} else {
		return (-1);
	}

	addr->addr_bits = row->OnLinkPrefixLength;

	return (0);
}

static int
_addr_to_unicastaddr(const struct addr* addr, NET_IFINDEX index, MIB_UNICASTIPADDRESS_ROW* row)
{
	InitializeUnicastIpAddressEntry(row);
	_set_ifindex(index, row);

	row->OnLinkPrefixLength = addr->addr_bits;
	row->PreferredLifetime = ULONG_MAX;
	row->ValidLifetime = ULONG_MAX;

	if (addr->addr_type == ADDR_TYPE_IP) {
		row->Address.si_family = AF_INET;
		return addr_ntos(addr, (struct sockaddr*)&row->Address.Ipv4);
	} else if (addr->addr_type == ADDR_TYPE_IP6) {
		row->Address.si_family = AF_INET6;
		return addr_ntos(addr, (struct sockaddr*)&row->Address.Ipv6);
	} else {
		return (-1);
	}

	return (0);
}

static void
_ifrow2_to_entry(intf_t* intf, MIB_IF_ROW2* ifrow, struct intf_entry* entry)
{
	struct addr* ap, * lap;
	ULONG i;

	/* The total length of the entry may be passed in inside entry.
	   Remember it and clear the entry. */
	u_int intf_len = entry->intf_len;
	memset(entry, 0, sizeof(*entry));
	/* Restore the length. */
	entry->intf_len = intf_len;

	/* XXX - Type matches MIB-II ifType. */
	entry->intf_type = _ifcombo_mapped_type(ifrow->Type);

	for (i = 0; i < intf->ifcombo[entry->intf_type].cnt; i++) {
		if (intf->ifcombo[entry->intf_type].idx[i] == ifrow->InterfaceIndex)
			break;
	}

	snprintf(entry->intf_name, sizeof(entry->intf_name), "%s%lu",
		_ifcombo_name(entry->intf_type), i);

	entry->intf_index = ifrow->InterfaceIndex;

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
	entry->intf_len = (u_char*)ap - (u_char*)entry;
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
_free_tables(intf_t* intf)
{
	_free_table((void**)&intf->iftable);
	_free_table((void**)&intf->addrs);
}

static int
_refresh_tables(intf_t* intf)
{
	MIB_IF_ROW2* row;
	ULONG i;

	_free_tables(intf);

	if (GetIfTable2(&intf->iftable) != NO_ERROR) {
		return (-1);
	} else if (GetUnicastIpAddressTable(AF_UNSPEC, &intf->addrs) != NO_ERROR) {
		return (-1);
	}

	for (i = 0; i < intf->iftable->NumEntries; i++) {
		row = &intf->iftable->Table[i];
		if (row->Type < MIB_IF_TYPE_MAX) {
			_ifcombo_add(&intf->ifcombo[_ifcombo_mapped_type(row->Type)],
				row->InterfaceIndex);
		}
		else
			return (-1);
	}

	return (0);
}

static NET_IFINDEX
_find_ifindex(intf_t *intf, const char *device)
{
	char *p = (char *)device;
	int n, ret, type = _ifcombo_type(device);
	
	while (isalpha((int) (unsigned char) *p)) p++;
	n = atoi(p);

	ret = intf->ifcombo[type].idx[n];
	if (!ret) {
		_set_error(ENXIO, ERROR_FILE_NOT_FOUND);
	}

	return (ret);
}

static int
_ifindex_to_entry(intf_t* intf, NET_IFINDEX index, struct intf_entry* entry)
{
	MIB_IF_ROW2 ifrow;

	_set_ifindex(index, &ifrow);

	if (GetIfEntry2(&ifrow) != NO_ERROR) {
		return (-1);
	}

	_ifrow2_to_entry(intf, &ifrow, entry);

	return (0);
}

static int
_entry_to_ipinterface(intf_t* intf, const struct intf_entry* entry, MIB_IPINTERFACE_ROW* row)
{
	NET_IFINDEX index = _find_ifindex(intf, entry->intf_name);

	_set_ifindex(index, row);
	if (GetIpInterfaceEntry(row) != NO_ERROR) {
		return (-1);
	}

	return 0;
}

static int
_intf_delete_unicast_addr(const struct addr* addr, u_int index)
{
	MIB_UNICASTIPADDRESS_ROW row;

	if (_addr_to_unicastaddr(addr, index, &row) < 0) {
		//errno = EINVAL;
		return (-1);
	}

	if (DeleteUnicastIpAddressEntry(&row) != NO_ERROR) {
		return (-1);
	}

	return 0;
}

static int
_intf_add_unicast_addr(const struct addr* addr, u_int index)
{
	MIB_UNICASTIPADDRESS_ROW row;

	if (_addr_to_unicastaddr(addr, index, &row) < 0) {
		//errno = EINVAL;
		return (-1);
	} 

	if (CreateUnicastIpAddressEntry(&row) != NO_ERROR) {
		return (-1);
	}

	return (0);
}

static int
_intf_add_unicast_addrs(intf_t* intf, const struct intf_entry* entry)
{
	MIB_IPINTERFACE_ROW row;
	ULONG dad_transmits_orig;
	int ret;

	if (_entry_to_ipinterface(intf, entry, &row) < 0) {
		return (-1);
	}

	/* The address added by CreateUnicastIpAddressEntry isn't immediately
	 * available for use, due to Windows' Duplicate Address Detection (DAD).
	 *
	 * The docs recommend pausing "for one to three seconds" (!) after calling
	 * CreateUnicastIpAddressEntry, before checking the DAD status[1]. This
	 * is unacceptably long, so we temporarily disable DAD by setting
	 * DadTransmits to 0 (ignoring potential errors from SetIpInterfaceEntry).
	 *
	 * [1] https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry
	 */

	dad_transmits_orig = row.DadTransmits;

	row.DadTransmits = 0;
	SetIpInterfaceEntry(&row);

	ret = _intf_loop_ipaddrs(entry, _intf_add_unicast_addr);

	row.DadTransmits = dad_transmits_orig;
	SetIpInterfaceEntry(&row);

	return (ret);
}

intf_t *
intf_open(void)
{
	return (calloc(1, sizeof(intf_t)));
}

int
intf_get(intf_t* intf, struct intf_entry* entry)
{
	NET_IFINDEX idx;

	if (_refresh_tables(intf) < 0)
		return (-1);
	
	if (entry->intf_name[0]) {
		idx = _find_ifindex(intf, entry->intf_name);
	} else {
		idx = entry->intf_index;
	}

	return _ifindex_to_entry(intf, idx, entry);
}

int
intf_get_src(intf_t* intf, struct intf_entry* entry, struct addr* src)
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
intf_get_dst(intf_t* intf, struct intf_entry* entry, struct addr* dst)
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
intf_set(intf_t* intf, const struct intf_entry* entry)
{
	MIB_IPINTERFACE_ROW iprow;
	MIB_IFROW ifrow1;
	MIB_IF_ROW2 ifrow2;
	NET_IFINDEX index;
	int i;

	if (_refresh_tables(intf) < 0) {
		return (-1);
	}

	index = _find_ifindex(intf, entry->intf_name);
	if (!index) {
		return (-1);
	}

	/* Delete all existing (unicast) addrs. */
	if (_intf_loop_ipaddrs(entry, _intf_delete_unicast_addr) < 0) {
		return (-1);
	}

	/* Add all addrs from entry. */
	if (_intf_add_unicast_addrs(intf, entry) < 0) {
		return (-1);
	}

	/* Begin Get/SetIpInterfaceEntry. Options are set separately for AF_INET and AF_INET6. */

	for (i = 0; i < 2; ++i) {
		_set_ifindex(index, &iprow);
		iprow.Family = i ? AF_INET6 : AF_INET;

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
	}

	/* End Get/SetIpInterfaceEntry */

	_set_ifindex(index, &ifrow2);
	if (GetIfEntry2(&ifrow2) != NO_ERROR) {
		return (-1);
	}

	/* Set hardware address. */
	if (entry->intf_link_addr.addr_type == ADDR_TYPE_ETH) {
		if (memcmp(&entry->intf_link_addr.addr_eth, &ifrow2.PhysicalAddress, ETH_ADDR_LEN) != 0) {
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
	}
	else {
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
intf_loop(intf_t* intf, intf_handler callback, void* arg)
{
	struct intf_entry* entry;
	u_char ebuf[1024];
	ULONG i;
	int ret;

	if (_refresh_tables(intf) < 0)
		return (-1);

	ret = 0;
	entry = (struct intf_entry*)ebuf;	

	for (i = 0; i < intf->iftable->NumEntries; ++i) {
		entry->intf_len = sizeof(ebuf);
		_ifrow2_to_entry(intf, &intf->iftable->Table[i], entry);
		if ((ret = (*callback)(entry, arg)) != 0)
			break;
	}

	return ret;
}

intf_t*
intf_close(intf_t* intf)
{
	int i;

	if (intf != NULL) {
		for (i = 0; i < MIB_IF_TYPE_MAX; i++) {
			if (intf->ifcombo[i].idx)
				free(intf->ifcombo[i].idx);
		}
		_free_tables(intf);
		free(intf);
	}

	return (NULL);
}
