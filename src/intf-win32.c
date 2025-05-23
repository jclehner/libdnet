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
#include <wbemidl.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

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

static char*
_intf_get_guid_str(NET_IFINDEX index, char* str, size_t len)
{
	GUID guid;
	NET_LUID luid;

	if (ConvertInterfaceIndexToLuid(index, &luid) != NO_ERROR) {
		fprintf(stderr, "%s: ConvertInterfaceIndexToLuid\n", __func__);
		return NULL;
	}

	if (ConvertInterfaceLuidToGuid(&luid, &guid) != NO_ERROR) {
		fprintf(stderr, "%s: ConvertInterfaceLuidToGuid\n", __func__);
		return NULL;
	}

	snprintf(str, len,
		"{%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

	return str;
}

static wchar_t*
_intf_get_guid_wcs(NET_IFINDEX index, wchar_t* wcs, size_t len)
{
	char str[39];
	size_t converted;

	if (!_intf_get_guid_str(index, str, sizeof(str))) {
		return NULL;
	}

	if (mbstowcs_s(&converted, wcs, len, str, sizeof(str)) != 0) {
		return NULL;
	}

	return wcs;
}

static int
_intf_set_link_addr(NET_IFINDEX index, const eth_addr_t* addr)
{
	char guid[39];
	char subkey[64];
	char buf[64];
	HKEY hkey;
	DWORD i, len, err;
	BOOL match;

	if (!_intf_get_guid_str(index, guid, sizeof(guid))) {
		return (-1);
	}

	err = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		"System\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}",
		0, KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS, &hkey);

	if (err) {
		printf("  RegOpenKeyExA: %lu\n", err);
		return (-1);
	}

	match = FALSE;

	for (i = 0; !match; ++i) {
		len = sizeof(subkey);
		err = RegEnumKeyExA(hkey, i, subkey, &len, NULL, NULL, NULL, NULL);
		if (err == ERROR_NO_MORE_ITEMS) {
			break;
		} else if (err == ERROR_MORE_DATA) {
			/* The subkeys we expect are a 4-digit decimal number (e.g. 0018),
			   so sizeof(subkey) should be plenty. */
			continue;
		} else if (err) {
			printf("  RegEnumKeyExA: %lu\n", err);
			break;
		}

		len = sizeof(buf);
		err = RegGetValueA(hkey, subkey, "NetCfgInstanceId", RRF_RT_REG_SZ, NULL, buf, &len);
		if (err) {
			printf("  RegGetValueA: %lu\n", err);
			break;
		}

		if (!err && strcasecmp(buf, guid) == 0) {
			match = TRUE;
			snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x",
				addr->data[0], addr->data[1], addr->data[2],
				addr->data[3], addr->data[4], addr->data[5]);

			err = RegSetKeyValueA(hkey, subkey, "NetworkAddress", REG_SZ, buf, strlen(buf));
			if (err) {
				printf("  RegSetKeyValueA: %lu\n", err);
			}
		}
	}

	RegCloseKey(hkey);

	if (err) {
		return ( -1);
	}

	return (match ? 0 : -1);
}

#define _com_release(obj) do { if (obj) { obj->lpVtbl->Release(obj); }} while(0)

static int
_iwbemobj_exec_method(IWbemServices* svc, IWbemClassObject* obj, const wchar_t* funcname)
{
	BSTR func = SysAllocString(funcname);
	HRESULT hr;
	VARIANT path = { VT_EMPTY };
	int ret = -1;

	do {
		if (!func) {
			break;
		}

		hr = obj->lpVtbl->Get(obj, L"__PATH", 0, &path, 0, 0);
		if (FAILED(hr)) {
			printf("%s: IWbemClassObject::Get", __func__);
			break;
		}

		hr = svc->lpVtbl->ExecMethod(svc, V_BSTR(&path), func, 0, NULL, NULL, NULL, NULL);
		if (FAILED(hr)) {
			printf("%s: IWbemServices::ExecMethod", __func__);
			break;
		}

		ret = 0;

	} while (0);

	SysFreeString(func);
	return ret;
}

static int
_intf_restart(NET_IFINDEX index)
{
	char guid[39];
	wchar_t buf[128];
	BSTR query = NULL;
	BSTR resource = NULL;
	BSTR language = NULL;
	IWbemLocator* locator = NULL;
	IWbemServices* services = NULL;
	IEnumWbemClassObject* results = NULL;
	IWbemClassObject* result = NULL;
	int ret = -1;
	ULONG count;
	HRESULT hr;

	if (!_intf_get_guid_str(index, guid, ARRAY_SIZE(guid))) {
		printf("%s: _intf_get_guid_str", __func__);
		return -1;
	}

	do {
		snwprintf(buf, ARRAY_SIZE(buf), L"SELECT * FROM MSFT_NetAdapter WHERE DeviceId='%s'", guid);
		query = SysAllocString(buf);
		resource = SysAllocString(L"ROOT\\StandardCimv2");
		language = SysAllocString(L"WQL");

		if (!query || !resource || !language ) {
			printf("%s: SysAllocString", __func__);
			break;
		}

		hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
		if (FAILED(hr)) {
			printf("%s: CoInitializeEx", __func__);
			break;
		}

		hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
			RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
		if (FAILED(hr)) {
			printf("%s: CoInitializeSecurity", __func__);
			break;
		}

		hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator,
			(LPVOID*)&locator);
		if (FAILED(hr) || !locator) {
			printf("%s: CoCreateInstance", __func__);
			break;
		}

		hr = locator->lpVtbl->ConnectServer(locator, resource, NULL, NULL, NULL, 0, NULL, NULL, &services);
		if (FAILED(hr) || !services) {
			printf("%s: IWbemLocator::ConnectServer", __func__);
			break;
		}

		hr = services->lpVtbl->ExecQuery(services, language, query, WBEM_FLAG_BIDIRECTIONAL, NULL, &results);
		if (FAILED(hr) || !results) {
			printf("%s: IWbemServices::ExecQuery", __func__);
			break;
		}

		hr = results->lpVtbl->Next(results, WBEM_INFINITE, 1, &result, &count);
		if (FAILED(hr) || !result) {
			printf("%s: IEnumWbemClassObject::Next", __func__);
			break;
		}

		ret = _iwbemobj_exec_method(services, result, L"Restart");
		result->lpVtbl->Release(result);
	} while (0);

	_com_release(results);
	_com_release(services);
	_com_release(locator);

	CoUninitialize();

	SysFreeString(language);
	SysFreeString(resource);
	SysFreeString(query);

	return ret;
}

static int
_intf_loop_ipaddrs(const struct intf_entry* entry, u_short type, int (*callback)(const struct addr*, u_int))
{
	const struct addr* addr;
	int ret;
	u_int i = 0;

	addr = &entry->intf_addr;

	do {
		if (addr->addr_type == ADDR_TYPE_NONE) {
			continue;
		} else if (type && type != addr->addr_type) {
			continue;
		}

		ret = callback(addr, entry->intf_index);
		if (ret < 0) {
			return ret;
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

static u_int
_entry_to_ifindex(intf_t* intf, const struct intf_entry* entry)
{
	if (entry->intf_name[0]) {
		return _find_ifindex(intf, entry->intf_name);
	}

	return entry->intf_index;
}

static int
_ifindex_to_entry(intf_t* intf, struct intf_entry* entry)
{
	MIB_IF_ROW2 ifrow;

	_set_ifindex(entry->intf_index, &ifrow);

	if (GetIfEntry2(&ifrow) != NO_ERROR) {
		return (-1);
	}

	_ifrow2_to_entry(intf, &ifrow, entry);

	return (0);
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
	DWORD err;

	if (_addr_to_unicastaddr(addr, index, &row) < 0) {
		errno = EINVAL;
		return (-1);
	}

	err = CreateUnicastIpAddressEntry(&row);

	if (err) {
		if (err == ERROR_OBJECT_ALREADY_EXISTS) {
			errno = EEXIST;
		}
		else if (err == ERROR_ACCESS_DENIED) {
			errno = EACCES;
		}
		else {
			errno = EINVAL;
		}
	}

	if (err) {
		printf("%s: CreateUnicastIpAddressEntry(%s)=%lu", __func__, addr_ntoa(addr), err);
	}

	return (err ? -1 : 0);
}

intf_t *
intf_open(void)
{
	return (calloc(1, sizeof(intf_t)));
}

int
intf_get(intf_t* intf, struct intf_entry* entry)
{
	if (_refresh_tables(intf) < 0)
		return (-1);

	if (!entry->intf_index) {
		entry->intf_index = _entry_to_ifindex(intf, entry);
	}

	return _ifindex_to_entry(intf, entry);
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
			entry->intf_index = intf->addrs->Table[i].InterfaceIndex;
			return _ifindex_to_entry(intf, entry);
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

	entry->intf_index = index;
	return _ifindex_to_entry(intf, entry);
}

int
intf_set(intf_t* intf, const struct intf_entry* entry)
{
	MIB_IPINTERFACE_ROW iprow;
	MIB_IFROW ifrow1;
	MIB_IF_ROW2 ifrow2;
	NET_IFINDEX index;
	ULONG dad_transmits_orig;
	DWORD err;
	int i;

	if (_refresh_tables(intf) < 0) {
		return (-1);
	}

	index = _entry_to_ifindex(intf, entry);
	if (!index) {
		errno = ENXIO;
		return (-1);
	}

	/* Set the hardware address first, so _intf_restart doesn't mess up our other changes. */
	if (entry->intf_link_addr.addr_type == ADDR_TYPE_ETH) {
		if (memcmp(&entry->intf_link_addr.addr_eth, &ifrow2.PhysicalAddress, ETH_ADDR_LEN) != 0) {
			if (_intf_set_link_addr(index, &entry->intf_link_addr.addr_eth) < 0) {
				return (-1);
			}

			if (_intf_restart(index) < 0) {
				return (-1);
			}
		}
	}

	/* Delete all existing (unicast) addrs. ADDR_TYPE_NONE means "all" here. */
	if (_intf_loop_ipaddrs(entry, ADDR_TYPE_NONE, _intf_delete_unicast_addr) < 0) {
		printf("%s: _intf_loop_ipaddrs\n", __func__);
		return (-1);
	}

	/* Get/SetIpInterfaceEntry options are set separately for AF_INET and AF_INET6. */

	for (i = 0; i < 2; ++i) {
		_set_ifindex(index, &iprow);
		iprow.Family = i ? AF_INET6 : AF_INET;

		if (GetIpInterfaceEntry(&iprow) != NO_ERROR) {
			printf("%s: GetIpInterfaceEntry\n", __func__);
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

		dad_transmits_orig = iprow.DadTransmits;
		iprow.DadTransmits = 0;

		if (!i) {
			// must be 0 for IPv4 (but isn't set as such)
			iprow.SitePrefixLength = 0;
		}

		if ((err = SetIpInterfaceEntry(&iprow)) != NO_ERROR) {
			printf("%s: SetIpInterfaceEntry 1: %lu\n", __func__, err);
			return (-1);
		}

		/* Add IPv4/IPv6 addresses from entry */
		if (_intf_loop_ipaddrs(entry, i ? ADDR_TYPE_IP6 : ADDR_TYPE_IP, _intf_add_unicast_addr) < 0) {
			printf("%s: _intf_loop_ipaddrs(..., _intf_add_unicast_addr)\n", __func__);
			return (-1);
		}

		/* Restore DadTransmits (see above) */
		iprow.DadTransmits = dad_transmits_orig;

		/* Set interface MTU. */
		if (entry->intf_mtu != 0) {
			iprow.NlMtu = entry->intf_mtu;
		}

		if (SetIpInterfaceEntry(&iprow) != NO_ERROR) {
			printf("%s: SetIpInterfaceEntry 2\n", __func__);
			return (-1);
		}
	}

	/* End Get/SetIpInterfaceEntry */

	_set_ifindex(index, &ifrow2);
	if (GetIfEntry2(&ifrow2) != NO_ERROR) {
		printf("%s: GetIfEntry2\n", __func__);
		return (-1);
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
