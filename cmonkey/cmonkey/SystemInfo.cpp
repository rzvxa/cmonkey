#include "SystemInfo.h"
#include "include\curl\curl.h"
#include "curl_helper.h"
#include "include\picosha2.h"
#include "Utility.h"
#include <Windows.h>
#include <tchar.h>
#include <intrin.h>
#include <lmcons.h>
#include <ShlObj.h>
#include <comdef.h>
#include <WbemIdl.h>
#include <atlconv.h>
#include <iphlpapi.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)

SystemInfo SystemInfo::Instance()
{
	static SystemInfo instance;
	return instance;
}

SystemInfo::SystemInfo()
{
	architecture_ = machine();
	win_ver_ = platform();
	cpu_ = processor();
	user_ = user();
	pc_name_ = pcname();
	is_admin_ = isAnAdmin();
	gpu_ = gpu();
	motherboard_ = motherboard();
	chassis_type_ = chassistype();
	total_ram_ = totalram();
	bios_ = bios();
	pid_ = pid();
	mac_ = mac();
	ipv4_ = ipv4(mac_);
	antivirus_ = antivirus();
	firewall_ = firewall();
	antispyware_ = antispyware();
	geolocation_ = geolocation();
	unique_id_ = unique_id();
}

typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

std::string SystemInfo::machine()
{
	BOOL bIsWow64 = FALSE;
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
		GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		{
			//handle error
			return "Unknown";
		}
	}
	if (bIsWow64)
		return "x64";
	return "x86";
}

typedef void (WINAPI * RtlGetVersion_FUNC) (OSVERSIONINFOEXW *);
std::string SystemInfo::platform()
{
	OSVERSIONINFOEX * os = new OSVERSIONINFOEX();
	HMODULE hMod;
	RtlGetVersion_FUNC func;
#ifdef UNICODE
	OSVERSIONINFOEXW * osw = os;
#else
	OSVERSIONINFOEXW o;
	OSVERSIONINFOEXW * osw = &o;
#endif

	hMod = LoadLibrary(TEXT("ntdll.dll"));
	if (hMod) {
		func = (RtlGetVersion_FUNC)GetProcAddress(hMod, "RtlGetVersion");
		if (func == 0) {
			FreeLibrary(hMod);
			return FALSE;
		}
		ZeroMemory(osw, sizeof(*osw));
		osw->dwOSVersionInfoSize = sizeof(*osw);
		func(osw);
#ifndef UNICODE
		os->dwBuildNumber = osw->dwBuildNumber;
		os->dwMajorVersion = osw->dwMajorVersion;
		os->dwMinorVersion = osw->dwMinorVersion;
		os->dwPlatformId = osw->dwPlatformId;
		os->dwOSVersionInfoSize = sizeof(*os);
		DWORD sz = sizeof(os->szCSDVersion);
		WCHAR * src = osw->szCSDVersion;
		unsigned char * dtc = (unsigned char *)os->szCSDVersion;
		while (*src)
			* dtc++ = (unsigned char)* src++;
		*dtc = '\0';
#endif

	}
	else {
		delete os;
		return "Unknown";
	}
	FreeLibrary(hMod);
	std::string result = std::to_string(os->dwMajorVersion) + "." + std::to_string(os->dwMinorVersion);
	delete os;
	return result;
}

std::string SystemInfo::processor()
{
	// Get extended ids.
	int CPUInfo[4] = { -1 };
	__cpuid(CPUInfo, 0x80000000);
	unsigned int nExIds = CPUInfo[0];

	// Get the information associated with each extended ID.
	char CPUBrandString[0x40] = { 0 };
	for (unsigned int i = 0x80000000; i <= nExIds; ++i)
	{
		__cpuid(CPUInfo, i);

		// Interpret CPU brand string and cache information.
		if (i == 0x80000002)
		{
			memcpy(CPUBrandString,
				CPUInfo,
				sizeof(CPUInfo));
		}
		else if (i == 0x80000003)
		{
			memcpy(CPUBrandString + 16,
				CPUInfo,
				sizeof(CPUInfo));
		}
		else if (i == 0x80000004)
		{
			memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
		}
	}

	return CPUBrandString;
}

std::string SystemInfo::user()
{
	char username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserName(username, &username_len);
	return std::string(username);
}

std::string SystemInfo::pcname()
{
	char pc_name[UNLEN + 1];
	DWORD pc_name_len = UNLEN + 1;
	GetComputerName(pc_name, &pc_name_len);
	return std::string(pc_name);
}

std::string SystemInfo::isAnAdmin()
{
	return IsUserAnAdmin() ? "yes" : "no";
}

std::vector<std::string> SystemInfo::gpu()
{
	HRESULT hresult;

	hresult = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hresult))
		return {};
	hresult = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hresult))
		return {};

	IWbemLocator * pLoc = NULL;

	hresult = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID *)&pLoc
	);

	if (FAILED(hresult))
		return {};

	IWbemServices * pServ = NULL;

	hresult = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pServ
	);

	if (FAILED(hresult))
		return {};

	hresult = CoSetProxyBlanket(
		pServ,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hresult))
		return {};

	IEnumWbemClassObject * pEnumerator = NULL;
	hresult = pServ->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_VideoController"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	if (FAILED(hresult))
		return {};

	IWbemClassObject * pclsObj = NULL;
	ULONG uReturn = 0;
	
	std::vector<std::string> result;

	while (pEnumerator) {
		HRESULT hr = 
			pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (uReturn == 0)
			break;
		VARIANT vtProp;

		hr = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);
		USES_CONVERSION;
		result.push_back(W2A(vtProp.bstrVal));
		VariantClear(&vtProp);

		pclsObj->Release();
	}

	pServ->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return result;
}

std::string SystemInfo::motherboard()
{
	HRESULT hresult;

	hresult = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hresult))
		return {};
	hresult = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hresult))
		return {};

	IWbemLocator * pLoc = NULL;

	hresult = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID *)&pLoc
	);

	if (FAILED(hresult))
		return {};

	IWbemServices * pServ = NULL;

	hresult = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pServ
	);

	if (FAILED(hresult))
		return {};

	hresult = CoSetProxyBlanket(
		pServ,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hresult))
		return {};

	IEnumWbemClassObject * pEnumerator = NULL;
	hresult = pServ->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_BaseBoard"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	if (FAILED(hresult))
		return {};

	IWbemClassObject * pclsObj = NULL;
	ULONG uReturn = 0;

	std::string result;

	while (pEnumerator) {
		HRESULT hr =
			pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (uReturn == 0)
			break;
		VARIANT vtProp;

		USES_CONVERSION;
		hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
		std::string manufacturer = W2A(vtProp.bstrVal);
		hr = pclsObj->Get(L"Product", 0, &vtProp, 0, 0);
		std::string product = W2A(vtProp.bstrVal);
		hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
		std::string serialNumber = W2A(vtProp.bstrVal);

		result = manufacturer + product + serialNumber;

		VariantClear(&vtProp);

		pclsObj->Release();
		break;
	}

	pServ->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return result;

}

std::string SystemInfo::chassistype()
{
	HRESULT hresult;

	hresult = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hresult))
		return {};
	hresult = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hresult))
		return {};

	IWbemLocator * pLoc = NULL;

	hresult = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID *)&pLoc
	);

	if (FAILED(hresult))
		return {};

	IWbemServices * pServ = NULL;

	hresult = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pServ
	);

	if (FAILED(hresult))
		return {};

	hresult = CoSetProxyBlanket(
		pServ,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hresult))
		return {};

	IEnumWbemClassObject * pEnumerator = NULL;
	hresult = pServ->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_SystemEnclosure"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	if (FAILED(hresult))
		return {};

	IWbemClassObject * pclsObj = NULL;
	ULONG uReturn = 0;

	std::string result;

	while (pEnumerator) {
		HRESULT hr =
			pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (uReturn == 0)
			break;
		VARIANT vtProp;

		USES_CONVERSION;
		hr = pclsObj->Get(L"ChassisTypes", 0, &vtProp, 0, 0);
		if ((vtProp.vt & VT_ARRAY))
		{
			long lLower, lUpper;
			UINT32 Element = NULL;
			SAFEARRAY *pSafeArray = vtProp.parray;
			SafeArrayGetLBound(pSafeArray, 1, &lLower);
			SafeArrayGetUBound(pSafeArray, 1, &lUpper);

			for (long i = lLower; i <= lUpper; i++)
			{
				hresult = SafeArrayGetElement(pSafeArray, &i, &Element);
				result = std::to_string(Element);
				break;
			}

		}
		VariantClear(&vtProp);

		pclsObj->Release();
		break;
	}

	pServ->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return result;
}

std::string SystemInfo::totalram()
{
	HRESULT hresult;

	hresult = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hresult))
		return {};
	hresult = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hresult))
		return {};

	IWbemLocator * pLoc = NULL;

	hresult = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID *)&pLoc
	);

	if (FAILED(hresult))
		return {};

	IWbemServices * pServ = NULL;

	hresult = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pServ
	);

	if (FAILED(hresult))
		return {};

	hresult = CoSetProxyBlanket(
		pServ,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hresult))
		return {};

	IEnumWbemClassObject * pEnumerator = NULL;
	hresult = pServ->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_ComputerSystem"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	if (FAILED(hresult))
		return {};

	IWbemClassObject * pclsObj = NULL;
	ULONG uReturn = 0;

	std::string result;

	while (pEnumerator) {
		HRESULT hr =
			pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (uReturn == 0)
			break;
		VARIANT vtProp;

		USES_CONVERSION;
		hr = pclsObj->Get(L"TotalPhysicalMemory", 0, &vtProp, 0, 0);
		
		result = std::to_string(roundf(std::stof(W2A(vtProp.bstrVal)) / 1024 / 1024 / 1024));
		
		VariantClear(&vtProp);

		pclsObj->Release();
		break;
	}

	pServ->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return result;
}

std::string SystemInfo::bios()
{
	HRESULT hresult;

	hresult = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hresult))
		return {};
	hresult = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hresult))
		return {};

	IWbemLocator * pLoc = NULL;

	hresult = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID *)&pLoc
	);

	if (FAILED(hresult))
		return {};

	IWbemServices * pServ = NULL;

	hresult = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pServ
	);

	if (FAILED(hresult))
		return {};

	hresult = CoSetProxyBlanket(
		pServ,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hresult))
		return {};

	IEnumWbemClassObject * pEnumerator = NULL;
	hresult = pServ->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_BIOS"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	if (FAILED(hresult))
		return {};

	IWbemClassObject * pclsObj = NULL;
	ULONG uReturn = 0;

	std::string result;

	while (pEnumerator) {
		HRESULT hr =
			pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (uReturn == 0)
			break;
		VARIANT vtProp;

		USES_CONVERSION;
		hr = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);
		std::string caption = W2A(vtProp.bstrVal);
		hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
		std::string manufacturer = W2A(vtProp.bstrVal);
		hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
		std::string serialNumber = W2A(vtProp.bstrVal);

		result = caption + manufacturer + serialNumber;

		VariantClear(&vtProp);

		pclsObj->Release();
		break;
	}

	pServ->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return result;
}
#include <iostream>
std::string SystemInfo::pid()
{
	return std::to_string(GetCurrentProcessId());
}

std::string SystemInfo::mac()
{
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(AdapterInfo);
	char *mac_addr = (char*)malloc(17);

	AdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		free(AdapterInfo);
		return {};
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen     variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {

		AdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			free(AdapterInfo);
			return {};
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;// Contains pointer to current adapter info
		char* first_mac = nullptr;
		do {
			sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			if (strcmp(pAdapterInfo->IpAddressList.IpAddress.String, "0.0.0.0") != 0) {
				free(AdapterInfo);
				return mac_addr;
			}
			if (first_mac == nullptr) first_mac = mac_addr;

			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
		free(AdapterInfo);
		return first_mac;
	}
	return {};
}

std::string SystemInfo::ipv4(const std::string & my_mac)
{
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(AdapterInfo);
	char *mac_addr = (char*)malloc(17);

	AdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		free(AdapterInfo);
		return {};
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen     variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {

		AdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			free(AdapterInfo);
			return {};
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;// Contains pointer to current adapter info
		do {
			sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);

			if (strcmp(mac_addr, my_mac.c_str()) == 0)
				return pAdapterInfo->IpAddressList.IpAddress.String;

			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
		free(AdapterInfo);
	}
	return {};
}

std::vector<std::string> SystemInfo::antivirus()
{
	HRESULT hresult;

	hresult = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hresult))
		return {};
	hresult = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hresult))
		return {};

	IWbemLocator * pLoc = NULL;

	hresult = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID *)&pLoc
	);

	if (FAILED(hresult))
		return {};

	IWbemServices * pServ = NULL;

	hresult = pLoc->ConnectServer(
		_bstr_t(L"\\\\.\\root\\SecurityCenter2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pServ
	);

	if (FAILED(hresult))
		return {};

	hresult = CoSetProxyBlanket(
		pServ,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hresult))
		return {};

	IEnumWbemClassObject * pEnumerator = NULL;
	hresult = pServ->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM AntiVirusProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	if (FAILED(hresult))
		return {};

	IWbemClassObject * pclsObj = NULL;
	ULONG uReturn = 0;

	std::vector<std::string> result;

	while (pEnumerator) {
		HRESULT hr =
			pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (uReturn == 0)
			break;
		VARIANT vtProp;

		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		USES_CONVERSION;
		result.push_back(W2A(vtProp.bstrVal));
		VariantClear(&vtProp);

		pclsObj->Release();
	}

	pServ->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return result;
}

std::vector<std::string> SystemInfo::firewall()
{
	HRESULT hresult;

	hresult = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hresult))
		return {};
	hresult = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hresult))
		return {};

	IWbemLocator * pLoc = NULL;

	hresult = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID *)&pLoc
	);

	if (FAILED(hresult))
		return {};

	IWbemServices * pServ = NULL;

	hresult = pLoc->ConnectServer(
		_bstr_t(L"\\\\.\\root\\SecurityCenter2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pServ
	);

	if (FAILED(hresult))
		return {};

	hresult = CoSetProxyBlanket(
		pServ,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hresult))
		return {};

	IEnumWbemClassObject * pEnumerator = NULL;
	hresult = pServ->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM FirewallProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	if (FAILED(hresult))
		return {};

	IWbemClassObject * pclsObj = NULL;
	ULONG uReturn = 0;

	std::vector<std::string> result;

	while (pEnumerator) {
		HRESULT hr =
			pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (uReturn == 0)
			break;
		VARIANT vtProp;

		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		USES_CONVERSION;
		result.push_back(W2A(vtProp.bstrVal));
		VariantClear(&vtProp);

		pclsObj->Release();
	}

	pServ->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return result;
}

std::vector<std::string> SystemInfo::antispyware()
{
	HRESULT hresult;

	hresult = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hresult))
		return {};
	hresult = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hresult))
		return {};

	IWbemLocator * pLoc = NULL;

	hresult = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID *)&pLoc
	);

	if (FAILED(hresult))
		return {};

	IWbemServices * pServ = NULL;

	hresult = pLoc->ConnectServer(
		_bstr_t(L"\\\\.\\root\\SecurityCenter2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pServ
	);

	if (FAILED(hresult))
		return {};

	hresult = CoSetProxyBlanket(
		pServ,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hresult))
		return {};

	IEnumWbemClassObject * pEnumerator = NULL;
	hresult = pServ->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM AntiSpywareProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	if (FAILED(hresult))
		return {};

	IWbemClassObject * pclsObj = NULL;
	ULONG uReturn = 0;

	std::vector<std::string> result;

	while (pEnumerator) {
		HRESULT hr =
			pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (uReturn == 0)
			break;
		VARIANT vtProp;

		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		USES_CONVERSION;
		result.push_back(W2A(vtProp.bstrVal));
		VariantClear(&vtProp);

		pclsObj->Release();
	}

	pServ->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return result;
}

std::string SystemInfo::geolocation()
{

	CURL* curl;
	std::string response;
	curl_global_init(CURL_GLOBAL_ALL); //pretty obvious
	curl = curl_easy_init();

	curl_easy_setopt(curl, CURLOPT_URL, "http://ip-api.com/json/");
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curl_helper::WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

	curl_easy_perform(curl);


	curl_easy_cleanup(curl);
	curl_global_cleanup();
	return response;
}

std::string SystemInfo::unique_id()
{
	std::string str = architecture_ + win_ver_ + cpu_ + Utility::Join(gpu_, ';') +
		is_admin_ + motherboard_ + chassis_type_ + user_ + "@" + pc_name_ +
		total_ram_ + bios_ + mac_;
	return picosha2::hash256_hex_string(str);
}


SystemInfo::~SystemInfo()
{
}

