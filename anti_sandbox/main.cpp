#include <windows.h>
#include <winreg.h>
#include <stdio.h>

bool is_sandboxed() {
    HDEVINFO hDeviceInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_DISKDRIVE, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDeviceInfo == INVALID_HANDLE_VALUE) {
        return false;
    }

    SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
    deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (int i = 0; SetupDiEnumDeviceInterfaces(hDeviceInfo, NULL, &GUID_DEVCLASS_DISKDRIVE, i, &deviceInterfaceData); i++) {
        DWORD dwRegKeySize = 0;
        SetupDiGetDeviceRegistryProperty(hDeviceInfo, &deviceInterfaceData, SPDRP_REGISTRYKEY, NULL, NULL, 0, &dwRegKeySize);

        if (dwRegKeySize > 0) {
            wchar_t* pDeviceRegistryKey = (wchar_t*)malloc(dwRegKeySize);
            SetupDiGetDeviceRegistryProperty(hDeviceInfo, &deviceInterfaceData, SPDRP_REGISTRYKEY, NULL, (PBYTE)pDeviceRegistryKey, dwRegKeySize, NULL);

            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, pDeviceRegistryKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                wchar_t path[MAX_PATH];
                if (RegQueryValueExW(hKey, L"Parent", NULL, NULL, (LPBYTE)path, NULL) == ERROR_SUCCESS) {
                    if (_wcsstr(path, L"VMWare") || _wcsstr(path, L"VirtualBox")) {
                        free(pDeviceRegistryKey);
                        RegCloseKey(hKey);
                        SetupDiDestroyDeviceInfoList(hDeviceInfo);
                        return true;
                    }
                }

                RegCloseKey(hKey);
            }

            free(pDeviceRegistryKey);
        }
    }

    SetupDiDestroyDeviceInfoList(hDeviceInfo);
    return false;
}

bool is_debugger_present() {
    return IsDebuggerPresent();
}

bool is_virtualized() {
    bool is_virtualized = false;

    // Check for virtualized CPUID function
    __try {
        __asm {
            mov eax, 0x80000001
            cpuid
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        is_virtualized = true;
    }

    // Check for hypervisor-specific indicators
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t vendor[0x40];
        DWORD size = sizeof(vendor);
        RegQueryValueExW(hKey, L"VendorIdentifier", NULL, NULL, (LPBYTE)vendor, &size);

        if (_wcsstr(vendor, L"VMware") || _wcsstr(vendor, L"VirtualBox") || _wcsstr(vendor, L"QEMU")) {
            is_virtualized = true;
        }

        RegCloseKey(hKey);
    }

    return is_virtualized;
}

int main() {
    if (is_sandboxed() || is_debugger_present() || is_virtualized()) {
        // Prevent analysis by exiting
        exit(0);
    }

    // Rest of the code
    return 0;
}