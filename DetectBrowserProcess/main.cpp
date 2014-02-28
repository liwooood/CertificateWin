#include <Windows.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <process.h>
#include <tchar.h>

#pragma comment(lib, "Psapi.lib")


BOOL __stdcall DetectBrowserProcess()
{
	

	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnapshot)
		return FALSE;

	
	PROCESSENTRY32 pe;
	::ZeroMemory(&pe, sizeof(pe));
	pe.dwSize = sizeof(pe);

	if (!Process32First(hSnapshot, &pe))
	{
		return FALSE;
	}
	
	if (_tcsicmp(pe.szExeFile, "iexplore.exe") == 0)
	{
		return TRUE;
	}
		
	if (_tcsicmp(pe.szExeFile, "chrome.exe") == 0)
	{
		return TRUE;
	}
	
	if (_tcsicmp(pe.szExeFile, "firefox.exe") == 0)
	{
		return TRUE;
	}
			

	BOOL bFound = FALSE;

	while (!bFound && ::Process32Next(hSnapshot, &pe))
	{
		if (_tcsicmp(pe.szExeFile, "iexplore.exe") == 0)
		{
			bFound = TRUE;
			break;
		}
		else if (_tcsicmp(pe.szExeFile, "chrome.exe") == 0)
		{
			bFound = TRUE;
			break;
		}
		else if (_tcsicmp(pe.szExeFile, "firefox.exe") == 0)
		{
			bFound = TRUE;
			break;
		}
		else
		{
			bFound = FALSE;
		}
	} // end while

	if (hSnapshot)
	{
		CloseHandle(hSnapshot);
		hSnapshot = INVALID_HANDLE_VALUE;
	}

	return bFound;

}
