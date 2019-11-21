// nightshade.cpp : Defines the entry point for the application.


#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Dxva2.lib")

#include <Windows.h>
#include <WinNT.h>
#include <ntddvdeo.h>
#include <cfgmgr32.h>
#include <wmistr.h>
#include <physicalmonitorenumerationapi.h>
#include <lowlevelmonitorconfigurationapi.h>
#include <vector>
#include <thread>
#include <chrono>

#include "nightshade.h"

using namespace std;

int main()
{
	auto hShell = FindWindow("Shell_TrayWnd", NULL);
	HANDLE h = CreateFile("\\\\.\\LCD",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0, NULL);

	auto hWnd = GetConsoleWindow();
	ShowWindow(hWnd, SW_HIDE);

	auto darken = [&h, &hWnd, &hShell]() {
		DISPLAY_BRIGHTNESS _displayBrightness{
		DISPLAYPOLICY_BOTH,
		0,
		0
		};

		DWORD nOutBufferSize = sizeof(_displayBrightness);

		DWORD ret = NULL;

		if (!DeviceIoControl(h, IOCTL_VIDEO_SET_DISPLAY_BRIGHTNESS, 
			(DISPLAY_BRIGHTNESS*)& _displayBrightness, 
			nOutBufferSize, NULL, 0, &ret, NULL))
		{
			return false;
		}
		SendMessage(hWnd, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
		SendMessage(hShell, WM_COMMAND, 419, 0);
	};

	auto lighten = [&h, &hWnd, &hShell]() {
		DISPLAY_BRIGHTNESS _displayBrightness{
		DISPLAYPOLICY_BOTH,
		100,
		100
		};

		DWORD nOutBufferSize = sizeof(_displayBrightness);

		DWORD ret = NULL;

		if (!DeviceIoControl(h, IOCTL_VIDEO_SET_DISPLAY_BRIGHTNESS, 
			(DISPLAY_BRIGHTNESS*)& _displayBrightness, 
			nOutBufferSize, NULL, 0, &ret, NULL))
		{ 
			return false;
		}
		SendMessage(hWnd, WM_SYSCOMMAND, SC_MONITORPOWER, 1);
		SendMessage(hShell, WM_COMMAND, 416, 0);
	};

	while (1)
	{
		lighten();
		std::this_thread::sleep_for(std::chrono::minutes(20));
		darken();
		std::this_thread::sleep_for(std::chrono::minutes(5));
	}

	return 0;
}
