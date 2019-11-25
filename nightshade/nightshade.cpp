// nightshade.cpp : Defines the entry point for the application.


#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Dxva2.lib")

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <winioctl.h>
#include <ntddvdeo.h>
#include <physicalmonitorenumerationapi.h>
#include <highlevelmonitorconfigurationapi.h>
#include <lowlevelmonitorconfigurationapi.h>
#include <vector>
#include <thread>
#include <chrono>
#include <condition_variable>
#include "nightshade.h"

using namespace std;
using boost::asio::ip::udp;

std::thread worker;

std::mutex mymutex;
std::condition_variable mycond;

bool flag = false;

boost::asio::io_context io_context;
	boost::system::error_code error;

	udp::socket udp_socket(io_context);
boost::array<char, 128> recv_buf;
std::chrono::system_clock::time_point stime;
	auto remote_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::broadcast(), 4000);
	auto local_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 4000);

	bool found_heart;

void heartbeat(
	const boost::system::error_code& error, // Result of operation.
	std::size_t bytes_transferred           // Number of bytes received.
)
{
	auto rtime = *(std::chrono::system_clock::time_point*)(recv_buf.data());
	if (bytes_transferred && rtime != stime){ 
		found_heart = true;
	}

	else {
		return udp_socket.async_receive_from(
			boost::asio::buffer(recv_buf), local_endpoint, heartbeat);
	}
}

void send_heartbeat()
{	
	::stime = std::chrono::system_clock::now();
	boost::array<std::chrono::system_clock::time_point, sizeof(::stime)> send_buf = { ::stime };
	
	udp_socket.send_to(boost::asio::buffer(send_buf), remote_endpoint);
}

auto darken(HANDLE &h, HWND &hWnd, HWND &hShell, bool supports_hw_power_off) {
	DISPLAY_BRIGHTNESS _displayBrightness{
	DISPLAYPOLICY_BOTH,
	0,
	0
	};

	DWORD nOutBufferSize = sizeof(_displayBrightness);

	DWORD ret = NULL;

	if (supports_hw_power_off)
	{
		SetVCPFeature(h, 0xD6, 0x04); // turn off display
	}
	else if (DeviceIoControl(h, IOCTL_VIDEO_SET_DISPLAY_BRIGHTNESS,
		(DISPLAY_BRIGHTNESS*)&_displayBrightness,
		nOutBufferSize, NULL, 0, &ret, NULL))
	{
		SendMessage(hWnd, WM_SYSCOMMAND, SC_MONITORPOWER, 0x04); // turn off display		
	}
	return true;
};

auto lighten(HANDLE& h, HWND& hWnd, HWND& hShell, bool supports_hw_power_off) {
	DISPLAY_BRIGHTNESS _displayBrightness{
	DISPLAYPOLICY_BOTH,
	100,
	100
	};

	DWORD nOutBufferSize = sizeof(_displayBrightness);

	DWORD ret = NULL;
	if (supports_hw_power_off)
	{
		SetVCPFeature(h, 0xD6, 0x01); // turn on display
	}
	else if (DeviceIoControl(h, IOCTL_VIDEO_SET_DISPLAY_BRIGHTNESS,
		(DISPLAY_BRIGHTNESS*)&_displayBrightness,
		nOutBufferSize, NULL, 0, &ret, NULL))
	{
		SendMessage(hWnd, WM_SYSCOMMAND, SC_MONITORPOWER, 1); // turn on display
	}
	return true;
};

auto sheduler(HANDLE h, HWND hWnd, HWND hShell, bool supports_hw_power_off)
{
	while (1) {
		if(!found_heart) send_heartbeat();
		std::unique_lock<std::mutex> lock(mymutex);
		lighten(h, hWnd, hShell, supports_hw_power_off);
		auto exit = mycond.wait_for(lock, std::chrono::minutes(20), []() {return flag; });
		if (exit) return;
		darken(h, hWnd, hShell, supports_hw_power_off);
		mycond.wait_for(lock, std::chrono::minutes(4), []() {return flag; });
		found_heart = false;
	}
}

int main()
{
	udp_socket.open(udp::v4(), error);
	udp_socket.set_option(boost::asio::socket_base::broadcast(true));
	udp_socket.set_option(boost::asio::ip::udp::socket::reuse_address(true));

	udp_socket.bind(local_endpoint);

	std::stringstream ss;
	ss << recv_buf.data();

	auto hWnd = GetConsoleWindow();
	ShowWindow(hWnd, SW_HIDE);

	auto hShell = FindWindow("Shell_TrayWnd", NULL);
	HANDLE h = CreateFile("\\\\.\\LCD",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		auto monitor = MonitorFromWindow(hWnd, MONITOR_DEFAULTTOPRIMARY);
		DWORD amount;
		GetNumberOfPhysicalMonitorsFromHMONITOR(monitor, &amount);

		PHYSICAL_MONITOR* pMonitors = new PHYSICAL_MONITOR[amount];


		if (GetPhysicalMonitorsFromHMONITOR(monitor, amount, pMonitors))
		{
			DWORD pdwMonitorCapabilities = 0u;
			DWORD pdwSupportedColorTemperatures = 0u;
			bool b3 = GetMonitorCapabilities(pMonitors->hPhysicalMonitor, &pdwMonitorCapabilities, &pdwSupportedColorTemperatures);
			h = pMonitors->hPhysicalMonitor;
			delete[] pMonitors;
		}
	}

	DWORD current, max;
	auto supports_hw_power_off = GetVCPFeatureAndVCPFeatureReply(h, 0xD6, nullptr, &current, &max);

	auto task = std::bind(sheduler, h, hWnd, hShell, supports_hw_power_off);

	worker = std::thread(task);

	while (1)
	{		
		if (found_heart)
		{
			{
				std::lock_guard<std::mutex> lock(mymutex);
				flag = true;
				mycond.notify_all();
			}
			worker.join();
			// restart
			flag = false;
			worker = std::thread(task);
		}
		else
		{
			flag = false;
		}

		udp_socket.async_receive_from(
			boost::asio::buffer(recv_buf), local_endpoint, heartbeat);
		io_context.run();
		io_context.restart();
	}

	return 0;
}
