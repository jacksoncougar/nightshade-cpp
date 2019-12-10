// nightshade.cpp : Defines the entry point for the application.

#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Dxva2.lib")
#pragma comment(lib, "powrprof.lib")


#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <winioctl.h>
#include <ntddvdeo.h>
#include <physicalmonitorenumerationapi.h>
#include <highlevelmonitorconfigurationapi.h>
#include <lowlevelmonitorconfigurationapi.h>
#include <powrprof.h>
#include <vector>
#include <thread>
#include <chrono>
#include <time.h>
#include <iomanip>
#include <condition_variable>
#include "nightshade.h"

#define log(x) \
{ \
time_t  t = std::time(0); \
std::cout << ((std::ostringstream() << std::setw(10) << std::put_time(std::localtime(&t), "%H-%M-%S: ") \
<< std::left << x << "\n").str().c_str());\
} \

using namespace std;
using boost::asio::ip::udp;

HANDLE timer = CreateWaitableTimer(nullptr, true, nullptr);

std::thread worker;
std::mutex m;
std::condition_variable cv;

bool worker_should_terminate = false;

boost::asio::io_context io_context;
boost::system::error_code error;

udp::socket udp_socket(io_context);

boost::array<char, 128> recv_buf;

std::chrono::system_clock::time_point stime;

auto remote_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::broadcast(), 4000);
auto local_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 4000);

std::atomic<bool> found_heart;

void process_heartbeat(
	const boost::system::error_code& error, // Result of operation.
	std::size_t bytes_transferred           // Number of bytes received.
)
{
	auto rtime = *(std::chrono::system_clock::time_point*)(recv_buf.data());
	if (bytes_transferred && rtime != stime) {
		found_heart = true;
		log("found heartbeat");
	}
	else {
		log("heard own heartbeat")
			return udp_socket.async_receive_from(
				boost::asio::buffer(recv_buf), local_endpoint, process_heartbeat);
	}
}

void send_heartbeat()
{
	log("send_hearbeat");
	found_heart = false;
	::stime = std::chrono::system_clock::now();
	boost::array<std::chrono::system_clock::time_point, sizeof(::stime)> send_buf = { ::stime };
	udp_socket.send_to(boost::asio::buffer(send_buf), remote_endpoint);
}

auto darken_screens(HANDLE& h, HWND& hWnd, HWND& hShell, bool supports_hw_power_off, DWORD min_brightness) {
	log("darken");

	DISPLAY_BRIGHTNESS _displayBrightness{
		DISPLAYPOLICY_BOTH,	min_brightness, min_brightness
	};

	DWORD nOutBufferSize = sizeof(_displayBrightness);
	DWORD ret = NULL;

	if (supports_hw_power_off)
	{
		log("turn off display power");
		SetVCPFeature(h, 0xD6, 0x04); // turn off display
	}
	else if (DeviceIoControl(h, IOCTL_VIDEO_SET_DISPLAY_BRIGHTNESS,
		(DISPLAY_BRIGHTNESS*)& _displayBrightness,
		nOutBufferSize, NULL, 0, &ret, NULL))
	{
		log("lower brightness & suspend");
		
		if (!timer)throw;
		LARGE_INTEGER span;

		auto minutes = [](long long x) { return -x * 60 * 10'000'000ll; };
		auto seconds = [](long long x) { return -x * 10'000'000ll; };
		span.QuadPart = minutes(4);

		if (!SetWaitableTimer(timer, &span, 0, nullptr, nullptr, true)) throw;
		if (GetLastError() == ERROR_NOT_SUPPORTED) throw;
		
		auto enter_sleep = []() {
			log("wait on timer");
			if (WaitForSingleObject(timer, INFINITE) != WAIT_OBJECT_0)
			{
				log("WaitForSingleObject failed (%d)\n");
				log(GetLastError());
			}
			else log("Timer was signaled.\n");

			SetThreadExecutionState(ES_CONTINUOUS);

			log("awaken");
		};

		std::thread(enter_sleep).detach();

		if (!SetThreadExecutionState(ES_CONTINUOUS | ES_AWAYMODE_REQUIRED)) throw;
		SetSuspendState(false, false, false);
	}
	return true;
};

auto brighten_screens(HANDLE& h, HWND& hWnd, HWND& hShell, bool supports_hw_power_off, DWORD max_brightness) {
	DISPLAY_BRIGHTNESS _displayBrightness{
	DISPLAYPOLICY_BOTH,
	max_brightness,
	max_brightness
	};


	log("lighten");
	SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED);

	DWORD nOutBufferSize = sizeof(_displayBrightness);

	DWORD ret = NULL;
	if (supports_hw_power_off)
	{
		SetVCPFeature(h, 0xD6, 0x01); // turn on display
	}
	else if (DeviceIoControl(h, IOCTL_VIDEO_SET_DISPLAY_BRIGHTNESS,
		(DISPLAY_BRIGHTNESS*)& _displayBrightness,
		nOutBufferSize, NULL, 0, &ret, NULL))
	{
		SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1); // turn on display
	}
	return true;
};

auto sheduler(HANDLE h, HWND hWnd, HWND hShell, bool supports_hw_power_off, DWORD max_brightness, DWORD min_brightness)
{
	while (!worker_should_terminate) {

		std::unique_lock<std::mutex> lock(m);

		SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED);
		if (!found_heart) send_heartbeat();

		brighten_screens(h, hWnd, hShell, supports_hw_power_off, max_brightness);
		if (cv.wait_for(lock, std::chrono::minutes(20), []() {return worker_should_terminate; }))
			return;
		
		darken_screens(h, hWnd, hShell, supports_hw_power_off, min_brightness);
		if (cv.wait_for(lock, std::chrono::minutes(4), []() {return worker_should_terminate; }))
			return;

		
	}
}

int main()
{
	udp_socket.open(udp::v4(), error);
	udp_socket.set_option(boost::asio::socket_base::broadcast(true));
	udp_socket.set_option(boost::asio::ip::udp::socket::reuse_address(true));
	udp_socket.bind(local_endpoint);

	auto hWnd = GetConsoleWindow();
	//ShowWindow(hWnd, SW_HIDE);

	auto hShell = FindWindow("Shell_TrayWnd", NULL);
	
	HANDLE h = CreateFile("\\\\.\\LCD",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0, NULL);

	auto use_external_monitor = h == INVALID_HANDLE_VALUE;
	if (use_external_monitor)
	{
		auto monitor = MonitorFromWindow(hWnd, MONITOR_DEFAULTTOPRIMARY);
		DWORD amount;
		GetNumberOfPhysicalMonitorsFromHMONITOR(monitor, &amount);

		PHYSICAL_MONITOR* pMonitors = new PHYSICAL_MONITOR[amount];

		if (GetPhysicalMonitorsFromHMONITOR(monitor, amount, pMonitors))
		{
			h = pMonitors->hPhysicalMonitor;
			delete[] pMonitors;
		}
	}

	DWORD current, max;
	auto supports_hw_power_off = GetVCPFeatureAndVCPFeatureReply(h, 0xD6, nullptr, &current, &max);
	
	// Set shutdown privilege for current process
	{ 
		auto pid = GetCurrentProcess();
		HANDLE token;
		if (!OpenProcessToken(pid, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) throw;
		LUID luid;
		LookupPrivilegeValue(nullptr, "SeShutdownPrivilege", &luid);
		TOKEN_PRIVILEGES priv;
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		priv.Privileges[0].Luid = luid;

		if (!AdjustTokenPrivileges(token, false, &priv, 0, nullptr, nullptr)) throw;
		CloseHandle(token);
	}

	auto task = std::bind(sheduler, h, hWnd, hShell, supports_hw_power_off, max, 0);
	worker = std::thread(task);

	auto should_shutdown = false;
	while (!should_shutdown)
	{
		if (found_heart) 
		{
			{
				log("tell the worker thread to terminate.")
				std::lock_guard<std::mutex> lock(m);
				worker_should_terminate = true;
				cv.notify_all();
			}
			worker.join();
			log("worker thread joined main thread.")
			{
				worker_should_terminate = false;
				worker = std::thread(task);
			}
		}
		else
		{
			worker_should_terminate = false;
		}

		udp_socket.async_receive_from(
			boost::asio::buffer(recv_buf), local_endpoint, process_heartbeat);
		io_context.run(); // execution on this thread will poll here until a heartbeat is heard...
		io_context.restart(); 
	}

	return 0;
}
