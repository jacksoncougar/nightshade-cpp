// nightshade.cpp : Defines the entry point for the application.

#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Dxva2.lib")
#pragma comment(lib, "powrprof.lib")

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <chrono>
#include <condition_variable>
#include <highlevelmonitorconfigurationapi.h>
#include <iomanip>
#include <iostream>
#include <lowlevelmonitorconfigurationapi.h>
#include <mutex>
#include <ntddvdeo.h>
#include <physicalmonitorenumerationapi.h>
#include <powrprof.h>
#include <sstream>
#include <thread>
#include <time.h>
#include <vector>
#include <winioctl.h>

#include "logging.h"
#include "nightshade.h"

using udp = boost::asio::ip::udp;

HANDLE timer = CreateWaitableTimer(nullptr, true, nullptr);

std::thread worker;
std::mutex m;
std::condition_variable cv;

bool worker_should_terminate = false;

boost::asio::io_context io_context;
boost::system::error_code error;

udp::socket udp_socket(io_context);

boost::array<char, 128> recieve_buffer;

std::chrono::system_clock::time_point stime;

auto remote_endpoint = boost::asio::ip::udp::endpoint(
    boost::asio::ip::address_v4::broadcast(), 4000);
auto local_endpoint =
    boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 4000);

std::atomic<bool> synchronized = false;
std::atomic<bool> suspended = false;

void process_heartbeat(
    const boost::system::error_code &error, // Result of operation.
    std::size_t bytes_transferred           // Number of bytes received.
)
{
  ns::log(__func__);
  auto rtime =
      *(std::chrono::system_clock::time_point *)(recieve_buffer.data());
  if (bytes_transferred && rtime != stime)
  {
    synchronized = true;
    ns::log("found heartbeat");
  }
  else
  {
    ns::log("heard own heartbeat");
    return udp_socket.async_receive_from(
        boost::asio::buffer(recieve_buffer), local_endpoint, process_heartbeat);
  }
}

void broadcast_synchronization_message()
{
  ns::log(__func__);
  synchronized = false;
  ::stime = std::chrono::system_clock::now();
  boost::array<std::chrono::system_clock::time_point, sizeof(::stime)>
      send_buf = {::stime};
  udp_socket.send_to(boost::asio::buffer(send_buf), remote_endpoint);
}

enum class DARKEN_RESULT : bool
{
  POWER_OFF_MONITORS = false,
  SUSPEND_OS = true
};

auto darken_screens(
    std::vector<HANDLE> &monitors,
    HWND &hWnd,
    HWND &hShell,
    bool supports_hw_power_off,
    DWORD min_brightness)
{
  ns::log(__func__);

  DISPLAY_BRIGHTNESS _displayBrightness{
      DISPLAYPOLICY_BOTH, min_brightness, min_brightness};

  DWORD nOutBufferSize = sizeof(_displayBrightness);
  DWORD ret = NULL;

  // Screen darkening happens two ways:
  // (1) turn off monitor power, or
  // (2) suspend the OS

  bool suspend = !supports_hw_power_off;

  if (supports_hw_power_off)
  {
    for (auto monitor : monitors)
    {
      if (supports_hw_power_off)
      {
        //# Turn the monitor off.
        SetVCPFeature(monitor, 0xD6, 0x04);
      }
      else if (!DeviceIoControl(
                   monitor,
                   IOCTL_VIDEO_SET_DISPLAY_BRIGHTNESS,
                   (DISPLAY_BRIGHTNESS *)&_displayBrightness,
                   nOutBufferSize,
                   NULL,
                   0,
                   &ret,
                   NULL))
      {
        throw;
      }
    }

    return DARKEN_RESULT::POWER_OFF_MONITORS;
  }
  else
  {
    auto minutes = [](long long x) { return -x * 60 * 10'000'000ll; };

    LARGE_INTEGER duration;
    duration.QuadPart = minutes(4);

    if (constexpr auto RUN_ONCE = 0;
        !SetWaitableTimer(timer, &duration, RUN_ONCE, nullptr, nullptr, true))
    {
      throw;
    }
    if (GetLastError() == ERROR_NOT_SUPPORTED)
    {
      throw;
    }

    auto wakeup_handler = []() {
      ns::log(__func__);
      if (WaitForSingleObject(timer, INFINITE) != WAIT_OBJECT_0)
      {
        throw;
      }

      // Wake up laptop monitors
      if (!SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED))
      {
        throw;
      }
      suspended = false;
    };

    // Create a new process to handle wake-up event so this thread can call
    // SetSuspendState.
    std::thread(wakeup_handler).detach();

    // Tell OS we need to keep executing in suspended state; attempts to avoid
    // entering deeper sleep states.
    if (!SetThreadExecutionState(ES_CONTINUOUS | ES_AWAYMODE_REQUIRED))
      throw;

    suspended = true;
    SetSuspendState(false, false, false);

    return DARKEN_RESULT::SUSPEND_OS;
  }
};

void brighten_screens(
    std::vector<HANDLE> &monitors,
    HWND &hWnd,
    HWND &hShell,
    bool supports_hw_power_off,
    DWORD max_brightness)
{
  ns::log(__func__);

  DISPLAY_BRIGHTNESS _displayBrightness{
      DISPLAYPOLICY_BOTH, max_brightness, max_brightness};

  // Inform OS that we want to do work during suspended state; tries to prevent
  // entering deeper sleep states that we cannot come back from.
  SetThreadExecutionState(
      ES_CONTINUOUS | ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED);

  for (auto monitor : monitors)
  {
    if (supports_hw_power_off)
    {
      //# Turn the monitor on.
      constexpr auto VCP_CODE_POWER_MODE = 0xD6;
      constexpr auto ON = 0xD6;
      SetVCPFeature(monitor, VCP_CODE_POWER_MODE, ON);
    }
    else if (DWORD ret = NULL, nOutBufferSize = sizeof(_displayBrightness);
             //# Turn monitor brightness to maximum.
             DeviceIoControl(
                 monitor,
                 IOCTL_VIDEO_SET_DISPLAY_BRIGHTNESS,
                 (DISPLAY_BRIGHTNESS *)&_displayBrightness,
                 nOutBufferSize,
                 NULL,
                 0,
                 &ret,
                 NULL))
    {
      //# Turn the monitor on (work-around for laptop monitors turning off when
      // suspended).
      constexpr auto POWER_ON = -1;
      SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, POWER_ON);
    }
    // else ...???
  }
};

auto sheduler(
    std::vector<HANDLE> &monitors,
    HWND hWnd,
    HWND hShell,
    bool supports_hw_power_off,
    DWORD max_brightness,
    DWORD min_brightness)
{
  while (!worker_should_terminate)
  {
    std::unique_lock<std::mutex> lock(m);

    SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED);

    if (!synchronized)
    {
      broadcast_synchronization_message();
    }

    brighten_screens(
        monitors, hWnd, hShell, supports_hw_power_off, max_brightness);

    // wait for some time and continue -- or exit thread when signalled.
    if (cv.wait_for(lock, std::chrono::minutes(20), []() {
          return worker_should_terminate;
        }))
    {
      return; // exit thread
    }

    // Screen can be darkened by turning off monitors or suspending the OS
    // (entering sleep modes):
    // - When the monitors are turned off we just wait before turning them back
    // on.
    // - When the OS is suspended we wait until the OS resumes.

    auto result = darken_screens(
        monitors, hWnd, hShell, supports_hw_power_off, min_brightness);

    if (result == DARKEN_RESULT::SUSPEND_OS)
    {
      ns::log("Waiting until computer wakes up.");
      cv.wait(lock, []() { return !suspended.load(); });
    }
    else
    {
      ns::log("Waiting for sleep timer.");
      if (cv.wait_for(lock, std::chrono::minutes(4), []() {
            return worker_should_terminate;
          }))
      {
        return; // exit thread
      }
    }
  }
}

/// <summary>
/// Collects all monitor HANDLEs
/// </summary>
bool query_monitors(HMONITOR Arg1, HDC Arg2, LPRECT Arg3, LPARAM Arg4)
{

  std::vector<HANDLE> *monitors = reinterpret_cast<std::vector<HANDLE> *>(Arg4);
  DWORD amount;
  GetNumberOfPhysicalMonitorsFromHMONITOR(Arg1, &amount);

  PHYSICAL_MONITOR *pMonitors = new PHYSICAL_MONITOR[amount];

  if (GetPhysicalMonitorsFromHMONITOR(Arg1, amount, pMonitors))
  {
    ns::log(ns::format(
        "Found monitor #{number}: {description}",
        monitors->size() + 1,
        pMonitors->szPhysicalMonitorDescription));
    monitors->emplace_back(pMonitors->hPhysicalMonitor);

    bool supports_power_off = false;
    DWORD max;
    if (DWORD current; supports_power_off = GetVCPFeatureAndVCPFeatureReply(
            pMonitors->hPhysicalMonitor, 0xD6, nullptr, &current, &max))
    {
      ns::log("Supports power control.");
    }

    delete[] pMonitors;
  }

  return true;
};

int main(int argc, char *argv[])
{

  udp_socket.open(udp::v4(), error);
  udp_socket.set_option(boost::asio::socket_base::broadcast(true));
  udp_socket.set_option(boost::asio::ip::udp::socket::reuse_address(true));
  udp_socket.bind(local_endpoint);

  auto hWnd = GetConsoleWindow();

  if (!timer)
  {
    throw;
  }

  // ShowWindow(hWnd, SW_HIDE);
  auto hShell = FindWindow("Shell_TrayWnd", NULL);

  std::vector<HANDLE> monitors;

  // Find handles for monitors.
  {
    // Check if there is a laptop monitor.
    HANDLE laptop_monitor = CreateFile(
        "\\\\.\\LCD",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    auto use_external_monitor = laptop_monitor == INVALID_HANDLE_VALUE;

    if (use_external_monitor)
    {
      EnumDisplayMonitors(
          nullptr,
          nullptr,
          MONITORENUMPROC(&query_monitors),
          reinterpret_cast<LPARAM>(&monitors));
    }
    else
    {
      monitors.push_back(laptop_monitor);
    }
  }

  bool supports_power_off = false;
  DWORD max;
  if (DWORD current; supports_power_off = GetVCPFeatureAndVCPFeatureReply(
                         monitors[1], 0xD6, nullptr, &current, &max))
  {
    ns::log("Supports power control.");
  }

  // Set the shutdown privilege for this process.
  {
    if (HANDLE token; OpenProcessToken(
            GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
      LUID luid;
      LookupPrivilegeValue(nullptr, SE_SHUTDOWN_NAME, &luid);

      TOKEN_PRIVILEGES priv;
      priv.PrivilegeCount = 1;
      priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
      priv.Privileges[0].Luid = luid;

      if (!AdjustTokenPrivileges(token, false, &priv, 0, nullptr, nullptr))
        throw; // throw on failure

      CloseHandle(token);
    }
    else
    {
      throw; // throw on failure
    }
  }

  auto pomodoro_timer =
      std::bind(sheduler, monitors, hWnd, hShell, supports_power_off, max, 0);
  worker = std::thread(pomodoro_timer);

  auto should_shutdown = false;
  while (!should_shutdown)
  {

    SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED);

    if (synchronized)
    {
      // Restart the worker to synchronize heartbeats
      {
        ns::log("Terminate the worker thread.");
        std::lock_guard<std::mutex> lock(m);
        worker_should_terminate = true;
        cv.notify_all();
      }
      worker.join();
      ns::log("Worker thread has joined main thread.");
      {
        // Start new worker
        worker_should_terminate = false;
        worker = std::thread(pomodoro_timer);
      }
    }
    else
    {
      worker_should_terminate = false;
    }

    // Listen for a heartbeat over the network.

    udp_socket.async_receive_from(
        boost::asio::buffer(recieve_buffer), local_endpoint, process_heartbeat);
    io_context.run(); // execution on this thread will poll here until a
                      // heartbeat is heard...
    io_context.restart();
  }

  return 0;
}
