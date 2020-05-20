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
std::condition_variable sleep_timer_set;

std::chrono::minutes focus_duration(20);
std::chrono::minutes break_duration(4);

bool worker_should_terminate = false;

boost::asio::io_context io_context;
boost::system::error_code error;

udp::socket udp_socket(io_context);

boost::array<char, 128> recieve_buffer;

std::chrono::system_clock::time_point stime;

auto remote_endpoint = boost::asio::ip::udp::endpoint(
    boost::asio::ip::address_v4::broadcast(),
    4000);

auto local_endpoint =
    boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 4000);

std::atomic<bool> synchronized = false;
bool suspended = false;

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
    ns::log("Received synchronization message.");
  }
  else
  {
    ns::log("Received my own synchronization message.");
    return udp_socket.async_receive_from(
        boost::asio::buffer(recieve_buffer),
        local_endpoint,
        process_heartbeat);
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
        if (constexpr auto VCP_CODE_POWER_MODE = 0xD6, OFF = 0x04;
            SetVCPFeature(monitor, VCP_CODE_POWER_MODE, OFF))
        {
          ns::log("Success powering down display.");
        }
        else
        {
          ns::log("Failure powering down display.");
        }
      }
      else
      {
        std::array<std::uint8_t, 256> brightness_level_values;
        DWORD total_brightness_levels;
        DeviceIoControl(
            monitor,
            IOCTL_VIDEO_QUERY_SUPPORTED_BRIGHTNESS,
            nullptr,
            0,
            &brightness_level_values,
            256,
            &total_brightness_levels,
            NULL);
        auto min_brightness =
            brightness_level_values[total_brightness_levels - 1];

        DISPLAY_BRIGHTNESS _displayBrightness{
            DISPLAYPOLICY_BOTH,
            min_brightness,
            min_brightness};

        DWORD nOutBufferSize = sizeof(_displayBrightness);
        DWORD ret = NULL;

        if (DeviceIoControl(
                monitor,
                IOCTL_VIDEO_SET_DISPLAY_BRIGHTNESS,
                (DISPLAY_BRIGHTNESS *)&_displayBrightness,
                nOutBufferSize,
                NULL,
                0,
                &ret,
                NULL))
        {
          ns::log("Lowering monitor brightness.");
        }
        else
        {
          ns::log("Failure lowering monitor brightness.");
        }
      }
    }

    return DARKEN_RESULT::POWER_OFF_MONITORS;
  }
  else
  {
    auto minutes = [](auto &&time) {
      using T = std::decay_t<decltype(time)>;
      if constexpr (std::is_convertible_v<T, long long>)
        return -static_cast<long long>(time) * 60 * 10'000'000ll;
      else if constexpr (std::is_same_v<T, std::chrono::minutes>)
        return -static_cast<std::chrono::minutes>(time).count() * 60 *
               10'000'000ll;
      else if constexpr (std::is_same_v<T, std::chrono::seconds>)
        return -static_cast<std::chrono::seconds>(time).count() * 10'000'000ll;
      else
        static_assert(false, "Cannot convert given valuetype into minutes");
    };

    LARGE_INTEGER duration;
    auto t = break_duration.count();
    duration.QuadPart = minutes(break_duration);

    if (constexpr auto RUN_ONCE = 0;
        !SetWaitableTimer(timer, &duration, RUN_ONCE, nullptr, nullptr, true))
    {
      ns::log("Failure set wait timer (error #{e}).", GetLastError());
    }

    if (!SetThreadExecutionState(ES_CONTINUOUS))
    {
      ns::log("Failure setting execution state.");
    }

    // Create a new thread to handle wake-up.
    std::thread([]() {
      ns::log("wake_timer_thread");

      if (!(WaitForSingleObject(timer, INFINITE) == WAIT_OBJECT_0))
      {
        ns::log("Failure wait on timer.");
      }
      // Wake up laptop monitors
      if (!SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED))
      {
        ns::log("Failure setting execution state.");
      }
      ns::log("Wait timer expired");
      suspended = false;
      cv.notify_all();
    }).detach();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Tell OS we need to keep executing in suspended state; attempts to avoid
    // entering deeper sleep states.
    if (!SetThreadExecutionState(ES_CONTINUOUS | ES_AWAYMODE_REQUIRED))
    {
      ns::log("Failure setting execution state.");
    }
    // hack

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

  // Inform OS that we want to do work during suspended state; tries to prevent
  // entering deeper sleep states that we cannot come back from.
  SetThreadExecutionState(
      ES_CONTINUOUS | ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED);

  for (auto monitor : monitors)
  {
    if (supports_hw_power_off)
    {
      constexpr auto VCP_CODE_POWER_MODE = 0xD6;
      constexpr auto ON = 0x01;
      if (SetVCPFeature(monitor, VCP_CODE_POWER_MODE, ON))
      {
        ns::log("Success powering up display.");
      }
      else
      {
        ns::log("Failure powering up display.");
      }
    }
    else
    {
      std::array<std::uint8_t, 256> brightness_level_values;
      DWORD total_brightness_levels;
      DeviceIoControl(
          monitor,
          IOCTL_VIDEO_QUERY_SUPPORTED_BRIGHTNESS,
          nullptr,
          0,
          &brightness_level_values,
          256,
          &total_brightness_levels,
          NULL);
      max_brightness = brightness_level_values[total_brightness_levels - 1];

      DISPLAY_BRIGHTNESS _displayBrightness{
          DISPLAYPOLICY_BOTH,
          max_brightness,
          max_brightness};

      if (DWORD ret, nOutBufferSize = sizeof(_displayBrightness);
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

        ns::log("Increase display brightness.");
        // Turn the monitor on (work-around for laptop monitors turning off
        // when suspended).
        ns::log("Power up display.");

        SetThreadExecutionState(
            ES_CONTINUOUS | ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED);

        constexpr auto POWER_ON = -1;
        SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, POWER_ON);
      }
      else
      {
        ns::log(ns::format(
            "Failed to increase display brightness (error #{e}).",
            GetLastError()));
        ns::log("Failure powering up display.");
      }
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

    if (!synchronized)
    {
      broadcast_synchronization_message();
    }

    brighten_screens(
        monitors,
        hWnd,
        hShell,
        supports_hw_power_off,
        max_brightness);

    {
      // This code tries to froce the monitor to stay on without user
      // interaction when returning from sleep. Does this by turning on the
      // monitor every second...
    
        bool die = false;
      auto notify_thread = std::thread([&die]() {
        while (!die)
        {
          std::this_thread::sleep_for(std::chrono::seconds(1));
          cv.notify_all();
        }
      });

      // wait for some time and continue -- or exit thread when signaled.
      if (cv.wait_for(lock, focus_duration, []() {
            ns::log("waiting...");
            constexpr auto POWER_ON = -1;
            SendMessage(
                HWND_BROADCAST,
                WM_SYSCOMMAND,
                SC_MONITORPOWER,
                POWER_ON);

            SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED);
            return worker_should_terminate;
          }))
      {
        die = true;
        notify_thread.join();
        return; // exit thread
      }
      die = true;
      notify_thread.join();
    }

    // Screen can be darkened by turning off monitors or suspending the OS
    // (entering sleep modes):
    // - When the monitors are turned off we just wait before turning them back
    // on.
    // - When the OS is suspended we wait until the OS resumes.

    auto result = darken_screens(
        monitors,
        hWnd,
        hShell,
        supports_hw_power_off,
        min_brightness);

    if (result == DARKEN_RESULT::SUSPEND_OS)
    {
      ns::log("Waiting until computer wakes up.");
      cv.wait(lock, []() { return !suspended; });
    }
    else
    {
      ns::log("Waiting for sleep timer.");
      if (cv.wait_for(lock, break_duration, []() {
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
                           pMonitors->hPhysicalMonitor,
                           0xD6,
                           nullptr,
                           &current,
                           &max))
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
                         monitors[0],
                         0xD6,
                         nullptr,
                         &current,
                         &max))
  {
    ns::log("Supports power control.");
  }

  // Set the shutdown privilege for this process.
  {
    if (HANDLE token; OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &token))
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
        boost::asio::buffer(recieve_buffer),
        local_endpoint,
        process_heartbeat);
    io_context.run(); // execution on this thread will poll here until a
                      // heartbeat is heard...
    io_context.restart();
  }

  return 0;
}
