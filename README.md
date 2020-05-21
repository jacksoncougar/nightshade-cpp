# Nightshade

Nightshade helps you work smarter by forcing you to take breaks throughout the day. 
It works by turning the power off on your monitors after you have been working for 
a while then turning them back on after you've taken a break. Rinse and repeat.

If you've ever struggled with taking breaks, found secondary tasks lagging behind, 
or feel overworked this might be the solution for you.


## Demo

[![nightshade-cpp demo video](https://img.youtube.com/vi/xcMDlMT4uXc/0.jpg)](https://www.youtube.com/watch?v=xcMDlMT4uXc)

## Highlights

- Encourages break taking and multitasking by turning off all monitors after 20 minutes; then automatically turning them back on after 4 minutes.
- Multiple computers can be synchronized across a local network to encourage break-taking at the same time.

## Implementation Details

- Win32 power management APIs and the [VESA Monitor Control Command Set (MCCS)](https://en.wikipedia.org/wiki/Monitor_Control_Command_Set) are used to find and control the attached displays.
- Uses boost::asio to synchronize multiple nightshade clients across the local network using a UDP broadcast mechanism.
- Uses synchronization mechanisms to handle timers -- results in zero CPU utilization between timer events.
- Multi-threaded design.

## Usage

    nightshade [OPTION...]

    -d, --debug              Enable console window
    -f, --focus [=arg(=20)]  Number of minutes in a work interval (default: 20)

    -b, --break [=arg(=20)]  Number of minutes in a break (default: 4)
    -h, --help               Print usage

## Dependencies

- Boost (asio) - 
- cxxopts - https://github.com/jarro2783/cxxopts

## TODO:

- [ ] Windows Logging
- [ ] Events

- [x] Multi-monitor support
- [x] Program options
- [x] Customizable durations


## Bugs/Broken Behaviours

- [ ] Should only power on monitors that have been powered off by the program.
- [ ] Multiple clients should synchronize smallest time remaining.

