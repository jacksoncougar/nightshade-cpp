# Nightshade

Nightshade helps you work smarter by forcing you to take breaks throughout the day. 
It works by turning the power off on your monitors after you have been working for 
a while then turning them back on after you've taken a break. Rinse and repeat.

If you've ever struggled with taking breaks, found secondary tasks lagging behind, 
or feel overworked this might be the solution for you.

<blockquote>
<i style="font-size:xx-small">ask your doctor if this executable is right for you</i>
</blockquote>

## Highlights

- Encourages break taking and multitasking by turning off all monitors after 20 minutes; then automatically turning them back on after 4 minutes.
- Multiple computers can be synchronized across a local network to encourage break-taking at the same time.

## Implementation Details

- Win32 power management APIs and the [VESA Monitor Control Command Set (MCCS)](https://en.wikipedia.org/wiki/Monitor_Control_Command_Set) are used to find and control the attached displays.
- Uses boost::asio to synchronize multiple nightshade clients across the local network using a UDP broadcast mechanism.
- Uses synchronization mechanisms to handle timers -- results in zero CPU utilization between timer events.
- Multi-threaded design.

# Demo

[![nightshade-cpp demo video](https://img.youtube.com/vi/xcMDlMT4uXc/0.jpg)](https://www.youtube.com/watch?v=xcMDlMT4uXc)

## Dependencies

- Boost (asio)

## TODO:

- [x] Multi-monitor support
- [ ] Program options
- [ ] Customizable durations
- [ ] Events


## Bugs/Broken Behaviours

- [ ] Should only power on monitors that have been powered off by the program.

