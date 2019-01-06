# User-space TCP/IP stack
I started working on this project to learn more about TCP and IPv4, and possibly IPv6 later on.

# Requirements
- TAP device:
```
ip tuntap add tap0 mode tap
ip link set dev tap0 up
ip route add dev tap0 10.0.0.0/24
ip address add dev tap0 local 10.0.0.10
```

# Thanks to
- [level-ip by saminiir](https://github.com/saminiir/level-ip)
- [TCP/IP Illustrated, Volume 1](https://www.amazon.com/dp/0201633469)
- [TCP/IP Illustrated, Volume 2](https://www.amazon.com/dp/0134760131)
