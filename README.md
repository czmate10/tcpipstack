# User-space TCP/IP stack
I started working on this project to learn more about TCP and IPv4, and possibly IPv6 later on.  
Right now it's just a very basic TCP implementation that is able to connect, disconnect, send data(if size < MSS) and read incoming segments' payload.  
Please refer to [src/main.c](https://github.com/czmate10/tcpipstack/blob/master/src/main.c) to see an example HTTP GET request.

# Requirements
- TAP device:
```
ip tuntap add tap0 mode tap
ip link set dev tap0 up
ip route add dev tap0 10.0.0.0/24
ip address add dev tap0 local 10.0.0.10
```

# Simple HTTP client
After compiling the project, you can run it with:
`tcpipstack -h 10.0.0.10 -p 80`  
This will connect to an HTTP server running on 10.0.0.10:80

# To-do
- Clean up code, add documentation for functions and unit tests
- Add IPv6 support
- TCP write fragmentation
- TCP congestion control
- TCP selective ARQ
- Socket API for users

# Thanks to
- [level-ip by saminiir](https://github.com/saminiir/level-ip)
- [TCP/IP Illustrated, Volume 1](https://www.amazon.com/dp/0201633469)
- [TCP/IP Illustrated, Volume 2](https://www.amazon.com/dp/0134760131)
