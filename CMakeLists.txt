cmake_minimum_required(VERSION 3.10)
project(tcpstack C)
include_directories(include)

set(CMAKE_C_STANDARD 11)


add_executable(learnc
        src/main.c
        src/utils.c
        src/skbuff.c
        src/tap.c
        src/eth.c
        src/arp.c
        src/ipv4.c
        src/icmp.c
        src/tcp.c
        src/tcp_out.c
        src/tcp_in.c)