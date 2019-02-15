cmake_minimum_required(VERSION 3.10)
project(tcpipstack C)
set(CMAKE_C_STANDARD 11)

include_directories(include)

add_executable(tcpipstack
        src/main.c
        src/utils.c
        src/skbuff.c
        src/tap.c
        src/eth.c
        src/arp.c
        src/ipv4.c
        src/icmp.c
        src/tcp.c
        src/tcp_socket.c
        src/tcp_out.c
        src/tcp_in.c)

# C11
set_property(TARGET tcpipstack PROPERTY C_STANDARD 11)

# pthread
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(tcpipstack Threads::Threads)