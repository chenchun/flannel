cmake_minimum_required(VERSION 3.10)
project(ip C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(ip
        ip_proxy_amd64.c
        ip_proxy_amd64.h)
