cmake_minimum_required(VERSION 4.0)
project(netsec_project C)

set(CMAKE_C_STANDARD 11)

add_executable(ca_server main.c
)

target_include_directories(ca_server PUBLIC "C:/Program Files/openssl-3.5.2/openssl-3.5.2/include")
