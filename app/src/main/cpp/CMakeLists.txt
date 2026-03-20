cmake_minimum_required(VERSION 3.22.1)
project("application")

find_package(bytehook REQUIRED CONFIG)

add_library(hacker SHARED
    hacker.cpp
    hook_test.cpp
    monitor.cpp)


target_link_libraries(hacker
    android
    log
    bytehook::bytehook
    unwind
)

add_library(sample SHARED
    sample.cpp)

target_include_directories(hacker PUBLIC .)

target_link_libraries(sample
    log)