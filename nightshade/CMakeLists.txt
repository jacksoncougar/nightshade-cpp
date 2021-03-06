﻿# CMakeList.txt : CMake project for nightshade, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.14)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /EHsc")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd /EHsc")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED)
set(Boost_USE_STATIC_LIBS ON)

# Add source to this project's executable.
add_executable (nightshade "nightshade.cpp" "nightshade.h" "logging.h")
set_property(TARGET nightshade PROPERTY CXX_STANDARD 17
PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# TODO: Add tests and install targets if needed.

target_link_libraries(nightshade 
PRIVATE Boost::boost 
PRIVATE cxxopts)
