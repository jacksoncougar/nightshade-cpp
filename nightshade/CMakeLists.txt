# CMakeList.txt : CMake project for nightshade, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

find_path(BOOST_ASIO_INCLUDE boost/asio.hpp)
include_directories(${BOOST_ASIO_INCLUDE})
# Add source to this project's executable.
add_executable (nightshade "nightshade.cpp" "nightshade.h")

# TODO: Add tests and install targets if needed.

find_library(ws2_32_LIBRARY_PATH ws2_32)
target_link_libraries(nightshade ${ws2_32_LIBRARY_PATH})
