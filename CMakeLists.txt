cmake_minimum_required(VERSION 3.10)
project(kreo-daemon)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)
find_package(Threads REQUIRED)

include_directories(${LIBUSB_INCLUDE_DIRS})
link_directories(${LIBUSB_LIBRARY_DIRS})

add_executable(kreo-daemon src/main.cpp)

target_link_libraries(kreo-daemon ${LIBUSB_LIBRARIES} Threads::Threads)

# INSTALLATION

install(TARGETS kreo-daemon DESTINATION bin)

