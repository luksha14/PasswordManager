cmake_minimum_required(VERSION 3.15)
project(PasswordManager)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Svi izvori
file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

# Dodaj sqlite amalgamation kao izvor (ako koristiš third_party/sqlite/sqlite3.c)
set(SQLITE_SOURCE_FILE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite/sqlite3.c)
list(APPEND SOURCES ${SQLITE_SOURCE_FILE})

add_executable(password_manager ${SOURCES})

# include za sqlite header
target_include_directories(password_manager PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite)

# Link OpenSSL (mora ga pronaći: vcpkg ili sistemski)
find_package(OpenSSL REQUIRED)
target_link_libraries(password_manager PRIVATE OpenSSL::Crypto)


