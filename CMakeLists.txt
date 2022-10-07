cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

file(GLOB SOURCES
    ./src/*.cpp
    ./src/*.hpp
    ./src/*.h
)

project(openssl-test LANGUAGES CXX)

find_package(OpenSSL REQUIRED)
message("OpenSSL version: " ${OPENSSL_VERSION})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})

target_link_libraries(${CMAKE_PROJECT_NAME} ${OPENSSL_CRYPTO_LIBRARY})

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)