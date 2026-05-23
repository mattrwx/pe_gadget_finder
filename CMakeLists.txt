cmake_minimum_required(VERSION 3.20)

project(pe_gadget_finder)

include(FetchContent)

FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        master
    GIT_SUBMODULES_RECURSE ON
)

set(ZYDIS_BUILD_TOOLS    OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS    OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(zydis)

add_executable(pe_gadget_finder src/main.cpp)

target_compile_features(pe_gadget_finder PRIVATE cxx_std_20)

target_link_libraries(pe_gadget_finder PRIVATE Zydis)