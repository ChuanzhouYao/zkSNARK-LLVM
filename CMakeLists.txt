cmake_minimum_required(VERSION 3.2)

cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0063 NEW)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

include(CMConfig)
include(CMSetupVersion)

cm_workspace(zkllvm)

macro(cm_find_package NAME)
    if(NOT "${NAME}" MATCHES "^${CMAKE_WORKSPACE_NAME}_.*$" AND NOT "${NAME}" STREQUAL CM)
        find_package(${ARGV})
    else()
        set(${ARGV0}_FOUND ON CACHE BOOL "")
    endif()
endmacro()

cm_setup_version(VERSION 0.3.0 PREFIX ${CMAKE_WORKSPACE_NAME})

option(BUILD_SHARED_LIBS "Build shared library" TRUE)
option(BUILD_WITH_CCACHE "Build with ccache usage" TRUE)
option(BUILD_WITH_BOOST_STATIC_LIBS "Build using Boost static libraries" TRUE)
option(BUILD_TESTS "Build unit tests" FALSE)
option(BUILD_DOCS "Build with configuring Doxygen documentation compiler" TRUE)
option(CIRCUIT_BINARY_OUTPUT "Emit circuit IR as binary file" FALSE)
option(RSLANG_BUILD_EXTENDED "Build Rust tools (see build.extended)" FALSE)

set(BUILD_WITH_TARGET_ARCHITECTURE "" CACHE STRING "Target build architecture")
set(DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_LIST_DIR}/docs" CACHE STRING "Specify doxygen output directory")
set(ZKLLVM_DEV_ENVIRONMENT TRUE)
set(RSLANG_BUILD_STAGE "2" CACHE STRING "Stage to build (see --stage)")
set(RSLANG_CONFIG ${CMAKE_CURRENT_BINARY_DIR}/libs/rslang/config.toml CACHE STRING "Path to Rust config file")
set(RSLANG_BUILD_TOOLS "<none>" CACHE STRING "Rust tools to build (see build.tools)")

include(TargetArchitecture)
include(CircuitCompile)

if(BUILD_WITH_BOOST_STATIC_LIBS)
    set(Boost_USE_STATIC_LIBS TRUE)
else()
    set(Boost_USE_STATIC_LIBS FALSE)
endif()

if(UNIX AND BUILD_WITH_CCACHE)
    find_program(CCACHE_FOUND ccache)
    if(CCACHE_FOUND)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
    endif(CCACHE_FOUND)
endif()

if(BUILD_WITH_TARGET_ARCHITECTURE)
    set(CMAKE_TARGET_ARCHITECTURE ${BUILD_WITH_TARGET_ARCHITECTURE})
else()
    target_architecture(CMAKE_TARGET_ARCHITECTURE)
endif()

if(BUILD_TESTS)
    cm_find_package(Boost COMPONENTS REQUIRED unit_test_framework)
endif()

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/libs/crypto3")
#
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/libs/blueprint")
#add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/libs/assigner")
#add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/libs/libsnark")

set(LLVM_ENABLE_PROJECTS "clang" CACHE STRING "Additional llvm projects")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/libs/circifier/llvm")

add_subdirectory(examples)
#if(BUILD_TESTS)
#  add_subdirectory(tests)
#endif()

add_subdirectory(libs/stdlib)

install(FILES cmake/CircuitCompile.cmake DESTINATION share/zkllvm)

find_package(Git REQUIRED)



# 指定生成 Debian 包
set(CPACK_GENERATOR DEB)

# 使用默认的 .deb 文件名格式（推荐）
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

# 设置维护者信息
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "YCZ")

# 声明依赖项（基础编译工具链）
set(CPACK_DEBIAN_PACKAGE_DEPENDS "build-essential")

#set(CPACK_PACKAGE_VERSION "${ZKLLVM_VERSION_MAJOR}.${ZKLLVM_VERSION_MINOR}.${ZKLLVM_VERSION_PATCH}")
#if(ZKLLVM_VERSION_INCREMENT)
#    string(APPEND CPACK_PACKAGE_VERSION "-${ZKLLVM_VERSION_INCREMENT}")
#endif()
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr/lib/zkllvm")

configure_file("${CMAKE_CURRENT_LIST_DIR}/cmake/zkllvm.conf.in"
               "${CMAKE_CURRENT_BINARY_DIR}/zkllvm.conf"
               NO_SOURCE_PERMISSIONS
               @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/zkllvm.conf" DESTINATION /etc/ld.so.conf.d)

set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_LIST_DIR}/cmake/triggers")
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)

message(${CMAKE_INSTALL_FULL_LIBDIR})

install(SCRIPT cmake/create-symlinks.cmake)

include(CPack)

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/bin")

#find_package(Python3 REQUIRED COMPONENTS Interpreter)
