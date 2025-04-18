#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2018-2020 Alexey Moskvin
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

find_package(Boost REQUIRED COMPONENTS filesystem unit_test_framework)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       ${CMAKE_WORKSPACE_NAME}::algebra
                       ${CMAKE_WORKSPACE_NAME}::hash
                       ${CMAKE_WORKSPACE_NAME}::mac
                       ${CMAKE_WORKSPACE_NAME}::stream
                       ${CMAKE_WORKSPACE_NAME}::multiprecision

                       marshalling::crypto3_algebra

                       ${Boost_LIBRARIES})

#cm_test(NAME ${CURRENT_PROJECT_NAME}_chacha_test SOURCES ${CURRENT_TEST_SOURCES_DIR}/chacha.cpp)
#set_target_properties(${CURRENT_PROJECT_NAME}_chacha_test PROPERTIES CXX_STANDARD 17)
#target_include_directories(${CURRENT_PROJECT_NAME}_chacha_test PRIVATE
#                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
#                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

#                           ${Boost_INCLUDE_DIRS})

cm_test(NAME ${CURRENT_PROJECT_NAME}_hash_test SOURCES ${CURRENT_TEST_SOURCES_DIR}/hash.cpp)
set_target_properties(${CURRENT_PROJECT_NAME}_hash_test PROPERTIES CXX_STANDARD 17)
target_include_directories(${CURRENT_PROJECT_NAME}_hash_test PRIVATE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           ${Boost_INCLUDE_DIRS})

cm_test(NAME ${CURRENT_PROJECT_NAME}_algebraic_engine_test SOURCES ${CURRENT_TEST_SOURCES_DIR}/algebraic_engine.cpp)
set_target_properties(${CURRENT_PROJECT_NAME}_algebraic_engine_test PROPERTIES CXX_STANDARD 17)
target_include_directories(${CURRENT_PROJECT_NAME}_algebraic_engine_test PRIVATE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           ${Boost_INCLUDE_DIRS})

cm_test(NAME ${CURRENT_PROJECT_NAME}_rfc6979_engine_test SOURCES ${CURRENT_TEST_SOURCES_DIR}/rfc6979.cpp)
set_target_properties(${CURRENT_PROJECT_NAME}_rfc6979_engine_test PROPERTIES CXX_STANDARD 17)
target_include_directories(${CURRENT_PROJECT_NAME}_rfc6979_engine_test PRIVATE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           ${Boost_INCLUDE_DIRS})

include_directories(${CMAKE_WORKSPACE_SOURCES_DIR})