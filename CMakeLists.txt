# Copyright 2011-2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.7)
cmake_policy(VERSION 3.7)
project(binexport VERSION 10)  # Only major version is used

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})
include(copts.cmake)
include(util.cmake)

# Use a copy of a subset of Boost that we ship
set(Boost_NO_SYSTEM_PATHS TRUE)
set(BOOST_ROOT ${PROJECT_SOURCE_DIR}/third_party/boost_parts)

set(OPENSSL_USE_STATIC_LIBS TRUE)
set(Protobuf_USE_STATIC_LIBS TRUE)

find_package(Boost 1.55 REQUIRED)
find_package(Git)
find_package(IdaSdk)
find_package(BNSdk)
find_package(OpenSSL 1.0.2 REQUIRED)
find_package(PostgreSQL 9.5 REQUIRED)
find_package(Protobuf 3.0.0 REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig)
pkg_search_module(CAPSTONE REQUIRED capstone)
include(cctz.cmake)
include(googletest.cmake)
include(absl.cmake)

enable_testing()

if (WIN32)
  list(GET PostgreSQL_LIBRARIES 0 postgresql_lib)
  get_filename_component(postgresql_root ${postgresql_lib} DIRECTORY)
  list(APPEND PostgreSQL_LIBRARIES ${postgresql_root}/libpgport.lib)
endif ()

# Make Google-style includes work
set(_binexport_src ${PROJECT_BINARY_DIR}/src_include/third_party/zynamics)
set(_binexport_gen ${PROJECT_BINARY_DIR}/gen_include/third_party/zynamics)
create_directory_symlink(${PROJECT_SOURCE_DIR} ${_binexport_src}/binexport)
create_directory_symlink(${absl_src_dir}/absl ${_binexport_src}/../absl)
create_directory_symlink(${PROJECT_BINARY_DIR} ${_binexport_gen}/binexport)

# Find the Git revision number, if applicable
set(REVISION unknown)
if (GIT_FOUND)
  execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
    OUTPUT_VARIABLE REVISION ERROR_QUIET)
  if (NOT ${REVISION} STREQUAL "")
    string(STRIP ${REVISION} REVISION)
  else ()
    set(REVISION internal)
  endif ()
endif ()

configure_file(version.h.in version.h ESCAPE_QUOTES @ONLY)

# Interface library with include paths used by BinExport
add_library(binexport_base INTERFACE)
target_include_directories(binexport_base INTERFACE
  ${PROJECT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/stubs
  ${PROJECT_BINARY_DIR}/src_include
  ${PROJECT_BINARY_DIR}/gen_include
  ${absl_src_dir}
  ${cctz_src_dir}/include
  ${Boost_INCLUDE_DIR}
  ${PostgreSQL_INCLUDE_DIRS}
  ${Protobuf_INCLUDE_DIRS}
  )
target_link_libraries(binexport_base INTERFACE
  ${Protobuf_LIBRARIES}  # Same as protobuf::libprotobuf
  )

# Interface library to be used by all tests
add_library(binexport_test INTERFACE)
target_link_libraries(binexport_test INTERFACE
  gtest_main
  )

# BinExport format version 2 proto library
protobuf_generate_cpp(binexport2_proto binexport2_proto_h binexport2.proto)
add_library(binexport_proto STATIC
  ${binexport2_proto_h}
  ${binexport2_proto}
  )
target_link_libraries(binexport_proto PUBLIC
  binexport_base
  )

# Utility library code shared with BinDiff
add_library(binexport_shared STATIC
  filesystem_util.cc
  timer.h
  )
target_link_libraries(binexport_shared PUBLIC
  absl::strings
  binexport_base
  )
if (WIN32)
  target_link_libraries(binexport_shared PUBLIC
    shlwapi.lib
    )
endif ()
add_executable(binexport_shared_test
  filesystem_util_test.cc
  timer_test.cc
  )
target_link_libraries(binexport_shared_test PUBLIC
  binexport_test
  binexport_shared
  )
add_test(BinExportTests binexport_shared_test)

# binexport2dump tool
add_subdirectory(tools)

# Code shared with the BinDiff plugin
add_library(binexport_plugin_shared STATIC
  hash.cc
  hash.h
  hex_codec.cc
  hex_codec.h
  #  ida/digest.cc
  #  ida/digest.h
  #  ida/log.cc
  #  ida/log.h
  )
target_compile_definitions(binexport_plugin_shared PUBLIC
  ${IdaSdk_PLATFORM}
  __IDP__
  USE_DANGEROUS_FUNCTIONS
  USE_STANDARD_FILE_FUNCTIONS)
target_include_directories(binexport_plugin_shared PUBLIC
  ${IdaSdk_INCLUDE_DIRS}
  )
target_link_libraries(binexport_plugin_shared PUBLIC
  absl::time
  binexport_base
  OpenSSL::Crypto
  )

if (BNSdk_DIR)
  # BinjaExport static library
  set(name binjaexport)
  add_library(${name} STATIC
    binaryninja/binja_export.cc
    binaryninja/bntypes_container.cc
    binexport2_writer.cc
    dump_writer.cc
    database_writer.cc
    call_graph.cc
    edge.cc
    operand.cc
    hex_codec.cc
    query_builder.cc
    instruction.cc
    filesystem_util.cc
    base_types.cc
    x86_nop.cc
    comment.cc
    virtual_memory.cc
    type_system.cc
    tools/binexport2dump.cc
    hash.cc
    entry_point.cc
    chain_writer.cc
    library_manager.cc
    expression.cc
    postgresql.cc
    postgresql.h
    flow_analyzer.cc
    statistics_writer.cc
    address_references.cc
    function.cc
    flow_graph.cc
    basic_block.cc
    )

#  set_target_properties(${name} PROPERTIES PREFIX "")

  find_library(BINJA_API_LIBRARY binaryninjaapi
    HINTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/binaryninja/binaryninja-api/bin
    )

  MESSAGE("BNSdk_DIR:" ${BNSdk_DIR})

  find_library(BINJA_CORE_LIBRARY binaryninjacore
    HINTS ${BNSdk_DIR}
    # ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/binaryninja
    )

  # Interface for base deps

  add_library(binja_base INTERFACE)
  target_include_directories(binja_base INTERFACE
    ${BNSdk_INCLUDE_DIRS}
    ${CAPSTONE_INCLUDE_DIRS}
    )

  if (UNIX)

    if (APPLE)
      target_link_libraries(binja_base INTERFACE ${_bn_cflag}
        -Wl,-flat_namespace
        -Wl,-undefined,warning
        -Wl,-exported_symbol,_PLUGIN)
    else ()
        target_link_libraries(binja_base INTERFACE
          -Wl,-L${BNSdk_DIR} -Wl,-lbinaryninjacore
          ${BINJA_API_LIBRARY}
#          ${BINJA_CORE_LIBRARY}
          )
    endif ()

  elseif (WIN32)
    #    set(BNSdk_LIBRARY ${BNSdk_DIR}/lib/${_bn_prefix}_win_vc_64/ida.lib)
    #    target_link_libraries(${name} ${BNSdk_LIBRARY})
  endif ()

  set_target_properties(
    ${name} PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    RPATH ./:../
    INSTALL_RPATH ./:../
  )

  set(binexport_libraries ${BnSdk_LIBRARIES}
    absl::strings
    absl::time
    binexport_proto
    binexport_shared
    binexport_plugin_shared
    ${PostgreSQL_LIBRARIES}
    # OpenSSL must come after PostgreSQL
    OpenSSL::SSL
    ${CAPSTONE_LIBRARIES}
    )


  target_link_libraries(${name}
    binja_base
    ${binexport_libraries}
    )

  install(TARGETS ${name}
    ARCHIVE DESTINATION binexport-prefix
    RUNTIME DESTINATION binexport-prefix
    LIBRARY DESTINATION binexport-prefix/plugins)


  # Plugin
  add_library(${name}_plugin SHARED
    binaryninja/binja_export_plugin.cc
    )

  target_link_libraries(${name}_plugin
    binja_base
    ${name}
    ${binexport_libraries}
    )

  set_target_properties(
    ${name}_plugin PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    RPATH ./:../
    INSTALL_RPATH ./:../
  )

  install(TARGETS ${name}_plugin
    ARCHIVE DESTINATION binexport-prefix
    RUNTIME DESTINATION binexport-prefix
    LIBRARY DESTINATION binexport-prefix/plugins)
endif ()

if (IdaSdk_DIR)
  set(binexport_plugin_name binexport${RELEASE})
  add_ida_plugin(${binexport_plugin_name} EA64
    address_references.cc
    address_references.h
    base_types.cc
    base_types.h
    basic_block.cc
    basic_block.h
    binexport2_writer.cc
    binexport2_writer.h
    call_graph.cc
    call_graph.h
    chain_writer.cc
    chain_writer.h
    comment.cc
    comment.h
    database_writer.cc
    database_writer.h
    dump_writer.cc
    dump_writer.h
    edge.cc
    edge.h
    entry_point.cc
    entry_point.h
    expression.cc
    expression.h
    flow_analyzer.cc
    flow_analyzer.h
    flow_graph.cc
    flow_graph.h
    function.cc
    function.h
    ida/arm.cc
    ida/arm.h
    ida/dalvik.cc
    ida/dalvik.h
    ida/generic.cc
    ida/generic.h
    ida/main_plugin.cc
    ida/metapc.cc
    ida/metapc.h
    ida/mips.cc
    ida/mips.h
    ida/names.cc
    ida/names.h
    ida/ppc.cc
    ida/ppc.h
    ida/types_container.cc
    ida/types_container.h
    ida/ui.cc
    ida/ui.h
    initialize_constraints_postgresql_sql.h
    initialize_indices_postgresql_sql.h
    initialize_tables_postgresql_sql.h
    instruction.cc
    instruction.h
    library_manager.cc
    library_manager.h
    maintenance_postgresql_sql.h
    operand.cc
    operand.h
    postgresql.cc
    postgresql.h
    query_builder.cc
    query_builder.h
    statistics_writer.cc
    statistics_writer.h
    type_system.cc
    type_system.h
    version.h
    virtual_memory.cc
    virtual_memory.h
    x86_nop.cc
    x86_nop.h
    )
  set(binexport_libraries ${IdaSdk_LIBRARIES}
    absl::strings
    absl::time
    binexport_proto
    binexport_shared
    Threads::Threads
    binexport_plugin_shared
    ${PostgreSQL_LIBRARIES}
    # OpenSSL must come after PostgreSQL
    OpenSSL::SSL)
  if (WIN32)
    list(APPEND binexport_libraries crypt32.lib
      secur32.lib
      shlwapi.lib
      ws2_32.lib
      wldap32.lib)
  endif ()
  target_link_libraries(${binexport_plugin_name}${_plx}
    ${binexport_libraries}
    )
  target_link_libraries(${binexport_plugin_name}${_plx64}
    ${binexport_libraries}
    )
  set_target_properties(
    ${binexport_plugin_name}${_plx}
    ${binexport_plugin_name}${_plx64}
    PROPERTIES POSITION_INDEPENDENT_CODE ON
  )
  install(TARGETS ${binexport_plugin_name}${_plx}
    ${binexport_plugin_name}${_plx64}
    ARCHIVE DESTINATION binexport-prefix
    RUNTIME DESTINATION binexport-prefix
    LIBRARY DESTINATION binexport-prefix)
endif ()