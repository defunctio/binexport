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
project(tools CXX)

add_executable(binexport2dump binexport2dump.cc)
target_link_libraries(binexport2dump
  absl::strings
  binexport_base
  binexport_shared
  binexport_proto
)
install(TARGETS binexport2dump RUNTIME DESTINATION binexport-prefix)

# Binjadump - CLI to binjaexport
add_executable(binjadump binjadump.cc)

set_target_properties(binjadump PROPERTIES
  RPATH $ORIGIN:$ORIGIN/plugins
  INSTALL_RPATH $ORIGIN:$ORIGIN/plugins
  )

find_library(DL_LIBRARIES dl)
MESSAGE(STATUS "DL_LIBRARIES:" ${DL_LIBRARIES})

target_link_libraries(binjadump
  absl::strings
  binexport_base
  binjaexport
  #  ${DL_LIBRARIES}
  -ldl # TODO: fix dl
)

install(TARGETS binjadump RUNTIME DESTINATION binexport-prefix)