ExternalProject_Add(binaryninja-api
  GIT_REPOSITORY https://github.com/Vector35/binaryninja-api.git
  GIT_TAG master # living on the edge
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/binaryninja-api
  # Just use CMake to clone into directory
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  )