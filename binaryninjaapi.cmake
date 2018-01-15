find_path(binaryninjaapi_src_dir
  binaryninjaapi.h
  HINTS ${BINARYNINJAAPI_DIR}
  PATHS ${PROJECT_BINARY_DIR}/binaryninja-api
  )
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory(${binaryninjaapi_src_dir})
