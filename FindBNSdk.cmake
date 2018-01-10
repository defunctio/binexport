find_path(BNSdk_DIR NAMES libbinaryninjacore.so.1
                     HINTS ${BNSdk_ROOT_DIR} ENV BNSdk_ROOT
                     PATHS ${CMAKE_CURRENT_LIST_DIR}/third_party/binaryninja/binaryninja-api
                     PATH_SUFFIXES BNSdk
                     DOC "Location of the binaryninja SDK"
                     NO_DEFAULT_PATH)
set(BNSdk_INCLUDE_DIRS ${BNSdk_DIR}/binaryninja-api)

find_package_handle_standard_args(
  BNSdk FOUND_VAR BNSdk_FOUND
         REQUIRED_VARS BNSdk_DIR
                       BNSdk_INCLUDE_DIRS
         FAIL_MESSAGE "binaryninja SDK not found, try setting BNSdk_ROOT_DIR")
