find_path(BINARYNINJA_DIR NAMES libbinaryninjacore.so.1
                     HINTS ${BINARYNINJA_ROOT_DIR} ENV BINARYNINJA_ROOT
                     PATH_SUFFIXES BNSdk
                     DOC "Location of BinaryNinja"
                     NO_DEFAULT_PATH)
#set(BNSdk_INCLUDE_DIRS ${BN_DIR}/binaryninja-api)

find_package_handle_standard_args(
  BINARYNINJA FOUND_VAR BINARYNINJA_FOUND
         REQUIRED_VARS BINARYNINJA_DIR
#                       BN_INCLUDE_DIRS
         FAIL_MESSAGE "BinaryNinja not found, try setting BINARYNINJA_ROOT_DIR")
