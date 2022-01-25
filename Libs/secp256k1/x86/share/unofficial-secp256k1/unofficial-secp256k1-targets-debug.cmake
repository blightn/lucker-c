#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "unofficial::secp256k1" for configuration "Debug"
set_property(TARGET unofficial::secp256k1 APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(unofficial::secp256k1 PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "C"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/lib/secp256k1.lib"
  )

list(APPEND _IMPORT_CHECK_TARGETS unofficial::secp256k1 )
list(APPEND _IMPORT_CHECK_FILES_FOR_unofficial::secp256k1 "${_IMPORT_PREFIX}/debug/lib/secp256k1.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
