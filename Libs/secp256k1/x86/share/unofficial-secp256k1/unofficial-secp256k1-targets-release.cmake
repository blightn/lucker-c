#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "unofficial::secp256k1" for configuration "Release"
set_property(TARGET unofficial::secp256k1 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(unofficial::secp256k1 PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/secp256k1.lib"
  )

list(APPEND _IMPORT_CHECK_TARGETS unofficial::secp256k1 )
list(APPEND _IMPORT_CHECK_FILES_FOR_unofficial::secp256k1 "${_IMPORT_PREFIX}/lib/secp256k1.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
