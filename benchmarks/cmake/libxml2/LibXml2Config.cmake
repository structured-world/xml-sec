# Use the same pkg-config selection as the oracle's compile/link command.
# Ubuntu's libxml2-dev does not install a CMake package configuration.
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBXML2 REQUIRED IMPORTED_TARGET GLOBAL libxml-2.0)
if(NOT TARGET LibXml2::LibXml2)
  add_library(LibXml2::LibXml2 INTERFACE IMPORTED GLOBAL)
  set_target_properties(LibXml2::LibXml2 PROPERTIES
    INTERFACE_LINK_LIBRARIES PkgConfig::LIBXML2)
endif()
set(LibXml2_FOUND TRUE)
