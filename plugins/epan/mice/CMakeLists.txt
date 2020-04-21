cmake_minimum_required( VERSION 3.10 )

include( WiresharkPlugin )

set( DISSECTOR_NAME mice )

# Plugin name and version info (major minor micro extra)
set_module_info( ${DISSECTOR_NAME} 0 0 1 0 )

set( DISSECTOR_SRC packet-${DISSECTOR_NAME}.c )

set( PLUGIN_FILES plugin.c ${DISSECTOR_SRC} )

set( CLEAN_FILES ${PLUGIN_FILES} )

include_directories( ${CMAKE_CURRENT_SOURCE_DIR} )

register_plugin_files( plugin.c
  plugin
  ${DISSECTOR_SRC}
)

add_plugin_library( ${DISSECTOR_NAME} epan )

target_link_libraries( ${DISSECTOR_NAME} epan )

install_plugin( ${DISSECTOR_NAME} epan )

file( GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h" )
CHECKAPI(
  NAME
    ${DISSECTOR_NAME}
  SWITCHES
    -g abort -g termoutput -build
  SOURCES
    ${DISSECTOR_SRC}
    ${DISSECTOR_HEADERS}
)
