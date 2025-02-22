
set_property(GLOBAL PROPERTY oxen_executable_targets "")
function (oxen_add_executable target binary)
  add_executable("${target}" ${ARGN})
  target_link_libraries("${target}" PRIVATE extra)
  set_target_properties("${target}" PROPERTIES
    OUTPUT_NAME "${binary}${OXEN_EXECUTABLE_SUFFIX}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
  install(TARGETS "${target}" DESTINATION bin)
  get_property(exec_tgt GLOBAL PROPERTY oxen_executable_targets)
  list(APPEND exec_tgt "${target}")
  set_property(GLOBAL PROPERTY oxen_executable_targets "${exec_tgt}")
endfunction ()

function(oxen_install_library target)
  if(BUILD_SHARED_LIBS AND OXEN_VERSION_SO)
    set_target_properties("${target}" PROPERTIES
        VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}"
        SOVERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")
  endif()
  install(TARGETS "${target}"
      ARCHIVE DESTINATION lib${OXEN_INSTALL_LIBDIR_SUFFIX}
      LIBRARY DESTINATION lib${OXEN_INSTALL_LIBDIR_SUFFIX})
endfunction()

function (oxen_add_library target)
  add_library("${target}" ${ARGN})
  oxen_install_library("${target}")
endfunction()

