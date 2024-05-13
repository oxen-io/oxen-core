
macro(system_or_submodule BIGNAME smallname pkgconf subdir)
    option(FORCE_${BIGNAME}_SUBMODULE "force using ${smallname} submodule" OFF)
    if(NOT BUILD_STATIC_DEPS AND NOT FORCE_${BIGNAME}_SUBMODULE AND NOT FORCE_ALL_SUBMODULES)
        pkg_check_modules(${BIGNAME} ${pkgconf} IMPORTED_TARGET)
    endif()
    if(${BIGNAME}_FOUND)
        add_library(${smallname} INTERFACE)
        if(NOT TARGET PkgConfig::${BIGNAME} AND CMAKE_VERSION VERSION_LESS "3.21")
        # Work around cmake bug 22180 (PkgConfig::THING not set if no flags needed)
        else()
        target_link_libraries(${smallname} INTERFACE PkgConfig::${BIGNAME})
        endif()
        message(STATUS "Found system ${smallname} ${${BIGNAME}_VERSION}")
    else()
        message(STATUS "using ${smallname} submodule")
        add_subdirectory(${subdir} EXCLUDE_FROM_ALL)
    endif()
    if(NOT TARGET ${smallname}::${smallname})
        add_library(${smallname}::${smallname} ALIAS ${smallname})
    endif()
endmacro()