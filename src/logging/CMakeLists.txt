
add_library(logging STATIC
    oxen_logger.cpp
)
target_link_libraries(logging PUBLIC oxen::logging oxenmq::oxenmq oxenc::oxenc)
