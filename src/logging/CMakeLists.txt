
oxen_add_library(logging
    oxen_logger.cpp
)
target_link_libraries(logging PUBLIC oxen::logging oxenmq::oxenmq oxenc::oxenc)
