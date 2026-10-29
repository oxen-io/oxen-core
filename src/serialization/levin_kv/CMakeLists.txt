oxen_add_library(levin_kv
  reader.cpp
  writer.cpp)

target_link_libraries(levin_kv
  PUBLIC
    common
    oxenc::oxenc
  PRIVATE
    extra)
