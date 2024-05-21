
add_library(sqlitedb
  database.cpp)

target_link_libraries(sqlitedb
  PUBLIC
    epee
    SQLiteCpp
    common
  PRIVATE
    SQLite::SQLite3
    logging
    extra)
