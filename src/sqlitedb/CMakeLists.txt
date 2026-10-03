
oxen_add_library(sqlitedb
  database.cpp)

target_link_libraries(sqlitedb
  PUBLIC
    epee
    SQLiteCpp
    common
  PRIVATE
    sessiondep::sqlite3
    logging
    extra)
