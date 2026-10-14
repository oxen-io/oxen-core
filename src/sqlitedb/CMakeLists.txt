add_library(sqlitedb INTERFACE)

target_link_libraries(sqlitedb INTERFACE session::SQLite)
