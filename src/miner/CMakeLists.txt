add_library(miner
    miner.cpp
)

target_link_libraries(cryptonote_basic
    PRIVATE
    common
)