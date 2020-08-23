add_library(miner
    miner.cpp
)

target_link_libraries(miner
    PUBLIC
      common
    PRIVATE
      Boost::program_options
      extra
)