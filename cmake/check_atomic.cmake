
function(check_working_cxx_atomics64 varname)
  set(OLD_CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS})
  set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -std=c++11")
  check_cxx_source_compiles("
#include <atomic>
#include <cstdint>
std::atomic<uint64_t> x (0);
int main() {
  uint64_t i = x.load(std::memory_order_relaxed);
  return 0;
}
" ${varname})
  set(CMAKE_REQUIRED_FLAGS ${OLD_CMAKE_REQUIRED_FLAGS})
endfunction()

function(link_libatomic)
  check_working_cxx_atomics64(HAVE_CXX_ATOMICS64_WITHOUT_LIB)

  if(HAVE_CXX_ATOMICS64_WITHOUT_LIB)
    message(STATUS "Have working 64bit atomics")
    return()
  endif()

  check_library_exists(atomic __atomic_load_8 "" HAVE_CXX_LIBATOMICS64)
  if (HAVE_CXX_LIBATOMICS64)
    message(STATUS "Have 64bit atomics via library")
    list(APPEND CMAKE_REQUIRED_LIBRARIES "atomic")
    check_working_cxx_atomics64(HAVE_CXX_ATOMICS64_WITH_LIB)
    if (HAVE_CXX_ATOMICS64_WITH_LIB)
      message(STATUS "Can link with libatomic")
      link_libraries(atomic)
      return()
    endif()
  endif()

  message(FATAL_ERROR "Host compiler must support 64-bit std::atomic!")
endfunction()

