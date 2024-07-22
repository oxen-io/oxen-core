
execute_process(COMMAND ${Python_EXECUTABLE} "-c" "import requests, pytest" OUTPUT_QUIET ERROR_QUIET RESULT_VARIABLE _python_import_result)
if(NOT _python_import_result)
    message(STATUS "Ledger wallet tests enabled")
    get_target_property(_bin_dir daemon RUNTIME_OUTPUT_DIRECTORY)
    add_test(NAME ledger_tests 
        COMMAND ${Python_EXECUTABLE} -m pytest "${CMAKE_CURRENT_SOURCE_DIR}/" "--binary-dir=${_bin_dir}")
else()
    message(WARNING "Ledger tests not enabled: Python 3 with requests & pytest required")
endif()

