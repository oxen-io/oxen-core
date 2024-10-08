# This hack exists to make FindCURL in cpr work properly when doing a static deps build.
set(CURL_FOUND TRUE CACHE BOOL "" FORCE)
set(CURL_VERSION_STRING "${CURL_VERSION}" CACHE STRING "" FORCE)
