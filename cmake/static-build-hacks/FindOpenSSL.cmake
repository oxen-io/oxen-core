# This hack exists to make FindOpenSSL in cpr work properly when doing a static deps build.
set(OPENSSL_FOUND TRUE CACHE BOOL "" FORCE)
