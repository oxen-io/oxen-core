package=sqlite3
$(package)_version=3310100
$(package)_download_path=https://www.sqlite.org/2020/
$(package)_file_name=sqlite-autoconf-$($(package)_version).tar.gz
$(package)_sha256_hash=62284efebc05a76f909c580ffa5c008a7d22a1287285d68b7825a2b6b51949ae

define $(package)_set_vars
  $(package)_cflags=-Wformat -Wformat-security -fstack-protector -fstack-protector-strong -fPIC
  $(package)_cxxflags=-std=C++11 -Wformat -Wformat-security -fstack-protector -fstack-protector-strong -fPIC
  $(package)_config_opts=--prefix=$(host_prefix) --disable-shared
  $(package)_ldflags=-pie
endef

define $(package)_config_cmds
  $($(package)_autoconf) $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
