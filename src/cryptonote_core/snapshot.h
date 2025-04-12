#pragma once

#include <csignal>
#include <cstdint>

#include "common/fs.h"
#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote {

class Snapshot {
  public:
    explicit Snapshot(cryptonote::network_type nettype) : m_nettype{nettype} {}

    bool replace_databases(
            const fs::path& lmdb_dir, const fs::path& sqlite_db_path, const fs::path& ons_db_path);

  private:
    cryptonote::network_type m_nettype;

    // Helper methods for downloading and processing the snapshot
    bool download_and_verify(
            const fs::path& lmdb_dir,
            const fs::path& sqlite_db_path,
            const fs::path& ons_db_path,
            const fs::path& checksum_dir);
    bool verify_checksum(const std::string& file_path, const std::string& expected_checksum);

    // Helper struct for file downloads
    struct FileDownload {
        std::string name;
        std::string url;
        fs::path destination;
    };

    std::vector<FileDownload> prepare_downloads(
            const std::string& base_url,
            const fs::path& lmdb_dir,
            const fs::path& sqlite_db_path,
            const fs::path& ons_db_path,
            const fs::path& checksum_dir);
    bool download_file(const FileDownload& file);
    bool download_all_files(const std::vector<FileDownload>& downloads);
    std::unordered_map<std::string, std::string> parse_checksums(const fs::path& checksum_path);
    bool verify_all_checksums(
            const std::vector<FileDownload>& downloads, const fs::path& checksum_dir);
};

}  // namespace cryptonote
