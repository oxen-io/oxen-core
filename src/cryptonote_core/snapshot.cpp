#include "snapshot.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include <cpr/cpr.h>
#include <sodium/crypto_hash_sha256.h>

#include "blockchain_db/blockchain_db.h"
#include "blocks/blocks.h"
#include "common/exception.h"
#include "common/signal_handler.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "logging/oxen_logger.h"
#include "networks.h"
#include "serialization/binary_utils.h"

namespace cryptonote {

constexpr std::string_view snapshot_checksum_dir{"tmp_snapshot_checksum"};

namespace fs = std::filesystem;

static auto logcat = log::Cat("snapshot");

static std::atomic<bool> interrupted{false};

static void handle_signal(int) {
    interrupted = true;
}

bool Snapshot::replace_databases(
        const fs::path& lmdb_dir, const fs::path& sqlite_db_path, const fs::path& ons_db_path) {
    try {
        if (fs::exists(ons_db_path))
            fs::remove(ons_db_path);
        if (fs::exists(sqlite_db_path))
            fs::remove(sqlite_db_path);
        if (fs::exists(lmdb_dir))
            fs::remove_all(lmdb_dir);

        if (!fs::exists(lmdb_dir)) {
            fs::create_directories(lmdb_dir);
        }
    } catch (const std::exception& e) {
        log::error(logcat, "Failed removing old DB files: {}", e.what());
        return false;
    }

    fs::path tmp_dir = fs::temp_directory_path();
    fs::path checksum_dir = tmp_dir / snapshot_checksum_dir;
    if (!fs::exists(checksum_dir)) {
        fs::create_directories(checksum_dir);
    }

    if (!download_and_verify(lmdb_dir, sqlite_db_path, ons_db_path, checksum_dir))
        return false;

    log::info(logcat, "Snapshot database replacement complete");
    return true;
}

// -----------------------------------------------------
// Private helper methods
// -----------------------------------------------------
bool Snapshot::download_and_verify(
        const fs::path& lmdb_dir,
        const fs::path& sqlite_db_path,
        const fs::path& ons_db_path,
        const fs::path& checksum_dir) {
    const auto& config = get_config(m_nettype);

    if (config.SNAPSHOT_URL.empty()) {
        log::error(logcat, "No snapshot URL configured for this network");
        return false;
    }

    std::vector<FileDownload> downloads = prepare_downloads(
            std::string(config.SNAPSHOT_URL), lmdb_dir, sqlite_db_path, ons_db_path, checksum_dir);

    interrupted = false;
    bool handler_installed = tools::signal_handler::install(handle_signal);
    if (!handler_installed) {
        log::error(logcat, "Failed to set up interrupt handler");
    }

    bool success = download_all_files(downloads);

    if (success) {
        success = verify_all_checksums(downloads, checksum_dir);
    }

    return success;
}

std::vector<Snapshot::FileDownload> Snapshot::prepare_downloads(
        const std::string& base_url,
        const fs::path& lmdb_dir,
        const fs::path& sqlite_db_path,
        const fs::path& ons_db_path,
        const fs::path& checksum_dir) {

    fs::path lmdb_file = lmdb_dir / "data.mdb";

    return {{"data.mdb", base_url + "/data.mdb", lmdb_file},
            {"ons.db", base_url + "/ons.db", ons_db_path},
            {"sqlite.db", base_url + "/sqlite.db", sqlite_db_path},
            {"sha256sum.txt", base_url + "/sha256sum.txt", checksum_dir / "sha256sum.txt"}};
}

// Downloads a single file with progress updates
bool Snapshot::download_file(const FileDownload& file) {
    log::info(
            logcat, "Downloading {} from {} to {}", file.name, file.url, file.destination.string());

#ifdef ENABLE_SYSTEMD
    // Notify systemd we're starting a large download and need more time
    sd_notify(
            0,
            "EXTEND_TIMEOUT_USEC=600000000\nSTATUS=Downloading snapshot file: {}"_format(file.name)
                    .c_str());
#endif

    std::ofstream ofs(file.destination, std::ios::binary);
    if (!ofs) {
        log::error(logcat, "Failed to open output file: {}", file.destination.string());
        return false;
    }

    auto last_log_time = std::chrono::steady_clock::now();
    auto last_notify_time = last_log_time;
    std::chrono::seconds log_interval(15);
    std::chrono::seconds notify_interval(30);

    auto response = cpr::Get(
            cpr::Url{file.url},
            cpr::WriteCallback([&](const std::string_view& data, intptr_t /*userdata*/) -> bool {
                if (interrupted) {
                    log::warning(logcat, "Download interrupted by user");
                    return false;
                }
                ofs.write(data.data(), data.size());
                return ofs.good();
            }),
            cpr::ProgressCallback(
                    [&](cpr::cpr_off_t downloadTotal,
                        cpr::cpr_off_t downloadNow,
                        cpr::cpr_off_t /*uploadTotal*/,
                        cpr::cpr_off_t /*uploadNow*/,
                        intptr_t /*userdata*/) -> bool {
                        if (interrupted) {
                            log::warning(logcat, "Download interrupted by user");
                            return false;
                        }
                        if (downloadNow == 0)
                            return true;

                        auto now = std::chrono::steady_clock::now();

                        if (now - last_log_time >= log_interval || downloadNow == downloadTotal) {
                            last_log_time = now;
                            double downloadedGB =
                                    static_cast<double>(downloadNow) / (1024.0 * 1024.0 * 1024.0);
                            double totalGB =
                                    static_cast<double>(downloadTotal) / (1024.0 * 1024.0 * 1024.0);
                            log::info(
                                    logcat,
                                    "Downloading {}: {:.2f} / {:.2f} GB",
                                    file.name,
                                    downloadedGB,
                                    totalGB);
                        }

#ifdef ENABLE_SYSTEMD
                        if (now - last_notify_time >= notify_interval) {
                            last_notify_time = now;
                            double progress =
                                    downloadTotal ? (100.0 * downloadNow / downloadTotal) : 0.0;
                            sd_notify(
                                    0,
                                    "EXTEND_TIMEOUT_USEC=600000000\n"
                                    "STATUS=Downloading snapshot file: {} ({:.1f}%)"_format(
                                            file.name, progress)
                                            .c_str());
                        }
#endif
                        return true;
                    }));
    ofs.close();

    if (interrupted) {
        log::warning(logcat, "Download of {} cancelled, cleaning up partial file", file.name);
        fs::remove(file.destination);
        return false;
    }
    if (response.status_code == 0) {
        log::error(logcat, "Download error for {}: {}", file.name, response.error.message);
        return false;
    }
    if (response.status_code != 200) {
        log::error(logcat, "Bad status code {} for {}", response.status_code, file.name);
        return false;
    }

    return true;
}

bool Snapshot::download_all_files(const std::vector<FileDownload>& downloads) {
    for (const auto& file : downloads) {
        if (!download_file(file))
            return false;
    }
    return true;
}

// Parse the checksum file and return a map of filename->expected checksum
std::unordered_map<std::string, std::string> Snapshot::parse_checksums(
        const fs::path& checksum_path) {
    std::unordered_map<std::string, std::string> expected_checksums;

    if (!fs::exists(checksum_path)) {
        log::error(logcat, "Checksum file was not downloaded");
        return expected_checksums;
    }

    std::ifstream ifs(checksum_path);
    if (!ifs) {
        log::error(logcat, "Failed to open checksum file: {}", checksum_path.string());
        return expected_checksums;
    }

    std::string line;
    while (std::getline(ifs, line)) {
        // Expected format: "<checksum>  <filename>"
        std::istringstream iss(line);
        std::string checksum, filename;
        if (!(iss >> checksum >> filename)) {
            log::warning(logcat, "Malformed line in checksum file: {}", line);
            continue;
        }
        expected_checksums[filename] = checksum;
    }

    return expected_checksums;
}

// Verify checksums for all downloaded files
bool Snapshot::verify_all_checksums(
        const std::vector<FileDownload>& downloads, const fs::path& checksum_dir) {
#ifdef ENABLE_SYSTEMD
    sd_notify(0, "EXTEND_TIMEOUT_USEC=120000000\nSTATUS=Verifying snapshot file checksums");
#endif

    fs::path checksum_path = checksum_dir / "sha256sum.txt";
    auto expected_checksums = parse_checksums(checksum_path);

    if (expected_checksums.empty()) {
        log::error(logcat, "Failed to parse checksums");
        return false;
    }

    bool success = true;
    for (const auto& file : downloads) {
        if (file.name == "sha256sum.txt")
            continue;

        auto it = expected_checksums.find(file.name);
        if (it == expected_checksums.end()) {
            log::warning(logcat, "No checksum entry for {} in checksum file", file.name);
            continue;
        }

        log::info(logcat, "Verifying {} with expected checksum {}", file.name, it->second);
        if (!verify_checksum(file.destination.string(), it->second)) {
            log::error(logcat, "{} failed checksum verification!", file.name);
            fs::remove(file.destination);
            success = false;
            break;
        } else {
            log::info(logcat, "{} verified successfully", file.name);
        }
    }

    fs::remove(checksum_path);
    if (fs::exists(checksum_dir) && fs::is_empty(checksum_dir)) {
        fs::remove(checksum_dir);
    }

    return success;
}

bool Snapshot::verify_checksum(const std::string& file_path, const std::string& expected_checksum) {
    if (expected_checksum.empty()) {
        log::error(logcat, "No expected checksum provided");
        return false;
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        log::error(logcat, "Failed to open file: {}", file_path);
        return false;
    }

    std::vector<unsigned char> buffer(8192);
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);

    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytes_read = file.gcount();
        if (bytes_read > 0) {
            crypto_hash_sha256_update(&state, buffer.data(), bytes_read);
        }
    }

    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256_final(&state, hash);

    std::stringstream ss;
    for (unsigned int i = 0; i < crypto_hash_sha256_BYTES; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    std::string actual_checksum = ss.str();

    log::info(logcat, "Checking file: {}", file_path);
    log::info(logcat, "Expected checksum: {}", expected_checksum);
    log::info(logcat, "Actual checksum: {}", actual_checksum);

    return actual_checksum == expected_checksum;
}

}  // namespace cryptonote
