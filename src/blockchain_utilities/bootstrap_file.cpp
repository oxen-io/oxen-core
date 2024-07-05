// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "bootstrap_file.h"

#include <fmt/std.h>

#include "common/exception.h"
#include "bootstrap_serialization.h"
#include "serialization/binary_utils.h"  // dump_binary(), parse_binary()

using namespace cryptonote;
using namespace blockchain_utils;

namespace {
// This number was picked by taking the leading 4 bytes from this output:
// echo Oxen bootstrap file | sha1sum
const uint32_t blockchain_raw_magic = 0x28721586;
const uint32_t header_size = 1024;

std::string refresh_string = "\r                                    \r";
auto logcat = log::Cat("bcutil");
}  // namespace

bool BootstrapFile::open_writer(const fs::path& file_path) {
    const auto dir_path = file_path.parent_path();
    if (!dir_path.empty()) {
        if (fs::exists(dir_path)) {
            if (!fs::is_directory(dir_path)) {
                log::error(logcat, "export directory path is a file: {}", dir_path);
                return false;
            }
        } else {
            if (!fs::create_directory(dir_path)) {
                log::error(logcat, "Failed to create directory {}", dir_path);
                return false;
            }
        }
    }

    m_raw_data_file = new std::ofstream();

    bool do_initialize_file = false;
    uint64_t num_blocks = 0;

    if (!fs::exists(file_path)) {
        log::debug(logcat, "creating file");
        do_initialize_file = true;
        num_blocks = 0;
    } else {
        num_blocks = count_blocks(file_path.string());
        log::debug(
                logcat,
                "appending to existing file with height: {}  total blocks: {}",
                num_blocks - 1,
                num_blocks);
    }
    m_height = num_blocks;

    if (do_initialize_file)
        m_raw_data_file->open(
                file_path.string(), std::ios_base::binary | std::ios_base::out | std::ios::trunc);
    else
        m_raw_data_file->open(
                file_path.string(),
                std::ios_base::binary | std::ios_base::out | std::ios::app | std::ios::ate);

    if (m_raw_data_file->fail())
        return false;

    m_output_stream =
            new boost::iostreams::stream<boost::iostreams::back_insert_device<buffer_type>>(
                    m_buffer);
    if (m_output_stream == nullptr)
        return false;

    if (do_initialize_file)
        initialize_file();

    return true;
}

bool BootstrapFile::initialize_file() {
    const uint32_t file_magic = blockchain_raw_magic;

    std::string blob;
    try {
        blob = serialization::dump_binary(file_magic);
    } catch (const std::exception& e) {
        throw oxen::traced<std::runtime_error>("Error in serialization of file magic: "s + e.what());
    }
    *m_raw_data_file << blob;

    bootstrap::file_info bfi;
    bfi.major_version = 0;
    bfi.minor_version = 1;
    bfi.header_size = header_size;

    bootstrap::blocks_info bbi;
    bbi.block_first = 0;
    bbi.block_last = 0;
    bbi.block_last_pos = 0;

    buffer_type buffer2;
    boost::iostreams::stream<boost::iostreams::back_insert_device<buffer_type>>
            output_stream_header(buffer2);

    uint32_t bd_size = 0;

    std::string bd = t_serializable_object_to_blob(bfi);
    log::debug(logcat, "bootstrap::file_info size: {}", bd.size());
    bd_size = bd.size();

    try {
        blob = serialization::dump_binary(bd_size);
    } catch (const std::exception& e) {
        throw oxen::traced<std::runtime_error>(
                "Error in serialization of bootstrap::file_info size: "s + e.what());
    }
    output_stream_header << blob;
    output_stream_header << bd;

    bd = t_serializable_object_to_blob(bbi);
    log::debug(logcat, "bootstrap::blocks_info size: {}", bd.size());
    bd_size = bd.size();

    try {
        blob = serialization::dump_binary(bd_size);
    } catch (const std::exception& e) {
        throw oxen::traced<std::runtime_error>(
                "Error in serialization of bootstrap::blocks_info size: "s + e.what());
    }
    output_stream_header << blob;
    output_stream_header << bd;

    output_stream_header.flush();
    output_stream_header << std::string(
            header_size - buffer2.size(), 0);  // fill in rest with null bytes
    output_stream_header.flush();
    std::copy(buffer2.begin(), buffer2.end(), std::ostreambuf_iterator<char>(*m_raw_data_file));

    return true;
}

void BootstrapFile::flush_chunk() {
    m_output_stream->flush();

    uint32_t chunk_size = m_buffer.size();
    // log::trace(logcat, "chunk_size {}", chunk_size);
    if (chunk_size > BUFFER_SIZE) {
        log::warning(logcat, "WARNING: chunk_size {} > BUFFER_SIZE {}", chunk_size, BUFFER_SIZE);
    }

    std::string blob;
    try {
        blob = serialization::dump_binary(chunk_size);
    } catch (const std::exception& e) {
        throw oxen::traced<std::runtime_error>("Error in serialization of chunk size: "s + e.what());
    }
    *m_raw_data_file << blob;

    if (m_max_chunk < chunk_size) {
        m_max_chunk = chunk_size;
    }
    long pos_before = m_raw_data_file->tellp();
    std::copy(m_buffer.begin(), m_buffer.end(), std::ostreambuf_iterator<char>(*m_raw_data_file));
    m_raw_data_file->flush();
    long pos_after = m_raw_data_file->tellp();
    long num_chars_written = pos_after - pos_before;
    if (static_cast<unsigned long>(num_chars_written) != chunk_size) {
        log::error(
                logcat,
                "Error writing chunk:  height: {}  chunk_size: {}  num chars written: {}",
                m_cur_height,
                chunk_size,
                num_chars_written);
        throw oxen::traced<std::runtime_error>("Error writing chunk");
    }

    m_buffer.clear();
    delete m_output_stream;
    m_output_stream =
            new boost::iostreams::stream<boost::iostreams::back_insert_device<buffer_type>>(
                    m_buffer);
    log::debug(logcat, "flushed chunk:  chunk_size: {}", chunk_size);
}

void BootstrapFile::write_block(block& block) {
    bootstrap::block_package bp;
    bp.block = block;

    std::vector<transaction> txs;

    uint64_t block_height = var::get<txin_gen>(block.miner_tx.vin.front()).height;

    // now add all regular transactions
    for (const auto& tx_id : block.tx_hashes) {
        if (!tx_id) {
            throw oxen::traced<std::runtime_error>("Aborting: null txid");
        }
        transaction tx = m_blockchain_storage->get_db().get_tx(tx_id);

        txs.push_back(tx);
    }

    // these non-coinbase txs will be serialized using this structure
    bp.txs = txs;

    // These three attributes are currently necessary for a fast import that adds blocks without
    // verification.
    bool include_extra_block_data = true;
    if (include_extra_block_data) {
        size_t block_weight = m_blockchain_storage->get_db().get_block_weight(block_height);
        difficulty_type cumulative_difficulty =
                m_blockchain_storage->get_db().get_block_cumulative_difficulty(block_height);
        uint64_t coins_generated =
                m_blockchain_storage->get_db().get_block_already_generated_coins(block_height);

        bp.block_weight = block_weight;
        bp.cumulative_difficulty = cumulative_difficulty;
        bp.coins_generated = coins_generated;
    }

    std::string bd = t_serializable_object_to_blob(bp);
    m_output_stream->write((const char*)bd.data(), bd.size());
}

bool BootstrapFile::close() {
    if (m_raw_data_file->fail())
        return false;

    m_raw_data_file->flush();
    delete m_output_stream;
    delete m_raw_data_file;
    return true;
}

bool BootstrapFile::store_blockchain_raw(
        Blockchain* _blockchain_storage,
        tx_memory_pool* _tx_pool,
        fs::path& output_file,
        uint64_t requested_block_stop) {
    uint64_t num_blocks_written = 0;
    m_max_chunk = 0;
    m_blockchain_storage = _blockchain_storage;
    m_tx_pool = _tx_pool;
    uint64_t progress_interval = 100;
    log::info(logcat, "Storing blocks raw data...");
    if (!BootstrapFile::open_writer(output_file)) {
        log::error(logcat, "failed to open raw file for write");
        return false;
    }
    block b;

    // block_start, block_stop use 0-based height. m_height uses 1-based height. So to resume export
    // from last exported block, block_start doesn't need to add 1 here, as it's already at the next
    // height.
    uint64_t block_start = m_height;
    uint64_t block_stop = 0;
    log::info(
            logcat,
            "source blockchain height: {}",
            m_blockchain_storage->get_current_blockchain_height() - 1);
    if ((requested_block_stop > 0) &&
        (requested_block_stop < m_blockchain_storage->get_current_blockchain_height())) {
        log::info(logcat, "Using requested block height: {}", requested_block_stop);
        block_stop = requested_block_stop;
    } else {
        block_stop = m_blockchain_storage->get_current_blockchain_height() - 1;
        log::info(logcat, "Using block height of source blockchain: {}", block_stop);
    }
    for (m_cur_height = block_start; m_cur_height <= block_stop; ++m_cur_height) {
        // this method's height refers to 0-based height (genesis block = height 0)
        crypto::hash hash = m_blockchain_storage->get_block_id_by_height(m_cur_height);
        m_blockchain_storage->get_block_by_hash(hash, b);
        write_block(b);
        if (m_cur_height % NUM_BLOCKS_PER_CHUNK == 0) {
            flush_chunk();
            num_blocks_written += NUM_BLOCKS_PER_CHUNK;
        }
        if (m_cur_height % progress_interval == 0) {
            std::cout << refresh_string;
            std::cout << "block " << m_cur_height << "/" << block_stop << "\r" << std::flush;
        }
    }
    // NOTE: use of NUM_BLOCKS_PER_CHUNK is a placeholder in case multi-block chunks are later
    // supported.
    if (m_cur_height % NUM_BLOCKS_PER_CHUNK != 0) {
        flush_chunk();
    }
    // print message for last block, which may not have been printed yet due to progress_interval
    std::cout << refresh_string;
    std::cout << "block " << m_cur_height - 1 << "/" << block_stop << "\n";

    log::info(logcat, "Number of blocks exported: {}", num_blocks_written);
    if (num_blocks_written > 0)
        log::info(logcat, "Largest chunk: {} bytes", m_max_chunk);

    return BootstrapFile::close();
}

uint64_t BootstrapFile::seek_to_first_chunk(std::ifstream& import_file) {
    uint32_t file_magic;

    std::string str1;
    char buf1[2048];
    import_file.read(buf1, sizeof(file_magic));
    if (!import_file)
        throw oxen::traced<std::runtime_error>("Error reading expected number of bytes");
    str1.assign(buf1, sizeof(file_magic));

    try {
        serialization::parse_binary(str1, file_magic);
    } catch (const std::exception& e) {
        throw oxen::traced<std::runtime_error>("Error in deserialization of file_magic: "s + e.what());
    }

    if (file_magic != blockchain_raw_magic) {
        log::error(logcat, "bootstrap file not recognized");
        throw oxen::traced<std::runtime_error>("Aborting");
    } else
        log::info(logcat, "bootstrap file recognized");

    uint32_t buflen_file_info;

    import_file.read(buf1, sizeof(buflen_file_info));
    str1.assign(buf1, sizeof(buflen_file_info));
    if (!import_file)
        throw oxen::traced<std::runtime_error>("Error reading expected number of bytes");
    try {
        serialization::parse_binary(str1, buflen_file_info);
    } catch (const std::exception& e) {
        throw oxen::traced<std::runtime_error>("Error in deserialization of buflen_file_info: "s + e.what());
    }
    log::info(logcat, "bootstrap::file_info size: {}", buflen_file_info);

    if (buflen_file_info > sizeof(buf1))
        throw oxen::traced<std::runtime_error>("Error: bootstrap::file_info size exceeds buffer size");
    import_file.read(buf1, buflen_file_info);
    if (!import_file)
        throw oxen::traced<std::runtime_error>("Error reading expected number of bytes");
    str1.assign(buf1, buflen_file_info);
    bootstrap::file_info bfi;
    try {
        serialization::parse_binary(str1, bfi);
    } catch (const std::exception& e) {
        throw oxen::traced<std::runtime_error>("Error in deserialization of bootstrap::file_info: "s + e.what());
    }
    log::info(
            logcat,
            "bootstrap file v{}.{}",
            unsigned(bfi.major_version),
            unsigned(bfi.minor_version));
    log::info(logcat, "bootstrap magic size: {}", sizeof(file_magic));
    log::info(logcat, "bootstrap header size: {}", bfi.header_size);

    uint64_t full_header_size = sizeof(file_magic) + bfi.header_size;
    import_file.seekg(full_header_size);

    return full_header_size;
}

uint64_t BootstrapFile::count_bytes(
        std::ifstream& import_file, uint64_t blocks, uint64_t& h, bool& quit) {
    uint64_t bytes_read = 0;
    uint32_t chunk_size;
    char buf1[sizeof(chunk_size)];
    std::string str1;
    h = 0;
    while (1) {
        import_file.read(buf1, sizeof(chunk_size));
        if (!import_file) {
            std::cout << refresh_string;
            log::debug(logcat, "End of file reached");
            quit = true;
            break;
        }
        bytes_read += sizeof(chunk_size);
        str1.assign(buf1, sizeof(chunk_size));
        try {
            serialization::parse_binary(str1, chunk_size);
        } catch (const std::exception& e) {
            throw oxen::traced<std::runtime_error>("Error in deserialization of chunk_size: "s + e.what());
        }
        log::debug(logcat, "chunk_size: {}", chunk_size);

        if (chunk_size > BUFFER_SIZE) {
            std::cout << refresh_string;
            log::warning(
                    logcat,
                    "WARNING: chunk_size {} > BUFFER_SIZE {} height: {}, offset {}",
                    chunk_size,
                    BUFFER_SIZE,
                    h - 1,
                    bytes_read);
            throw oxen::traced<std::runtime_error>("Aborting: chunk size exceeds buffer size");
        }
        if (chunk_size > CHUNK_SIZE_WARNING_THRESHOLD) {
            std::cout << refresh_string;
            log::debug(
                    logcat,
                    "NOTE: chunk_size {} > {} height: {}, offset {}",
                    chunk_size,
                    CHUNK_SIZE_WARNING_THRESHOLD,
                    h - 1,
                    bytes_read);
        } else if (chunk_size <= 0) {
            std::cout << refresh_string;
            log::debug(
                    logcat,
                    "ERROR: chunk_size {} <= 0  height: {}, offset {}",
                    chunk_size,
                    h - 1,
                    bytes_read);
            throw oxen::traced<std::runtime_error>("Aborting");
        }
        // skip to next expected block size value
        import_file.seekg(chunk_size, std::ios_base::cur);
        if (!import_file) {
            std::cout << refresh_string;
            log::error(
                    logcat,
                    "ERROR: unexpected end of file: bytes read before error: {} of chunk_size {}",
                    import_file.gcount(),
                    chunk_size);
            throw oxen::traced<std::runtime_error>("Aborting");
        }
        bytes_read += chunk_size;
        h += NUM_BLOCKS_PER_CHUNK;
        if (h >= blocks)
            break;
    }
    return bytes_read;
}

uint64_t BootstrapFile::count_blocks(const fs::path& import_file_path) {
    std::streampos dummy_pos;
    uint64_t dummy_height = 0;
    return count_blocks(import_file_path, dummy_pos, dummy_height);
}

// If seek_height is non-zero on entry, return a stream position <= this height when finished.
// And return the actual height corresponding to this position. Allows the caller to locate its
// starting position without having to reread the entire file again.
uint64_t BootstrapFile::count_blocks(
        const fs::path& import_file_path, std::streampos& start_pos, uint64_t& seek_height) {
    if (std::error_code ec; !fs::exists(import_file_path, ec)) {
        log::error(logcat, "bootstrap file not found: {}", import_file_path);
        throw oxen::traced<std::runtime_error>("Aborting");
    }
    std::ifstream import_file{import_file_path, std::ios::binary};

    uint64_t start_height = seek_height;
    uint64_t h = 0;
    if (import_file.fail()) {
        log::error(logcat, "import_file.open() fail");
        throw oxen::traced<std::runtime_error>("Aborting");
    }

    uint64_t full_header_size;  // 4 byte magic + length of header structures
    full_header_size = seek_to_first_chunk(import_file);

    log::info(logcat, "Scanning blockchain from bootstrap file...");
    bool quit = false;
    uint64_t bytes_read = 0, blocks;
    int progress_interval = 10;

    while (!quit) {
        if (start_height && h + progress_interval >= start_height - 1) {
            start_height = 0;
            start_pos = import_file.tellg();
            seek_height = h;
        }
        bytes_read += count_bytes(import_file, progress_interval, blocks, quit);
        h += blocks;
        std::cout << "\r"
                  << "block height: " << h - 1 << "    \r" << std::flush;

        // std::cout << refresh_string;
        log::debug(logcat, "Number bytes scanned: {}", bytes_read);
    }

    import_file.close();

    std::cout << "\nDone scanning bootstrap file";
    std::cout << "\nFull header length: " << full_header_size << " bytes";
    std::cout << "\nScanned for blocks: " << bytes_read << " bytes";
    std::cout << "\nTotal:              " << full_header_size + bytes_read << " bytes";
    std::cout << "\nNumber of blocks: " << h;
    std::cout << std::endl;

    // NOTE: h is the number of blocks.
    // Note that a block's stored height is zero-based, but parts of the code use
    // one-based height.
    return h;
}
