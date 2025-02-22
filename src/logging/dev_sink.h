#pragma once

#include <spdlog/sinks/base_sink.h>

#include <iostream>
#include <mutex>
#include <vector>
// A sink used to store most important logs for developers

namespace oxen::logging {
template <typename Mutex>
class dev_sink : public spdlog::sinks::base_sink<Mutex> {
    using Base = spdlog::sinks::base_sink<Mutex>;

    // Potentially all entries will be returned in a
    // single message, so we should keep the limit
    // relatively small
    static constexpr size_t BUFFER_SIZE = 100;
    static constexpr size_t MAX_ENTRIES = 2 * BUFFER_SIZE;

    std::vector<std::string> primary_buffer_;
    std::vector<std::string> secondary_buffer_;
    // size_t log_entires

  protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        spdlog::memory_buf_t formatted;
        Base::formatter_->format(msg, formatted);

        if (primary_buffer_.size() >= BUFFER_SIZE) {
            secondary_buffer_ = std::move(primary_buffer_);
            primary_buffer_.clear();
        }

        primary_buffer_.push_back(fmt::to_string(formatted));
    }

    void flush_() override {
        // no op
    }

  public:
    dev_sink() : spdlog::sinks::base_sink<Mutex>() {
        primary_buffer_.reserve(BUFFER_SIZE);
        secondary_buffer_.reserve(BUFFER_SIZE);
    }

    std::vector<std::string> peek() {
        std::lock_guard<Mutex> lock{this->mutex_};

        std::vector<std::string> result;
        result.reserve(MAX_ENTRIES);

        for (auto it = primary_buffer_.end() - 1;
             it >= primary_buffer_.begin() && result.size() < MAX_ENTRIES;
             --it) {
            result.push_back(*it);
        }

        for (auto it = secondary_buffer_.end() - 1;
             it >= secondary_buffer_.begin() && result.size() < MAX_ENTRIES;
             --it) {
            result.push_back(*it);
        }

        return result;
    }
};

#include <mutex>
using dev_sink_mt = dev_sink<std::mutex>;

}  // namespace oxen::logging
