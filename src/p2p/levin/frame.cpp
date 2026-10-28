#include "frame.h"

#include <oxenc/endian.h>

#include <cstring>

namespace nodetool::levin {

std::array<unsigned char, header::SIZE> header::encode() const {
    std::array<unsigned char, SIZE> out;
    auto* p = out.data();
    oxenc::write_host_as_little(SIGNATURE, static_cast<void*>(p));
    oxenc::write_host_as_little(body_size, static_cast<void*>(p + 8));
    p[16] = expect_response ? 1 : 0;
    oxenc::write_host_as_little(command, static_cast<void*>(p + 17));
    oxenc::write_host_as_little(return_code, static_cast<void*>(p + 21));
    oxenc::write_host_as_little(flags, static_cast<void*>(p + 25));
    oxenc::write_host_as_little(protocol_version, static_cast<void*>(p + 29));
    return out;
}

std::optional<header> header::decode(std::span<const unsigned char, SIZE> data) {
    const auto* p = data.data();
    if (oxenc::load_little_to_host<uint64_t>(p) != SIGNATURE)
        return std::nullopt;
    header h;
    h.body_size = oxenc::load_little_to_host<uint64_t>(p + 8);
    h.expect_response = p[16] != 0;
    h.command = oxenc::load_little_to_host<uint32_t>(p + 17);
    h.return_code = oxenc::load_little_to_host<int32_t>(p + 21);
    h.flags = oxenc::load_little_to_host<uint32_t>(p + 25);
    h.protocol_version = oxenc::load_little_to_host<uint32_t>(p + 29);
    return h;
}

static std::string make_frame(const header& h, std::span<const unsigned char> body) {
    const auto head = h.encode();
    std::string frame;
    frame.reserve(head.size() + body.size());
    frame.append(reinterpret_cast<const char*>(head.data()), head.size());
    frame.append(reinterpret_cast<const char*>(body.data()), body.size());
    return frame;
}

std::string make_request(
        uint32_t command, std::span<const unsigned char> body, bool expect_response) {
    header h;
    h.body_size = body.size();
    h.expect_response = expect_response;
    h.command = command;
    h.flags = FLAG_REQUEST;
    return make_frame(h, body);
}

std::string make_response(
        uint32_t command, int32_t return_code, std::span<const unsigned char> body) {
    header h;
    h.body_size = body.size();
    h.command = command;
    h.return_code = return_code;
    h.flags = FLAG_RESPONSE;
    return make_frame(h, body);
}

std::vector<frame> frame_parser::feed(std::span<const unsigned char> data) {
    buf_.append(reinterpret_cast<const char*>(data.data()), data.size());
    const auto* bytes = reinterpret_cast<const unsigned char*>(buf_.data());

    std::vector<frame> frames;
    size_t pos = 0;
    while (true) {
        const size_t avail = buf_.size() - pos;
        if (!head_) {
            if (avail >= sizeof(SIGNATURE) &&
                oxenc::load_little_to_host<uint64_t>(bytes + pos) != SIGNATURE)
                throw parse_error{"levin frame has a bad signature"};
            if (avail < header::SIZE)
                break;
            head_ = header::decode(
                    std::span<const unsigned char, header::SIZE>{bytes + pos, header::SIZE});
            if (head_->body_size > max_body_size_)
                throw parse_error{"levin frame body too large"};
            pos += header::SIZE;
        } else {
            if (avail < head_->body_size)
                break;
            frames.push_back({*head_, buf_.substr(pos, head_->body_size)});
            pos += head_->body_size;
            head_.reset();
        }
    }
    buf_.erase(0, pos);
    return frames;
}

}  // namespace nodetool::levin
