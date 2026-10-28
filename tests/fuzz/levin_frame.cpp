#include <iostream>

#include "common/file.h"
#include "fuzzer.h"
#include "p2p/levin/frame.h"

class LevinFrameFuzzer : public Fuzzer {
  public:
    int init() override { return 0; }
    int run(const std::string& filename) override;
};

int LevinFrameFuzzer::run(const std::string& filename) {
    std::string s;
    if (!tools::slurp_file(filename, s)) {
        std::cout << "Error: failed to load file " << filename << std::endl;
        return 1;
    }
    // Fed in uneven pieces, sized by the data itself, so that the input also decides where the
    // parser's reads end.
    nodetool::levin::frame_parser parser{1'000'000};
    std::string_view data{s};
    try {
        while (!data.empty()) {
            size_t n = std::min<size_t>(data.size(), 1 + static_cast<unsigned char>(data[0]));
            parser.feed({reinterpret_cast<const unsigned char*>(data.data()), n});
            data.remove_prefix(n);
        }
    } catch (const nodetool::levin::parse_error& e) {
        std::cerr << "Invalid levin stream: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

int main(int argc, const char** argv) {
    LevinFrameFuzzer fuzzer;
    return run_fuzzer(argc, argv, fuzzer);
}
