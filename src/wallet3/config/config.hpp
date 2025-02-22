#pragma once

namespace wallet {

struct GeneralWalletConfig {
    std::string nettype = "testnet";  // What network the wallet is operating on ("mainnet" |
                                      // "testnet" | "devnet")
    std::string datadir =
            "oxen-wallet";  // Directory to store data (Database files, websocket file, logs)
    bool append_network_type_to_datadir = true;  // If you specify a datadir do you want the wallet
                                                 // to save into subdirs for testnet
    uint32_t subaddress_lookahead_major =
            50;  // The wallet will generate a number of accounts based on this figure
    uint32_t subaddress_lookahead_minor = 200;  // The wallet will generate a number of addresses
                                                // for each account based on this figure
};

struct LoggingConfig {
    std::string level = "info";
    bool save_logs_in_subdirectory = true;  // e.g ~/.oxen-wallet/testnet/logs/wallet_logs.txt vs
                                            // ~/.oxen-wallet/testnet/wallet_logs.txt
    std::string logdir = "logs";            // Directory to store log data
    std::string log_filename = "wallet_logs.txt";   // name for logs
    size_t log_file_size_limit = 1024 * 1024 * 50;  // 50MiB
    size_t extra_files = 1;
    bool rotate_on_open = true;  // wallet will create a new log file every time its opened
};

struct DaemonCommsConfig {
    std::string address;  // The remote url of the daemon.
    std::string proxy;  // Optional proxy to use for connection. E.g. socks4a://hostname:port for a
                        // SOCKS proxy.
    bool trusted;       // When true, allow the usage of commands that may compromise privacy
    std::string ssl_private_key_path;  // HTTPS client authentication: path to private key.  Must
                                       // use an address starting with https://
    std::string ssl_certificate_path;  // HTTPS client authentication: path to certificate.  Must
                                       // use an address starting with https://
    std::string ssl_ca_file;  // Path to CA bundle to use for HTTPS server certificate verification
                              // instead of system CA.  Requires an https:// address.
    bool ssl_allow_any_cert;  // Make HTTPS insecure: disable HTTPS certificate verification when
                              // using an https:// address.
};

namespace rpc {
    struct Config {
        std::string sockname = "wallet.sock";
    };
}  // namespace rpc

struct Config {
    GeneralWalletConfig general;
    LoggingConfig logging;
    DaemonCommsConfig daemon;
    wallet::rpc::Config omq_rpc;
};
}  // namespace wallet
