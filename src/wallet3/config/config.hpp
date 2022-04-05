#pragma once

namespace wallet
{

  struct DaemonCommsConfig
  {
    std::string address;              // The remote url of the daemon.
    std::string proxy;                // Optional proxy to use for connection. E.g. socks4a://hostname:port for a SOCKS proxy.
    bool trusted;                     // When true, allow the usage of commands that may compromise privacy
    std::string ssl_private_key_path; // HTTPS client authentication: path to private key.  Must use an address starting with https://
    std::string ssl_certificate_path; // HTTPS client authentication: path to certificate.  Must use an address starting with https://
    std::string ssl_ca_file;          // Path to CA bundle to use for HTTPS server certificate verification instead of system CA.  Requires an https:// address.
    bool ssl_allow_any_cert;          // Make HTTPS insecure: disable HTTPS certificate verification when using an https:// address.
  };

  struct Config
  {
    DaemonCommsConfig daemon;
  };
}
