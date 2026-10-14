FROM ubuntu:24.04

RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y curl && \
    curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg && \
    echo "deb https://deb.oxen.io noble main" >/etc/apt/sources.list.d/oxen.list && \
    apt-get update && \
    apt-get install -y oxen-wallet-rpc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

EXPOSE 18082

CMD ["oxen-wallet-rpc", "--rpc-bind-ip", "0.0.0.0", "--rpc-bind-port", "18082", "--confirm-external-bind", "--daemon-address", "public-eu.optf.ngo:22023", "--wallet-file", "/oxen/hotwallet", "--password-file", "/oxen/password", "--disable-rpc-login", "--log-level", "1"]

