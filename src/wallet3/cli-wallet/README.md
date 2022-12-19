# Oxen Wallet CLI

## Installing Dependancies
```
make system_dependencies
```

## Build using docker 
```
docker run --pull=always -v ~/oxen-core:/src --rm -it registry.oxen.rocks/lokinet-ci-debian-bullseye /bin/bash
curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
echo "deb https://deb.oxen.io $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/oxen.list
apt update
apt install gperf python3-venv python3-oxenmq
pip3 install --upgrade pip
pip3 install --upgrade build
pip3 install --upgrade setuptools
cd src/
mkdir build
cd build
cmake -DBUILD_STATIC_DEPS=ON ..
make wallet3_merged
pip3 install ./pybind/
cd ..
cd src/wallet3/cli-wallet/
python3.9 -m build
pip3 install --user --editable .
/usr/local/bin/oxen_wallet_cli
```

## Development Notes
### Click stuff
https://click.palletsprojects.com/en/8.1.x/

https://openbase.com/python/click-repl
