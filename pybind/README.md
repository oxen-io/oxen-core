# PyWallet3

Python interface to oxen wallet3

## building
First build the static oxen core
```
mkdir build
cd build
cmake -DBUILD_STATIC_DEPS=ON ..
make wallet3_merged -j16
```
Then, still in the build directory, install via pip using:
```
pip3 install ./pybind
```
