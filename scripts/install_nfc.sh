#!/bin/sh -e

# Copyright 2023 NXP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -e

# Assign default value to NXP_TRANSPORT if it was not provided and do uppercase
: ${NXP_TRANSPORT:="SPI"}
NXP_TRANSPORT=$(echo "$NXP_TRANSPORT" | tr '[:lower:]' '[:upper:]')

ACTUATOR_PATH=$(realpath $(dirname "$0")/..)
cd $ACTUATOR_PATH

mkdir -p third_party/nxp_nfc
cd third_party/nxp_nfc


echo "######################"
echo "Installing build tools"
echo "######################"
sudo apt update
sudo apt -y install build-essential automake autoconf libtool

echo "################"
echo "Cloning git repo"
echo "################"
[ -d "linux_libnfc-nci" ] || git clone https://github.com/NXPNFCLinux/linux_libnfc-nci.git -b NCI2.0_PN7160
cd linux_libnfc-nci

git reset --hard
git checkout NCI2.0_PN7160

git apply --whitespace=fix 64bit_patch/ROOT_src.patch

echo "####################################"
echo "Fixing missing cstdint includes for GCC 13+ compatibility"
echo "####################################"
# Fix all header files that use uint8_t, uint16_t, uint32_t, uint64_t without including cstdint
find . -name "*.h" -type f -exec grep -l "uint[0-9]*_t" {} \; | while read -r file; do
    if ! grep -q "#include <cstdint>" "$file" && ! grep -q "#include <stdint.h>" "$file"; then
        echo "Patching $file"
        # Add #include <cstdint> after the first #include line found
        sed -i '0,/#include.*/{/#include.*/a\
#include <cstdint>
}' "$file"
    fi
done

if [ "$NXP_TRANSPORT" = "SPI" ]; then
    echo "Install NFC with NXP_TRANSPORT=0x03 (${NXP_TRANSPORT})"
    sed -i 's/NXP_TRANSPORT=0x00/NXP_TRANSPORT=0x03/g' conf/libnfc-nxp.conf
elif [ "$NXP_TRANSPORT" = "I2C" ]; then
    echo "Install NFC with NXP_TRANSPORT=0x02 (${NXP_TRANSPORT})"
    sed -i 's/NXP_TRANSPORT=0x00/NXP_TRANSPORT=0x02/g' conf/libnfc-nxp.conf
else
    echo "Unsupported NXP_TRANSPORT option: $NXP_TRANSPORT" >&2
    exit 1
fi


sed -i 's/NXP_NFC_DEV_NODE="\/dev\/nxpnfc"/NXP_NFC_DEV_NODE="\/dev\/spidev0.0"/g' conf/libnfc-nxp.conf

echo "####################"
echo "building nfc library"
echo "####################"
./bootstrap
./configure -prefix $PWD/..
make
sudo make install

sudo cp conf/*.conf /usr/local/etc/
