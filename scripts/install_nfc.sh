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
ACTUATUR_PATH=$(realpath $(dirname "$0")/..)
cd $ACTUATUR_PATH
mkdir -p third_party

cd third_party
if [ $? -ne 0 ]; then
    exit 1
fi
[ -d "nxp_nfc" ] && rm -r nxp_nfc
mkdir nxp_nfc
cd nxp_nfc

echo "######################"
echo "Installing build tools"
echo "######################"
sudo apt install automake autoconf libtool

echo "################"
echo "Cloning git repo"
echo "################"
git clone https://github.com/NXPNFCLinux/linux_libnfc-nci.git -b NCI2.0_PN7160

cd linux_libnfc-nci
if [ $? -ne 0 ]; then
    exit 1
fi

git apply ../../../scripts/patch_file.patch 

echo "####################"
echo "building nfc library"
echo "####################"
./bootstrap
./configure -prefix $PWD/..
make
sudo make install
