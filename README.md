# Python Boilerplate

## Overview

This project implements the Aliro specification. 

The code is separated into 5 parts: the 4 parts as described in the Architecture
overview of the specification (chapter 5.1) and the hardware drivers.

The documentation of the project can be found in the docs/build folder. The
documentation can be found in html and pdf formats.

Examples of how to use the actuator can be found in the examples folder.

## Installing the prerequisites

This project uses the nci library (provided by NXP) for interfacing with the pn7160 nfc 
board. There at least two versions of [PN7160 evaluation kit](https://www.nxp.com/docs/en/application-note/AN12991.pdf):
- OM27160A1EVK (embeds PN7161A1HN I2C variant )
- OM27160B1EVK (embeds PN7161B1HN SPI variant)

By default this library can be build by running the following command and it supports SPI variant:
```
./scripts/install_nfc.sh
```

In case I2C variant kit is used run the script with `NXP_TRANSPORT=I2C` variable set:
```
NXP_TRANSPORT=I2C ./scripts/install_nfc.sh
```

This actuator use poetry for dependency management. To setup the environment, run:
```
sudo apt install python3-pip
pip install poetry
PATH="$PATH:/home/<user-name>/.local/bin"
sudo -E $(which poetry) install --no-root
sudo -E $(which poetry) shell
```

If using BLE, the firmware of the murata board needs to be updated. 
For instructions, see the readme in ```third_party/murata_fw```

### (re)building the nci library
In case the install script does not work as expected, the following steps can be followed for a manual install.

Note: these instructions come from:  
https://www.nxp.com/docs/en/application-note/AN13287.pdf  
https://www.nxp.com/docs/en/application-note/AN12991.pdf  

clone the nci library
```
git clone https://github.com/NXPNFCLinux/linux_libnfc-nci.git -b NCI2.0_PN7160
```

adjust linux_libnfc-nci/conf/libnfc-nxp.conf:
```
NXP_TRANSPORT=0x03
NXP_NFC_DEV_NODE="/dev/spidev0.0"
```

apply the changes in https://github.com/NXPNFCLinux/linux_libnfc-nci/blob/NCI2.0_PN7160/64bit_patch/ROOT_src.patch.
You might need to manually apply these changes, as the patch file seems to be outdated.

Install the requirements for the build:
```
sudo apt install automake autoconf libtool
```

Run the following commands in the linux_libnfc-nci folder:
```
./bootstrap
./configure -prefix $PWD/..
make
sudo make install
```

## Flashing the firmware
[How to flash guide](third_party/readme.md)

## Examples
The examples can be found in the examples folder. 
You can run an example in the poetry shell with:
```
python3 -m examples.nfc.reader.standard
python3 -m examples.nfc.reader.fast
python3 -m examples.nfc.user_device
python3 -m examples.ble.reader.standard
python3 -m examples.ble.reader.fast
python3 -m examples.ble.user_device
```

There are some tests used for specific usecases. These fall into three categories:
- fast transaction
- mailbox
- stepup
- key slot
- certificate (load cert)
- negative tests

Specific tests:
- `reader/fast.py`
- `reader/stepup.py`
- `reader/mailbox.py`
- `reader/key_slot.py`

Certificate tests:
- `reader/certificate.py`

Negative tests:
- `reader/id_fail.py`
- `reader/key_fail.py`
- `reader/key_fail.py`

For BLE only there is an example specific for UWB test cases:
- `reader/ble_uwb.py`
- `user_device_ble_uwb.py`

There are also examples that can be used to generate a keypair or a certificate:
```
python3 -m examples.cryptography.generate_certificate
python3 -m examples.cryptography.generate_keypair
```

## Using the Actuator
This actuator supports both the reader side and the user side of the protocol. The class
that implements the reader side is the ```Reader``` class located in ```aliro_actuator.access_protocol.reader```, and the user side is implemented by the ```UserDevice``` located in ```aliro_actuator.access_protocol.user_device```.

Both ```Reader``` and ```UserDevice``` have a similar structure. 
They both have a parameter ```transport_protocol``` which indicates which transport protocol to use (NFC or BLE/UWB). After instantiating the class, the ```transaction_initiation``` method is used to set up the connection to a device. 
This method blocks until the connection is established.

The ```UserDevice``` and ```Reader``` can now be used in one of two ways: using the handle functions for an easy to use approach, or the command/response methods for more control.

### Approach 1 (handle)
This approach uses the attributes set during instantation, and the ones received from commands, to make the actuator easier to use. Start by using the ```start_new_session``` to start a session. All data received will be stored in this session. Now, use the methods that start with handle to handle the commands.

### Approach 2 (command/response)
This approach gives more control to the programmer. The methods that start with command/response require a value for every piece of data they will send. The data received will also need to be manually processed by the programmer (unlike Approach 1, there is no session to save received data). 

## Create wheels
To create wheel files, for example to install the actuator as a package in another
project, use the following command. The wheels can be found in the dist folder.

```
poetry build
```

## Local development with VSCode

### Prerequisites

1. VSCode
2. VSCode - Dev Container extension ([ms-vscode-remote.remote-containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers))
3. Docker environment

### Setup

1. Clone Repo
2. Open Repo in VSCode
3. Reopen workspace in Dev Container

    - First launch can take several minutes
    - On first launch you must "Reload Window" in VSCode to fix dependency issue between
      python extensions

All dependencies and tooling will be automatically installed.

### Run in debbugger

- Hit <kbd>F5</kbd> to start app in debug mode
- VSCode will auto launch Swagger url in Browser.
- <kbd>⌘ Command</kbd> + <kbd>⇧ Shift</kbd> + <kbd>F5</kbd> will restart
- breakpoints can be set by clicking to the left of a python line

Note: App can also be stared in debug mode via the green play button in 
Run and Debug tab in sidebar.

### Use git in VSCode

You can use git integration in VSCode, from inside Dev Container.

**Note:** if you get an error with public key denied, you need to run `ssh-add` in a
terminal on you mac. This will add you ssh key to `ssh-agent` which VSCode uses to
forward the ssh-key to the Dev Container.

## Testing

Tests are implemented with `pytest` and stored in `tests` folder in the root of the 
project.

- VSCode will automatically discover tests in the project
- Tests can be run from the Testing tab in the sidebar or individually by clicking the 
testing icon in the code view, to the left of the line number, on the line declaring the
test.

To run all tests and generate code coverage report run shell script `scripts/test.sh`.

## Linting, formatting and type checking

The project is configured to be 
- linted with `flake8`
- autoformated via `black` and `isort`, 
- type checked with `mypy`
- spell checked with `cspell`

All of these are automatically running on save-file in VSCode, and problems identified
will be shown in the PROBLEMS tab (<kbd>⌘ Command</kbd> + <kbd>⇧ Shift</kbd> + <kbd>M</kbd>).

- Linting is also available via shell script in `scripts/lint.sh`
- Autoformatting is also available via shell script in `scripts/format.sh`
