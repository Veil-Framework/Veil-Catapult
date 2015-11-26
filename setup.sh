#!/bin/bash

# Clear (For Prettyness)
clear

# Echo Title
echo '========================================================================='
echo ' Veil-Catapult Setup Script | [Updated]: 01.30.2014'
echo '========================================================================='
echo ' [Web]: https://www.veil-framework.com | [Twitter]: @veilframework'
echo '========================================================================='
echo ""


echo -e " [*] Installing the passing-the-hash toolkit\n"
# install the passing-the-hash toolkit
apt-get install passing-the-hash

# if impacket isn't installed, install it
if [ -f /usr/share/pyshared/impacket/smbserver.py ]
then
    echo
    echo " [*] Impacket Already Installed... Skipping."
    echo
else
    echo -e " [*] Installing impacket\n"
    # install Impacket moved to github https://github.com/coresecurity/impacket
    git checkout https://github.com/CoreSecurity/impacket.git /tmp/impacket/
    cd /tmp/impacket/
    python setup.py install
    cd -
fi


echo ' [*] Updating Veil-Framework Configuration'
cd ./config/
python update.py

