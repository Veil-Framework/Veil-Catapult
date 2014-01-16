#!/bin/bash

# Clear (For Prettyness)
clear

# Echo Title
echo '========================================================================='
echo ' Veil-Catapult Setup Script | [Updated]: 01.15.2014'
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
    # install Impacket
    wget_output=$(wget -q -O "/tmp/impacket-0.9.10.tar.gz" "http://impacket.googlecode.com/files/impacket-0.9.10.tar.gz")
    if [ $? -ne 0 ]; then
        echo "Download of Impacket failed";
    else
        tar -C /tmp/ -zxvf /tmp/impacket-0.9.10.tar.gz
        cd /tmp/impacket-0.9.10/
        python setup.py install
        cd -
    fi
fi


echo ' [*] Updating Veil-Framework Configuration'
cd ./config/
python update.py

