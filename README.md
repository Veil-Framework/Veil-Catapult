#Veil-Catapult

Veil-Catapult is a payload delivery tool and a part of the [Veil framework](https://www.veil-framework.com/).

It utilizes Veil-Evasion to generate AV-evading binaries, Impacket to upload/host the binaries, and the passing-the-hash toolkit to trigger execution.

Veil-Catapult is currently under active support by @harmj0y with help from the @VeilFramework team.

##Software Requirements:

###Kali

Currently, only Kali linux x86 is officially supported. 

[Veil-Evasion](https://github.com/Veil-Framework/Veil-Evasion/) is required for payload generation.

[Impacket](https://code.google.com/p/impacket/) and the [passing-the-hash toolkit](http://passing-the-hash.blogspot.com/) are required for payload delivery and triggering.

##Setup (tldr;)

Install [Veil-Evasion from github](https://github.com/veil-framework/Veil-Evasion) if you didn't install the [Veil metaproject](https://github.com/veil-framework/Veil). Run the Veil-Evasion/setup/setup.sh script or do an initial Veil-Evasion run.

Run the setup.sh script to install the passing-the-hash toolkit and Impacket.

