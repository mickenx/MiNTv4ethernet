# MiNTv4ethernet

This is a FreeMiNT ethernet driver for Vampire v4 Standalone fpga computer. 
If you want to build it , use the dummy target in MiNTnet and change SRCFILES 
to include the two files.

But if you just want to try it , put the binary in your mint folder. c:\mint\$version\ .
You will also need a inet4 module. If you have a dhcp server on your network, just run 
dhclient en0. I am doing it at boot time.

Hapyy networking!
