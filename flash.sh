#!/bin/sh

esptool.py write_flash 0x0 app.out-0x00000.bin
esptool.py write_flash 0x40000 app.out-0x40000.bin
