# TDS684A
Notes about my TDS684A oscilloscope


## Memory Map

```
0x0000_0000 - 0x0004_0000: BootRom "160-9335-00". The ROM itself is 256KiB but only <32K is actually used. Unsure how much is physically mapped.
0x0020_0000 - 0x0024_0000: SRAM (M5M51008AFP-10LL (100ns) x2, totaling 256KiB)
0x0040_0000 - 0x????_????: NVRAM (DS1650Y-100 (512KiB), DS1486-150 (RTC + 128KiB) - unsure of their precise layout/order.
0x0060_0000 - 0x????_????: ?????
0x0080_0000 - 0x????_????: ?????
0x0100_0000 - 0x????_????: FlashRom
```
