# TDS684A
Notes about my TDS684A oscilloscope

@tomverbeure's TDS420A notes: (there's a lot of similarity here)

https://tomverbeure.github.io/2020/06/27/In-the-Lab-Tektronix-TDS420A.html

https://tomverbeure.github.io/2020/06/27/Tektronix-TDS420A-Remote-Control-over-GPIB.html

https://tomverbeure.github.io/2020/07/02/Extracting-the-Tektronix-TDS420A-Firmware.html

https://tomverbeure.github.io/2020/07/03/TDS420A-Serial-Debug-Console-Symbol-Table-Ghidra.html

https://tomverbeure.github.io/2020/07/11/Option-Hacking-the-Tektronix-TDS-420A.html

See also:

https://github.com/iliasam/tektronix_experiments

## Memory Map

The memory bus, from the perspective of the MC68020 CPU

(Derived from analyzing the BootRom code and inspecting the physical hardware - I don't yet have a GPIB adapter)

```
0x0000_0000 - 0x0004_0000: BootRom "160-9335-00". The ROM itself is 256KiB but only <32K is actually used. Unsure how much is physically mapped.
0x0020_0000 - 0x0024_0000: SRAM - M5M51008AFP-10LL (100ns) x2, totaling 256KiB
0x0040_0000 - 0x????_????: ???
0x0060_0000 - 0x????_????: 7-segment debug display
0x0080_0000 - 0x????_????: config DIP switches
0x00a0_0000 - 0x00a0_000f: RS232 UART - MC68681 (there's another one somewhere, for debug)
0x00c0_0000 - 0x00c?_????: GPIB
0x0100_0000 - 0x012f_ffff: FlashRom - Am28F020 256KiB (90ns), x12 (!), totaling 3MiB
0x0400_0000 - 0x????_????: NVRAM - DS1486-150 (RTC + 128KiB), DS1650Y-100 (512KiB) - the RTC one comes first, not 100% sure where the other one is (maybe right after? would be weird not to be aligned though).
0x0700_0000 - 0x07ff_ffff: ???? _readAddr reads from this, wrapped in calls to _busRequest/_busRelease - maybe D1 bus?
0x075e_d000 - 0x????_????: TLC34075 video chip
0x0800_0000 - 0x????_????: Maybe video related - framebuffer?
0x0a00_0000 - 0x????_????: main DRAM - unsure of capacity
```
