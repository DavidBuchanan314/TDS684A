# TDS684A
Notes about my TDS684A oscilloscope

@tomverbeure's TDS420A notes: (there's a lot of similarity here)

https://tomverbeure.github.io/2020/06/27/In-the-Lab-Tektronix-TDS420A.html

https://tomverbeure.github.io/2020/06/27/Tektronix-TDS420A-Remote-Control-over-GPIB.html

https://tomverbeure.github.io/2020/07/02/Extracting-the-Tektronix-TDS420A-Firmware.html

https://tomverbeure.github.io/2020/07/03/TDS420A-Serial-Debug-Console-Symbol-Table-Ghidra.html

https://tomverbeure.github.io/2020/07/11/Option-Hacking-the-Tektronix-TDS-420A.html

## Memory Map

The memory bus, from the perspective of the MC68020 CPU

(Derived from analyzing the BootRom code and inspecting the physical hardware - I don't yet have a GPIB adapter)

```
0x0000_0000 - 0x0004_0000: BootRom "160-9335-00". The ROM itself is 256KiB but only <32K is actually used. Unsure how much is physically mapped.
0x0020_0000 - 0x0024_0000: SRAM - M5M51008AFP-10LL (100ns) x2, totaling 256KiB
0x0040_0000 - 0x????_????: NVRAM - DS1650Y-100 (512KiB), DS1486-150 (RTC + 128KiB) - unsure of their precise layout/order.
0x0060_0000 - 0x????_????: 7-segment debug display
0x0080_0000 - 0x????_????: config DIP switches
0x00a0_0000 - 0x00a0_000f: RS232 UART - MC68681
0x00c0_0000 - 0x00c0_000f: Debug UART - Supposed to be a MC68681 but there isn't one present by default!
0x0100_0000 - 0x012f_ffff: FlashRom - Am28F020 256KiB, x12 (!), totaling 3MiB
```
