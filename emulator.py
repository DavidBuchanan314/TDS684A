"""
Interrupt 0x78 drives the task scheduler

"""

from unicorn import *
from unicorn.m68k_const import *
import sys
import time
import socket

M68K_CR_VBR = 0x801

symbol_lookup = {int(addr, 0):name for name, addr in map(lambda l: l.split(),open("dumps/FlashRom.symbols"))}

BOOTROM_BASE = 0x0000_0000
BOOTROM_SIZE = 0x0004_0000

SRAM_BASE = 0x0020_0000
SRAM_SIZE = 0x0004_0000

NVRAM_BASE = 0x0040_0000
NVRAM_SIZE = 0x000A_0000

FLASHROM_BASE = 0x0100_0000
FLASHROM_SIZE = 0x0030_0000

def hook_code(uc, address, size, user_data):
	print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))

def hook_block(uc: Uc, address, idk, emu: "ScopeEmu"):
	#print(hex(address))#, hex(uc.reg_read(UC_M68K_REG_A7)))#, symbol_lookup.get(address))
	#if address == 0x10027ac:
	#	print("HIT _sysClkRoutine")
	if address == 0x11ea22e:# _iosWrite
		print("_iosWrite")
		sp = uc.reg_read(UC_M68K_REG_A7)
		retaddr = int.from_bytes(uc.mem_read(sp, 4))
		fd = int.from_bytes(uc.mem_read(sp+4, 4))
		buf = int.from_bytes(uc.mem_read(sp+8, 4))
		length = int.from_bytes(uc.mem_read(sp+12, 4))
		if fd == 1: # stdout
			data = uc.mem_read(buf, length)
			emu.stdout_log.write(data)
			emu.stdout_log.flush()
			emu.stdout.write(data)
			emu.stdout.flush()
			#print(hex(retaddr), fd, hex(buf), len)
			# return
			uc.reg_write(UC_M68K_REG_D0, length)
			uc.reg_write(UC_M68K_REG_A7, sp+4) # pop
			uc.reg_write(UC_M68K_REG_PC, retaddr)
	elif address == 0x11ea17c:
		print("_iosRead")
		sp = uc.reg_read(UC_M68K_REG_A7)
		retaddr = int.from_bytes(uc.mem_read(sp, 4))
		fd = int.from_bytes(uc.mem_read(sp+4, 4))
		buf = int.from_bytes(uc.mem_read(sp+8, 4))
		length = int.from_bytes(uc.mem_read(sp+12, 4))
		if fd == 0: # stdin
			print(fd, hex(buf), length)
			recvd = emu.stdin.read(length)
			uc.mem_write(buf, recvd)
			#time.sleep(1000)
			#print(hex(retaddr), fd, hex(buf), len)
			# return
			uc.reg_write(UC_M68K_REG_D0, len(recvd))
			uc.reg_write(UC_M68K_REG_A7, sp+4) # pop
			uc.reg_write(UC_M68K_REG_PC, retaddr)

	elif address == 0x1218ee4:
		print("HIT _tickAnnounce")
	#elif address == 0x11e7608:
	#	print("HIT _hashLibInit")
	#	#time.sleep(10000)
	#elif address == 0x100815a:
	#	print("HIT _printLogo")
	#	time.sleep(10000)
	#elif address == 0x0100b59e:
	#	print("HIT FUN_0100b59e")
	#	time.sleep(10000)
	#elif address == 0x11f47f8:
	#	print("HIT _shellInit")
	#	time.sleep(10000)
	elif address == 0x1001594:
		print("HIT _scopeExec")
		#ret - stubs out diagnostics + smalltalk
		sp = uc.reg_read(UC_M68K_REG_A7)
		print("sp", hex(sp))
		retaddr = int.from_bytes(uc.mem_read(sp, 4))
		uc.reg_write(UC_M68K_REG_D0, 0) # return fake success
		uc.reg_write(UC_M68K_REG_A7, sp+4) # pop
		uc.reg_write(UC_M68K_REG_PC, retaddr)
		#time.sleep(10000)
	elif address == 0x11d3a12:
		print("HIT _main")
		time.sleep(10000)
	if 0:#(address == 0x1001dc6 and False) or address == 0x0100a508: # board ID, RAM test
		print("oops")
		sp = uc.reg_read(UC_M68K_REG_A7)
		print("sp", hex(sp))
		retaddr = int.from_bytes(uc.mem_read(sp, 4))
		uc.reg_write(UC_M68K_REG_D0, 0) # return fake success
		uc.reg_write(UC_M68K_REG_A7, sp+4) # pop
		uc.reg_write(UC_M68K_REG_PC, retaddr)
		return

def hook_intr(uc: Uc, intno: int, emu: "ScopeEmu"):
	print("INTERRUPT", intno)
	if intno == 0x100: # EXCP_RTE
		print("RTE")
		sp = uc.reg_read(UC_M68K_REG_A7)
		#print(uc.mem_read(sp-0x10, 0x20).hex())
		sr = int.from_bytes(uc.mem_read(sp, 2))
		pc = int.from_bytes(uc.mem_read(sp+2, 4))
		vector_offset = int.from_bytes(uc.mem_read(sp+6, 2))
		print("vector_offset", hex(vector_offset))
		# "vector offset" here, see MC68020 datasheet "6.4 EXCEPTION STACK FRAME FORMAT"
		#print("sp", hex(sp))
		#print("sr", hex(sr))
		print("pc", hex(pc))
		uc.reg_write(UC_M68K_REG_A7, sp+8) # pop
		uc.reg_write(UC_M68K_REG_SR, sr)
		uc.reg_write(UC_M68K_REG_PC, pc)
		return

	print("unhandled interrupt", hex(intno))
	emu.running = False
	uc.emu_stop()

def hook_unmapped(uc: Uc, user_data):
	print("UNMAPPED")
	uc.emu_stop()
	return -1

count = 0
def dbg_7seg_write(uc: Uc, offset: int, size: int, value: int, user_data) -> None:
	global count
	assert(offset == 0)
	assert(size == 1)
	print("7-seg write:", hex(value))
	count += 1
	#if count > 500:
	#	uc.emu_stop()

def dip_switch_read(uc, offset: int, size: int, user_data) -> int:
	assert(offset == 0)
	assert(size == 1)
	print("DIP switch read")
	#return 0x20 # 0x20 is "normal" config
	return 0xc0 # skip all bootrom tests, skip startup diagnostics

class MC68681:
	def __init__(self, base, emu: "ScopeEmu"):
		self.base = base
		self.emu = emu
		self.foo = 0
	
	def uc_map(self, uc: Uc):
		uc.mmio_map(self.base, 0x1000, self.reg_read, None, self.reg_write, None)
	
	def reg_read(self, uc: Uc, offset: int, size: int, user_data) -> int:
		assert(size == 1)
		#print(hex(uc.reg_read(UC_M68K_REG_PC)))
		if offset == 1:
			return 0b0000_1100
			self.foo += 1 # silly
			if self.foo & 1:
				return 0b0000_1100  # TXEMT, TXRDY
			else:
				return 0
		elif offset == 3:
			print("UART READ")
			return 0x44 # idk what's going on here exactly
		elif offset == 0xf:
			#stop-counter command
			print("#"*100 + " UART stop-counter")
			#uc.emu_stop()
			return 100
		print("MC68681 READ:", hex(offset))
		self.emu.running = False
		uc.emu_stop()
		raise Exception("TODO")
		return 0

	def reg_write(self, uc: Uc, offset: int, size: int, value: int, user_data) -> None:
		assert(size == 1)
		#print(hex(uc.reg_read(UC_M68K_REG_PC)))
		if offset == 3:
			#print("UART:", repr(chr(value)))
			sys.stderr.buffer.write(bytes([value]))
			sys.stderr.flush()
			self.emu.stdio.write(bytes([value]))
			self.emu.stdio.flush()
			return
		print("MC68681 WRITE:", hex(offset), hex(value))
		#uc.emu_stop()

class ScopeEmu():
	def __init__(self):
		self.mu = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
		self.mu.ctl_set_cpu_model(UC_CPU_M68K_M68020)

		# BootRom
		self.mu.mem_map(BOOTROM_BASE, BOOTROM_SIZE, UC_PROT_READ | UC_PROT_EXEC)
		self.mu.mem_write(BOOTROM_BASE, open("dumps/BootRom_160-9335-00.bin", "rb").read(BOOTROM_SIZE))

		# SRAM
		self.mu.mem_map(SRAM_BASE, SRAM_SIZE) # rwx

		# NVRAM
		self.mu.mem_map(NVRAM_BASE, NVRAM_SIZE) # rwx
		self.mu.mem_write(NVRAM_BASE, open("dumps/NVRAM.bin", "rb").read(NVRAM_SIZE))
		# XXX: hack?
		self.mu.mem_write(NVRAM_BASE, b"\x00")

		# FlashRom
		self.mu.mem_map(FLASHROM_BASE, FLASHROM_SIZE, UC_PROT_READ | UC_PROT_EXEC)
		self.mu.mem_write(FLASHROM_BASE, open("dumps/FlashRom.bin", "rb").read(FLASHROM_SIZE))

		# mystery device
		self.mu.mem_map(0x0260_0000, 0x10_0000)
		# mystery device
		self.mu.mem_map(0x0360_0000, 0x10_0000)
		# mystery device 4 (probably NVRAM)
		self.mu.mem_map(0x0400_0000, 0x100_0000)
		# mystery device 5 (probably DRAM)
		self.mu.mem_map(0x0500_0000, 0x100_0000)

		# set up MMIO devices
		self.mu.mmio_map(0x0060_0000, 0x1000, None, None, dbg_7seg_write, None)
		self.mu.mmio_map(0x0080_0000, 0x1000, dip_switch_read, None, None, None)

		# mystery device  - I think it's an interrupt controller
		self.mu.mem_map(0x0900_0000, 0x100_0000)

		# mystery device2
		self.mu.mem_map(0x00e0_0000, 0x10_0000)
		self.mu.mem_write(0xe00000, b"\x08\x00") # related to board ID
		# mystery device3
		self.mu.mem_map(0x0180_0000, 0x80_0000)
		#mu.mem_write(0x1fffffc, b"\xff\xff\xff\xff") # also related to board ID

		# mystery
		self.mu.mem_map(0x0a00_0000, 0x100_0000)
		# mystery device d
		self.mu.mem_map(0x0d00_0000, 0x1000)
		self.mu.mem_write(0x0d000005, b"\xff")

		uart = MC68681(0x00a0_0000, self)
		uart.uc_map(self.mu)

		# tracing all instructions
		#mu.hook_add(UC_HOOK_CODE, hook_code)
		self.mu.hook_add(UC_HOOK_BLOCK, hook_block, self)

		self.mu.hook_add(UC_HOOK_INTR, hook_intr, self)

		self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

		# Status Register - enable supervisor mode and mask interrupts
		self.mu.reg_write(UC_M68K_REG_SR, 0x2700)

		# start execution using the vector table
		self.mu.reg_write(UC_M68K_REG_A7, int.from_bytes(self.mu.mem_read(0, 4))) # SP
		self.mu.reg_write(UC_M68K_REG_PC, int.from_bytes(self.mu.mem_read(4, 4)))

		self.running = False
		self.cycles = 0

		sock = sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect(("127.0.0.1", 1234))
		self.stdin = sock.makefile("rb")
		self.stdout = sock.makefile("wb")
		self.stdout_log = open("stdout.txt", "wb")

	def deliver_interrupt(self, priority: int):
		orig_sr = self.mu.reg_read(UC_M68K_REG_SR)
		print("orig_sr", hex(orig_sr))
		int_mask = (orig_sr >> 8) & 7
		# 7 is non-maskable
		if priority != 7 and priority <= int_mask: # XXX: this isn't quite right?
			print("masked")
			return

		orig_pc = self.mu.reg_read(UC_M68K_REG_PC)
		orig_sp = self.mu.reg_read(UC_M68K_REG_A7)
		#print("orig_pc", hex(orig_pc))
		vector_offset = 0x60 + priority * 4
		sp = orig_sp - 8
		self.mu.mem_write(sp, orig_sr.to_bytes(2) + orig_pc.to_bytes(4) + vector_offset.to_bytes(2))
		vbr = 0x5000000 #self.mu.msr_read(M68K_CR_VBR)
		vector = int.from_bytes(self.mu.mem_read(vbr + vector_offset, 4))
		#print("new sp", hex(sp))
		#print("vector", hex(vector))
		sr = ((orig_sr & ~0x1700 ) | 0x2000 | (priority << 8))  # is this correct?
		print("new_sr", hex(sr))
		self.mu.reg_write(UC_M68K_REG_SR, sr)
		self.mu.reg_write(UC_M68K_REG_PC, vector)
		self.mu.reg_write(UC_M68K_REG_A7, sp)

	def run(self):
		self.running = True

		cycles_per_invocation = 1000000
		self.i = 0

		try:
			while self.running:
				#self.mu.ctl_flush_tb()  # unfortunately this seems to be necessary - perhaps a qemu/unicorn bug
				self.mu.emu_start(self.mu.reg_read(UC_M68K_REG_PC), 0, 0, cycles_per_invocation) # TODO: determine reasonable "count" and/or timeout
				self.cycles += cycles_per_invocation
				#print("TICK")

				# TODO: figure out if we should fire the interrupt based on some logic:
				if self.cycles > 24000000:
					print("TICK")
					print(hex(int.from_bytes(self.mu.mem_read(0x0940_0000, 4))))
					print(hex(int.from_bytes(self.mu.mem_read(0x0960_0000, 4))))
					self.deliver_interrupt(6)

		except UcError as e:
			print(e)
			print("pc", hex(self.mu.reg_read(UC_M68K_REG_PC)))
			print("a0", hex(self.mu.reg_read(UC_M68K_REG_A0)))
			print("a1", hex(self.mu.reg_read(UC_M68K_REG_A1)))
			print("a2", hex(self.mu.reg_read(UC_M68K_REG_A2)))

			print("d0", hex(self.mu.reg_read(UC_M68K_REG_D0)))
			print("d1", hex(self.mu.reg_read(UC_M68K_REG_D1)))
			print("d2", hex(self.mu.reg_read(UC_M68K_REG_D2)))

			print("cycles", self.cycles)

if __name__ == "__main__":
	import os

	os.system("""gnome-terminal -- sh -c "rlwrap nc -lp 1234; read -p 'connection closed [ENTER to exit]'" &""")
	time.sleep(0.5)

	emu = ScopeEmu()
	emu.run()
