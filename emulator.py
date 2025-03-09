"""
Interrupt 0x78 drives the task scheduler

"""

from unicorn import *
from unicorn.m68k_const import *
import sys

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

def hook_block(uc: Uc, address, idk, user_data):
	print(hex(address))#, hex(uc.reg_read(UC_M68K_REG_A7)))#, symbol_lookup.get(address))
	if 0:#(address == 0x1001dc6 and False) or address == 0x0100a508: # board ID, RAM test
		print("oops")
		sp = uc.reg_read(UC_M68K_REG_A7)
		print("sp", hex(sp))
		retaddr = int.from_bytes(uc.mem_read(sp, 4))
		uc.reg_write(UC_M68K_REG_D0, 0) # return fake success
		uc.reg_write(UC_M68K_REG_A7, sp+4) # pop
		uc.reg_write(UC_M68K_REG_PC, retaddr)
		return

def hook_intr(uc: Uc, foo, user_data):
	print("INTERRUPT", foo)
	if foo == 256: # RTE?
		print("RTE")
		sp = uc.reg_read(UC_M68K_REG_A7)
		#print(uc.mem_read(sp-0x10, 0x20).hex())
		sr = int.from_bytes(uc.mem_read(sp, 2))
		pc = int.from_bytes(uc.mem_read(sp+2, 4))
		# "vector offset" here, see MC68020 datasheet "6.4 EXCEPTION STACK FRAME FORMAT"
		#print("sp", hex(sp))
		#print("sr", hex(sr))
		#print("pc", hex(pc))
		uc.reg_write(UC_M68K_REG_A7, sp+8) # pop
		uc.reg_write(UC_M68K_REG_SR, sr)
		uc.reg_write(UC_M68K_REG_PC, pc)
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
	return 0xc0 # skip all bootrom tests

class MC68681:
	def __init__(self, base):
		self.base = base
		self.foo = 0
	
	def uc_map(self, uc: Uc):
		uc.mmio_map(self.base, 0x1000, self.reg_read, None, self.reg_write, None)
	
	def reg_read(self, uc: Uc, offset: int, size: int, user_data) -> int:
		assert(size == 1)
		#print(hex(uc.reg_read(UC_M68K_REG_PC)))
		if offset == 1:
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
		# mystery device 4
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

		uart = MC68681(0x00a0_0000)
		uart.uc_map(self.mu)

		# tracing all instructions
		#mu.hook_add(UC_HOOK_CODE, hook_code)
		#self.mu.hook_add(UC_HOOK_BLOCK, hook_block)

		self.mu.hook_add(UC_HOOK_INTR, hook_intr)

		self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

		# Status Register - enable supervisor mode and mask interrupts
		self.mu.reg_write(UC_M68K_REG_SR, 0x2700)

		# start execution using the vector table
		self.mu.reg_write(UC_M68K_REG_A7, int.from_bytes(self.mu.mem_read(0, 4))) # SP
		self.mu.reg_write(UC_M68K_REG_PC, int.from_bytes(self.mu.mem_read(4, 4)))

		self.running = False
		self.cycles = 0

	def run(self):
		self.running = True

		cycles_per_invocation = 10000
		self.i = 0

		try:
			while self.running:
				self.mu.ctl_flush_tb()  # unfortunately this seems to be necessary - perhaps a qemu/unicorn bug
				self.mu.emu_start(self.mu.reg_read(UC_M68K_REG_PC), 0, 0, cycles_per_invocation) # TODO: determine reasonable "count" and/or timeout
				self.cycles += cycles_per_invocation
				#print("TICK")

				# TODO: figure out if we should fire the interrupt based on some logic:
				if self.cycles > 24000000:
					print("TICK")
					#interrupt = 0x78
					#interrupt = 0x68
					orig_sr = self.mu.reg_read(UC_M68K_REG_SR)
					print("orig_sr", hex(orig_sr))
					interrupt = 30 # works
					#interrupt = 25 + (self.i%7)
					self.i += 1
					if 1 or not orig_sr & 0x0700:
						orig_pc = self.mu.reg_read(UC_M68K_REG_PC)
						orig_sp = self.mu.reg_read(UC_M68K_REG_A7)
						#print("orig_pc", hex(orig_pc))
						sp = orig_sp - 8
						self.mu.mem_write(sp, orig_sr.to_bytes(2) + orig_pc.to_bytes(4) + (interrupt * 4).to_bytes(2))
						vbr = 0x5000000 #self.mu.msr_read(M68K_CR_VBR)
						vector = int.from_bytes(self.mu.mem_read(vbr + interrupt*4, 4))
						#print("new sp", hex(sp))
						#print("vector", hex(vector))
						self.mu.reg_write(UC_M68K_REG_SR, ((orig_sr & 0x0700 )| 0x2700)) # is this correct?
						self.mu.reg_write(UC_M68K_REG_PC, vector)
						self.mu.reg_write(UC_M68K_REG_A7, sp)
				
		except UcError as e:
			print(e)
			print("pc", hex(self.mu.reg_read(UC_M68K_REG_PC)))
			print("a0", hex(self.mu.reg_read(UC_M68K_REG_A0)))
			print("a1", hex(self.mu.reg_read(UC_M68K_REG_A1)))
			print("a2", hex(self.mu.reg_read(UC_M68K_REG_A2)))

			print("d0", hex(self.mu.reg_read(UC_M68K_REG_D0)))
			print("d1", hex(self.mu.reg_read(UC_M68K_REG_D1)))
			print("d2", hex(self.mu.reg_read(UC_M68K_REG_D2)))

if __name__ == "__main__":
	emu = ScopeEmu()
	emu.run()
