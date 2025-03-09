# based on https://github.com/ragges/tektools/blob/master/tektool/tektool.c
# tested with an AR488 GPIB adapter on a TDS684A (with the rocker switch flipped)

# current status: it doesn't work properly (the eventual goal is to replicate tektool functionality)

import serial
import time
from tqdm import tqdm

def build_cmd(cmd: bytes, payload: bytes) -> bytes:
	assert(len(cmd) == 1)
	csum = sum(cmd + len(payload).to_bytes(2) + payload) & 0xff
	return cmd + csum.to_bytes(1) + len(payload).to_bytes(2) + payload

def cmd_read_memory(addr: int, length: int) -> 4:
	return build_cmd(b"m", addr.to_bytes(4) + length.to_bytes(4))

def escape(data: bytes) -> bytes:
	for badchar in [b"\x1b", b"\r", b"\n", b"+"]:
		data = data.replace(badchar, b"\x1b" + badchar)
	return data

def read_memory(ser: serial.Serial, addr: int, length: int):
	ser.read_all() # flush input buffer
	mycmd = cmd_read_memory(addr, length)
	print(mycmd)
	ser.write(escape(mycmd) + b"\n")
	ser.flush()
	ser.write(b"++read\n")
	ser.flush()
	ack = ser.read(1)
	print("ack", ack)
	assert(ack == b"+")
	cmd = ser.read(1)
	csum = ser.read(1)[0]
	print("cmd", cmd)
	assert(cmd == b"=")
	length_bytes = ser.read(2)
	length_out = int.from_bytes(length_bytes)
	assert(length_out == length)
	data = ser.read(length_out)
	# TODO: loop until all read?
	assert(len(data) == length_out)
	csum_calc = sum(cmd + length_bytes + data) & 0xff
	#print("csum", csum, csum_calc)
	assert(csum == csum_calc)
	ser.write(escape(b"+") + b"\n") # ack
	return data

with serial.Serial("/dev/ttyUSB0", 115200, timeout=1) as ser:
	time.sleep(2) # wait for the arduino to wake up

	# check the serial->GPIB adapter is alive
	ser.write(b"++ver\n")
	print("Adapter version:", ser.readline().decode().strip())

	#ser.write(b"++addr 7\n") # what my scope is set to
	ser.write(b"++addr 29\n") # actually it needs this I guess, in "firmware update mode"
	ser.write(b"++eor 7\n")  # when receiving, end only on EOI
	ser.write(b"++eos 3\n")  # when sending, do not end with any characters
	ser.write(b"++eoi 1\n")  # when sending, end with EOI

	if 0: # this doesn't work in firmware update mode!
		# check the scope is alive
		ser.write(b"*IDN?\n")
		#time.sleep(0.1)
		#ser.write(b"++eoi 1\n")
		#time.sleep(0.1)
		#ser.write(b"++eoi 0\n")
		#time.sleep(0.1)
		ser.write(b"++read\n")
		scope_ver = ser.readline()
		print(scope_ver)
		if b"TEKTRONIX" not in scope_ver:
			raise Exception("could not read scope version")
		print("Scope version:", scope_ver.decode().strip())

	dump_addr = 0x0
	dump_len = 0x40000
	BLOCK_SIZE = 0x207 # 0x400 is max that works
	with open(f"{hex(dump_addr)}-{hex(dump_addr+dump_len)}.bin", "wb") as outfile:
		for i in tqdm(range(0, dump_len, BLOCK_SIZE)):
			# TODO: don't overread if last block is small
			time.sleep(1.5) # unfortunately this seems to be necessary
			res = read_memory(ser, dump_addr+i, BLOCK_SIZE)
			outfile.write(res)
			outfile.flush()


"""
failures:
b'm}\x00\x08\x00\x00\x00\x07\x00\x00\x00\x01'

b'm{\x00\x08\x00\x00\x05\x00\x00\x00\x01\x00'

b'm\x88\x00\x08\x00\x00\x12\x00\x00\x00\x01\x00'

b'm\x8d\x00\x08\x00\x00\x0b\x0b\x00\x00\x01\x01'

b'm\x87\x00\x08\x00\x00\x05\n\x00\x00\x01\x02'

b'mV\x00\x08\x00\x000\xa8\x00\x00\x02\x07'
"""
