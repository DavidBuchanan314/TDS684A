BASE_ADDR = 0x0100_0000

data = open("dumps/FlashRom.bin", "rb").read()

# heuristic to find the "end" of rom by stripping of \xff padding
symbol_count_offset = len(data) - 4
while data[symbol_count_offset:symbol_count_offset+4] == b"\xff\xff\xff\xff":
	symbol_count_offset -= 4

print("symbol_count_offset", hex(symbol_count_offset))

num_symbols = int.from_bytes(data[symbol_count_offset:symbol_count_offset+4])

print("num_symbols", hex(num_symbols))

symbol_table_start = symbol_count_offset - num_symbols*14

print("symbol_table_start", hex(symbol_table_start))

for i in range(num_symbols):
	offset = symbol_table_start + i*14
	name_off = int.from_bytes(data[offset+4:offset+8]) - BASE_ADDR
	symbol_value = int.from_bytes(data[offset+8:offset+12])
	symbol_type = int.from_bytes(data[offset+12:offset+14])
	name_end = data.index(b"\x00", name_off)
	name = data[name_off:name_end].decode()
	#if symbol_type == 0x500:
	print(name, hex(symbol_type), hex(symbol_value))
