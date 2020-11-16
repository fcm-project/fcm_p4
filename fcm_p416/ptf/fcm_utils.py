import numpy as np
import math
import zlib
import struct

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Cardinality with adaptive spacing for saving TCAM, using the sensitivity of LC estimator. 
# This technique makes an additional error at most 0.3 %
def lc_cardinality(m_occupied, m):
	return m * np.log(m / float(m-m_occupied))

def lc_delta_m0(m_occupied, m, epsilon):
	return (m - m_occupied) * np.log(m / float(m - m_occupied)) * epsilon


def fcm_crc32_mpeg2(msg="192.168.1.1"):
	crc = np.uint32(0xFFFFFFFF)
	msb = np.uint32(0)
	msg_arr = msg.split(".") # convert IP address to 8-bit values
	
	for i in range(len(msg_arr)):
		# xor next byte to upper bits of crc
		crc ^= np.uint32(np.uint32(msg_arr[i]) << 24)
		for j in range(8):
			msb = np.uint32(crc >> 31)
			crc = np.uint32(crc << 1)
			crc = np.uint32(crc ^ (np.uint32(0 - msb) & np.uint32(0x04C11DB7)));
	return crc

def do_crc(s):
    n = zlib.crc32(s)
    return n + (1<<32) if n < 0 else n

def fcm_crc32(msg="192.168.1.1"):
	msg_arr = msg.split(".")
	msg_val = b''
	for i in range(len(msg_arr)):
		msg_val = msg_val + struct.pack("B", int(msg_arr[i]))
	# msg_val = b'\xc0\xa8\x01\x01'
	return do_crc(msg_val)


# print("util directory - test : %f" % lc_cardinality(10000, 524288))
## debugging
# print(fcm_crc32() % 524288 ) # 408597
# print(fcm_crc32_mpeg2() % 524288 ) # 465664