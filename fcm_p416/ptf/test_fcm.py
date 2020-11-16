import logging

from ptf import config
from collections import namedtuple
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
import random
import time

from fcm_utils import *

## SKETCH CONSTANT VALUES ##

DEBUGGING = False				# debugging? (True -> yes)
FROM_HW = True					# From Tofino hardware model, must be True.
SKETCH_W1 = 524288				# 8-bit, level 1
SKETCH_W2 = 65536				# 16-bit, level 2
SKETCH_W3 = 8192				# 32-bit, level 3
ADD_LEVEL1 = 255				# 2^8 -2 + 1 (actual count is 254)
ADD_LEVEL2 = 65789				# (2^8 - 2) + (2^16 - 2) + 1 (actual count is 65788)


# Cardinality with adaptive spacing for saving TCAM, using the sensitivity of LC estimator. 
# This technique makes an additional error at most 0.3 % 
n_leaf = SKETCH_W1							# number of leaf nodes at a single tree
epsilon = 0.003 							# 0.3 %
m_occupied = 0 								# number of occupied registers
n_entry = 0 								# number of entries
match_table = [None] * (n_leaf) 			# for PTF-testbed
range_table = [(None, None)] * (n_leaf-1)	# for TCAM range, a <= x < b

while m_occupied <= n_leaf -1:
	if (m_occupied is 0):
		match_table[m_occupied] = 0			# no insertion, card = 0
		m_occupied += 1
		n_entry += 1
		continue
	# minimum spacing is 1
	delta = int(math.floor(max(lc_delta_m0(m_occupied, n_leaf, epsilon), 1))) 
	# here we use under-estimation for simplicity, but we can further improve.
	est_card = int(lc_cardinality(m_occupied, n_leaf)) 
	
	for i in range(delta):
		if (m_occupied + i <= n_leaf-1):
			match_table[m_occupied + i] = est_card
	range_table[n_entry] = (m_occupied, m_occupied + delta)
	m_occupied += delta
	n_entry += 1


""" This test module is to evaluate fcm.p4 """

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)
    swports.sort()

if swports == []:
    swports = list(range(9))



class FCMTest(BfRuntimeTest):
	"""@brief This test inserts multiple random TCP packets, and evaluates the accuracy of flow size, cardinality, and possibly, flow size distribution and entropy. In fcm.p4, the flow ID is source IP. 
	"""
	def setUp(self):
		client_id = 0
		BfRuntimeTest.setUp(self, client_id)
		# p4_name = "fcm"
		# BfRuntimeTest.setUp(self, client_id, p4_name)


	def runTest(self):
		ig_port = swports[1]
		num_pipes = int(testutils.test_param_get('num_pipes'))

		logger.info("[INFO-Switch] Adding TCAM Ranges for cardinality...")
		bfrt_info = self.interface.bfrt_info_get("fcm")
		card_range_tcam = bfrt_info.table_get("SwitchIngress.fcmsketch.tb_fcm_cardinality")
		target = gc.Target(device_id=0, pipe_id=0xffff)


		NUM_FLOWS = 1000			# number of sample flows
		MAX_FLOW_SIZE = 10 			# max size of flows
		num_packets = 0				# PTF generates 40 packets per second
		seed = 30669				# random seed
		random.seed(seed)
		logger.info("Seed used %d" % seed)

		# info of sample packet
		dmac = "00:11:22:33:44:55"
		ip_src = None # random flow ID
		ip_dst = "192.168.1.1" 
		ip_src_list = []
		

		# # Make sure the table starts off empty
		resp_empty = card_range_tcam.entry_get(target, None, {"from_hw": FROM_HW})
		for data, key in resp_empty:
			assert 0, "Shouldn't have hit here since table is supposed to be empty"

		# Insert TCAM Range Entries
		for i in range(1, n_entry-1):
			if DEBUGGING:
				logger.info("Rule %d : Card %d <- range (%d, %d)", i, int(lc_cardinality(float(range_table[i][0]), float(n_leaf))), range_table[i][0], range_table[i][1])
			# add entry
			card_range_tcam.entry_add(target, 
				[card_range_tcam.make_key(
					[gc.KeyTuple('$MATCH_PRIORITY', 1),
					gc.KeyTuple('num_occupied_reg', low=int(range_table[i][0]), high=int(range_table[i][1]))]
					)],
				[card_range_tcam.make_data([gc.DataTuple('card_match', int(lc_cardinality(float(range_table[i][0]), float(n_leaf))))], 
					'SwitchIngress.fcmsketch.fcm_action_set_cardinality')]
			)
		logger.info("[INFO-Switch] TCAM Ranges %d entries are successfully added.", n_entry)



		# generate random packets and insert
		logger.info("[INFO-Switch] Sending %d flows on port %d", NUM_FLOWS, ig_port)
		for i in range(NUM_FLOWS):
			flow_size = random.randint(1, MAX_FLOW_SIZE) # 1 ~ 10
			num_packets += flow_size
			ip_src = "%d.%d.%d.%d" % (random.randint(0, 255), random.randint(0, 255), 
									random.randint(0, 255), random.randint(0, 255))
			ip_src_list.append((ip_src, flow_size));
			# sending packets
			pkt = testutils.simple_tcp_packet(eth_dst=dmac, ip_src=ip_src, ip_dst=ip_dst)
			testutils.send_packet(self, ig_port, pkt, count=flow_size)
			if (i % 100 is 0):
				logger.info("[INFO-Switch] %d / %d flows are done...", i, NUM_FLOWS)

		
		logger.info("[INFO-Switch] Wait until packets are all received...")
		# check all packets are sent
		while True:
			register_pktcount = bfrt_info.table_get("SwitchIngress.num_pkt")
			register_pktcount.operations_execute(target, 'Sync')
			
			resp_pktcount = register_pktcount.entry_get(target,
					[register_pktcount.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
					{"from_hw": FROM_HW})
			data, _ = next(resp_pktcount)
			data_dict = data.to_dict()
			
			logger.info("[INFO-Switch] Sent : %d, Received : %d\t\t wait 10s more...", num_packets, data_dict["SwitchIngress.num_pkt.f1"][0])
			if (data_dict["SwitchIngress.num_pkt.f1"][0] == num_packets):
				break
			time.sleep(10)

		assert data_dict["SwitchIngress.num_pkt.f1"][0] == num_packets, "Error: Packets are not correctly inserted..."

		

		# call the register values and get flow size estimation
		logger.info("[INFO-FCM] Start query processing...")
		ARE = 0
		AAE = 0
		Card_RE = 0
		for i in range(NUM_FLOWS):
			# Flow size

			## depth 1, level 1
			hash_d1 = fcm_crc32(ip_src_list[i][0])
			register_l1_d1 = bfrt_info.table_get("SwitchIngress.fcmsketch.sketch_reg_l1_d1")
			resp_l1_d1 = register_l1_d1.entry_get(target,
					[register_l1_d1.make_key([gc.KeyTuple('$REGISTER_INDEX', hash_d1 % SKETCH_W1)])],
					{"from_hw": FROM_HW})
			data_d1, _ = next(resp_l1_d1)
			data_d1_dict = data_d1.to_dict()
			val_d1 = data_d1_dict["SwitchIngress.fcmsketch.sketch_reg_l1_d1.f1"][0]
			# overflow to level 2?
			if (val_d1 is ADD_LEVEL1):
				register_l2_d1 = bfrt_info.table_get("SwitchIngress.fcmsketch.sketch_reg_l2_d1")
				resp_l2_d1 = register_l2_d1.entry_get(target,
						[register_l2_d1.make_key([gc.KeyTuple('$REGISTER_INDEX', hash_d1 % SKETCH_W2)])],
						{"from_hw": FROM_HW})
				data_d1, _ = next(resp_l2_d1)
				data_d1_dict = data_d1.to_dict()
				val_d1 = data_d1_dict["SwitchIngress.fcmsketch.sketch_reg_l2_d1.f1"][0] + ADD_LEVEL1 - 1
				# overflow to level 3?
				if (val_d1 is ADD_LEVEL2):
					register_l3_d1 = bfrt_info.table_get("SwitchIngress.fcmsketch.sketch_reg_l3_d1")
					resp_l3_d1 = register_l3_d1.entry_get(target,
							[register_l3_d1.make_key([gc.KeyTuple('$REGISTER_INDEX', hash_d1 % SKETCH_W3)])],
							{"from_hw": FROM_HW})
					data_d1, _ = next(resp_l3_d1)
					data_d1_dict = data_d1.to_dict()
					val_d1 = data_d1_dict["SwitchIngress.fcmsketch.sketch_reg_l3_d1.f1"][0] + ADD_LEVEL2 - 1

			## depth 2, level 1
			hash_d2 = fcm_crc32_mpeg2(ip_src_list[i][0])
			register_l1_d2 = bfrt_info.table_get("SwitchIngress.fcmsketch.sketch_reg_l1_d2")
			resp_l1_d2 = register_l1_d2.entry_get(target,
					[register_l1_d2.make_key([gc.KeyTuple('$REGISTER_INDEX', hash_d2 % SKETCH_W1)])],
					{"from_hw": FROM_HW})
			data_d2, _ = next(resp_l1_d2)
			data_d2_dict = data_d2.to_dict()
			val_d2 = data_d2_dict["SwitchIngress.fcmsketch.sketch_reg_l1_d2.f1"][0]
			# overflow to level 2?
			if (val_d2 is ADD_LEVEL1):
				register_l2_d2 = bfrt_info.table_get("SwitchIngress.fcmsketch.sketch_reg_l2_d2")
				resp_l2_d2 = register_l2_d2.entry_get(target,
						[register_l2_d2.make_key([gc.KeyTuple('$REGISTER_INDEX', hash_d2 % SKETCH_W2)])],
						{"from_hw": FROM_HW})
				data_d2, _ = next(resp_l2_d2)
				data_d2_dict = data_d2.to_dict()
				val_d2 = data_d2_dict["SwitchIngress.fcmsketch.sketch_reg_l2_d2.f1"][0] + ADD_LEVEL1 - 1
				# overflow to level 3?
				if (val_d2 is ADD_LEVEL2):
					register_l3_d2 = bfrt_info.table_get("SwitchIngress.fcmsketch.sketch_reg_l3_d2")
					resp_l3_d2 = register_l3_d2.entry_get(target,
							[register_l3_d2.make_key([gc.KeyTuple('$REGISTER_INDEX', hash_d2 % SKETCH_W3)])],
							{"from_hw": FROM_HW})
					data_d2, _ = next(resp_l3_d2)
					data_d2_dict = data_d2.to_dict()
					val_d2 = data_d2_dict["SwitchIngress.fcmsketch.sketch_reg_l3_d2.f1"][0] + ADD_LEVEL2 - 1

			if DEBUGGING:
				logger.info("[INFO-FCM] Flow %d - True : %d, Est of FCM : %d", i, ip_src_list[i][1], min(val_d1, val_d2))

			final_query = min(val_d1, val_d2)
			ARE += abs(final_query - ip_src_list[i][1]) / float(ip_src_list[i][1])
			AAE += abs(final_query - ip_src_list[i][1]) / 1.0
		logger.info(bcolors.OKBLUE + "[INFO-FCM] Flow Size - ARE = %2.8f" + bcolors.ENDC, (ARE / NUM_FLOWS))
		logger.info(bcolors.OKBLUE + "[INFO-FCM] Flow Size - AAE = %2.8f" + bcolors.ENDC, (AAE / NUM_FLOWS))

		# # Cardinality

  		## check the cardinality parameter
		register_occupied_num = bfrt_info.table_get("SwitchIngress.fcmsketch.reg_num_empty")
		resp_occupied_num = register_occupied_num.entry_get(target,
					[register_occupied_num.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
					{"from_hw": FROM_HW})
		data, _ = next(resp_occupied_num)
		data_dict = data.to_dict()
		avg_occupied_leaf = math.floor(data_dict["SwitchIngress.fcmsketch.reg_num_empty.f1"][0] / 2.0)
		est_cardinality = match_table[int(avg_occupied_leaf)]
		Card_RE = abs(est_cardinality - NUM_FLOWS) / NUM_FLOWS
		logger.info(bcolors.OKBLUE + "[INFO-FCM] Cardinality RE = %0.9e (True : %d, Est of FCM : %d)" + bcolors.ENDC, Card_RE, NUM_FLOWS, est_cardinality)


		# You can also estimate flow size distribution and entropy by loading the sketch values on simulator.
		# You MUST CHANGE the hash functions as the simulator currently uses BOBHASH.
		# You can use the cpp codes "./calc_hash.cpp" to sync hash values.
		# Currently, our simulator supports only 3-level FCM (8,16,32-bit).
		# Mainly it is because of heuristic complexity truncation of EM algorithm.
		# In future, we will generalize the implementation.






