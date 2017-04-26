import sys
import NSDP
import socket
import binascii

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind(('0.0.0.0', 63322))

pss = NSDP.ProSafeSwitch(
  model    = 'GS108Ev2',
  name     = 'sw1',
  mac      = '28:c6:8e:00:00:01',
  ip       = '172.16.2.2',
  netmask  = '255.255.255.0',
  gateway  = '172.16.2.1',
  dhcp     =  False,
  firmware = '1.00.12',
  ports    = 8,
  password = 'swordfish'
)

pss.portstats[0]['bytes_sent'] = 371671832968
pss.portstats[0]['bytes_received'] = 546442323743
pss.portstats[0]['crc_error_packets'] = 2

pss.link_speed[0] = NSDP.LINK_SPEED_1000M
pss.link_speed[1] = NSDP.LINK_SPEED_1000M
pss.link_speed[2] = NSDP.LINK_SPEED_1000M
pss.link_speed[3] = NSDP.LINK_SPEED_1000M
pss.link_speed[4] = NSDP.LINK_SPEED_1000M
pss.link_speed[5] = NSDP.LINK_SPEED_10G
pss.link_speed[6] = NSDP.LINK_SPEED_10G

pss.cable_test_results[0] = (NSDP.CABLE_TEST_OK, 1)
pss.cable_test_results[1] = (NSDP.CABLE_TEST_OK, 1)
pss.cable_test_results[2] = (NSDP.CABLE_TEST_CROSSTALK, 1)
pss.cable_test_results[3] = (NSDP.CABLE_TEST_UNKNOWN, 1)
pss.cable_test_results[4] = (NSDP.CABLE_TEST_NO_CABLE, 1)
pss.cable_test_results[5] = (NSDP.CABLE_TEST_FIBER_CABLE, 1)
pss.cable_test_results[6] = (NSDP.CABLE_TEST_SHORT_CIRCUIT, 1)
pss.cable_test_results[7] = (NSDP.CABLE_TEST_OPEN_CABLE, 19)

pss.vlan_engine_type = NSDP.VLAN_ENGINE_TYPE_802_ADVANCED
pss.vlans_802[1] = ([1], [6, 7, 8])
pss.vlans_802[2] = ([1], [2, 4])
pss.vlans_802[3] = ([1], [3, 5])
pss.pvids = [1, 2, 3, 2, 3, 1, 1, 1]

pss.bandwidth_limit_in[1] = NSDP.BANDWIDTH_LIMIT_512M
pss.bandwidth_limit_out[1] = NSDP.BANDWIDTH_LIMIT_64M

while True:
  data, addr = sock.recvfrom(1024)
  print 'RECEIVED:'
  print binascii.hexlify(data)
  frame = NSDP.Frame.from_data(data)
  print repr(frame)

  rsp = pss.handle_frame(frame)

  if rsp != None:
    print 'SENT:'
    print repr(rsp)
    print binascii.hexlify(rsp.pack())
    sock.sendto(rsp.pack(), ('255.255.255.255', 63321))
