import struct, binascii
from suitcase.structure import Structure
from suitcase.fields import UBInt8, UBInt16, UBInt32, UBInt64, Magic, LengthField, Payload
from suitcase.fields import DispatchField, DispatchTarget, DependentField, ConditionalField, FieldArray, FieldProperty, UBInt8Sequence, SubstructureField

OPERATION_READ_REQUEST = 1
OPERATION_READ_RESPONSE = 2
OPERATION_WRITE_REQUEST = 3
OPERATION_WRITE_RESPONSE = 4

LINK_SPEED_0 = 0
LINK_SPEED_10M_ALT = 1
LINK_SPEED_10M = 2
LINK_SPEED_100M_ALT = 3
LINK_SPEED_100M = 4
LINK_SPEED_1000M = 5
LINK_SPEED_10G = 6

CABLE_TEST_OK = 0
CABLE_TEST_NO_CABLE = 1
CABLE_TEST_OPEN_CABLE = 2
CABLE_TEST_SHORT_CIRCUIT = 3
CABLE_TEST_FIBER_CABLE = 4
CABLE_TEST_SHORTED_CABLE = 5
CABLE_TEST_UNKNOWN = 6
CABLE_TEST_CROSSTALK = 7

BANDWIDTH_LIMIT_0 = 0
BANDWIDTH_LIMIT_512K = 1
BANDWIDTH_LIMIT_1M = 2
BANDWIDTH_LIMIT_2M = 3
BANDWIDTH_LIMIT_4M = 4
BANDWIDTH_LIMIT_8M = 5
BANDWIDTH_LIMIT_16M = 6
BANDWIDTH_LIMIT_32M = 7
BANDWIDTH_LIMIT_64M = 8
BANDWIDTH_LIMIT_128M = 9
BANDWIDTH_LIMIT_256M = 10
BANDWIDTH_LIMIT_512M = 11

QOS_TYPE_PORT_BASED = 1
QOS_TYPE_DSCP_BASED = 2

QOS_PORT_HIGH = 1
QOS_PORT_MEDIUM = 2
QOS_PORT_NORMAL = 3
QOS_PORT_LOW = 4

VLAN_ENGINE_TYPE_NONE = 0
VLAN_ENGINE_TYPE_PORT_BASIC = 1
VLAN_ENGINE_TYPE_PORT_ADVANCED = 2
VLAN_ENGINE_TYPE_802_BASIC = 3
VLAN_ENGINE_TYPE_802_ADVANCED = 4

def pack_mac(mac):
  mac = mac.replace(':', '')
  if len(mac) != 12:
    raise ValueError
  return binascii.unhexlify(mac)

def unpack_mac(data):
  if len(data) == 0:
    return ''
  if len(data) != 6:
    raise ValueError('length was %d' % len(data))
  mac = binascii.hexlify(data)
  return ':'.join(a + b for a, b in zip(mac[::2], mac[1::2]))

def pack_ipv4(ipv4):
  ipv4 = map(int, ipv4.split('.'))
  if len(ipv4) != 4:
    raise ValueError('length was %d' % len(ipv4))
  return struct.pack('!BBBB', ipv4[0], ipv4[1], ipv4[2], ipv4[3])

def unpack_ipv4(data):
  if len(data) == 0:
    return ''
  if len(data) != 4:
    raise ValueError
  return '.'.join(map(str, struct.unpack('BBBB', data)))

class PortTrafficStatistics(Structure):
  port = UBInt8()
  bytes_received = UBInt64()
  bytes_sent = UBInt64()
  unknown_0 = Magic('\x00\x00\x00\x00\x00\x00\x00\x00')
  unknown_1 = Magic('\x00\x00\x00\x00\x00\x00\x00\x00')
  unknown_2 = Magic('\x00\x00\x00\x00\x00\x00\x00\x00')
  crc_error_packets = UBInt64()

class MessageStructure(Structure):
  def get_message(self):
    message = Message()
    for t in MESSAGE_DISPATCH_MAPPING:
      if MESSAGE_DISPATCH_MAPPING[t] == self.__class__:
        message.tag = t
        break
    message.message = self
    return message

class DeviceNameMessage(MessageStructure):
  value = Payload()

class DeviceModelMessage(MessageStructure):
  value = Payload()

class MacAddressMessage(MessageStructure):
  value = Payload()
  address = FieldProperty(value, onget=unpack_mac, onset=pack_mac)

class IPAddressMessage(MessageStructure):
  value = Payload()
  ip = FieldProperty(value, onget=unpack_ipv4, onset=pack_ipv4)

class NetmaskMessage(MessageStructure):
  value = Payload()
  netmask = FieldProperty(value, onget=unpack_ipv4, onset=pack_ipv4)

class GatewayMessage(MessageStructure):
  value = Payload()
  ip = FieldProperty(value, onget=unpack_ipv4, onset=pack_ipv4)

class NewPasswordMessage(MessageStructure):
  value = Payload()

class PasswordMessage(MessageStructure):
  value = Payload()

class DHCPStatusMessage(MessageStructure):
  value = Payload()
  enabled = FieldProperty(value,
                          onget=lambda v: v == '\x01',
                          onset=lambda v: '\x01' if v else '\x00')

class FirmwareVersionMessage(MessageStructure):
  value = Payload()

class FirmwareUpgradeMessage(MessageStructure):
  value = Payload()

class RebootMessage(MessageStructure):
  value = Payload()

class EncryptPasswordMessage(MessageStructure):
  value = Payload()
  encrypted = FieldProperty(value,
                            onget=lambda v: v == '\x00\x00\x00\x01',
                            onset=lambda v: '\x00\x00\x00\x01' if v else '\x00\x00\x00\x00')

class FactoryResetMessage(MessageStructure):
  value = Payload()

class SpeedLinkStatusMessage(MessageStructure):
  value = Payload()
  port_speed = FieldProperty(value,
                             onget=lambda v: None if len(v) == 0 else (ord(v[0]), ord(v[1])),
                             onset=lambda v: chr(v[0]) + chr(v[1]) + '\x01')

class PortTrafficStatisticsMessage(MessageStructure):
  length = DependentField('length')
  empty = True
  data = ConditionalField(SubstructureField(PortTrafficStatistics), lambda v: v.length > 0 or not v.empty)

class ResetPortTrafficStatisticMessage(MessageStructure):
  value = Payload()

class TestCableMessage(MessageStructure):
  value = Payload()

class TestCableResultMessage(MessageStructure):
  value = Payload()
  port_result_meters = FieldProperty(value,
                                     onget=lambda v: None if len(v) == 0 else (ord(v[0]), None, None) if len(v) == 1 else struct.unpack('!BII', v),
                                     onset=lambda v: chr(v[0]) if v[1] == None or v[2] == None else struct.pack('!BII', v[0], v[1], v[2]))

class VLANEngineMessage(MessageStructure):
  value = Payload()
  type = FieldProperty(value,
                       onget=lambda v: None if len(v) == 0 else ord(v),
                       onset=lambda v: chr(v))

class VLANIDMessage(MessageStructure):
  value = Payload()

  def get_conf(payload):
    if payload == None or len(payload) == 0:
      return None
    vlanid = struct.unpack('!H', payload[0:2])[0]
    pp = ord(payload[2])
    ports = []
    for p in range(0, 8):
      if pp & (1 << (7 - p)):
        ports.append(p + 1)
    return (vlanid, ports)

  def set_conf(conf):
    if conf == None or conf[0] == None:
      return '\x00\x00\x00'
    vlanid = conf[0]
    ports = conf[1]
    pp = 0
    for p in range(0, 8):
      if p + 1 in ports:
        pp = pp | (1 << (7 - p))
    return struct.pack('!HB', vlanid, pp)

  config = FieldProperty(value, onget=get_conf, onset=set_conf)

class VLANID802Message(MessageStructure):
  value = Payload()

  def get_conf(payload):
    if payload == None or len(payload) == 0:
      return None
    vlanid = struct.unpack('!H', payload[0:2])[0]
    if len(payload) == 2:
      return (vlanid, None)

    mp = ord(payload[2]) & (~ord(payload[3]))
    untag_ports = []
    for p in range(0, 8):
      if mp & (1 << (7 - p)):
        untag_ports.append(p + 1)

    mp = ord(payload[3])
    tag_ports = []
    for p in range(0, 8):
      if mp & (1 << (7 - p)):
        tag_ports.append(p + 1)

    return (vlanid, tag_ports, untag_ports)

  def set_conf(conf):
    if conf == None or conf[0] == None:
      return '\x00\x00\x00\x00' # TODO
    vlanid = conf[0]
    tag_ports = conf[1]
    untag_ports = conf[2]
    if tag_ports == None or untag_ports == None:
      return struct.pack('!H', vlanid)

    tp = 0
    for p in range(0, 8):
      if p + 1 in tag_ports:
        tp = tp | (1 << (7 - p))

    up = tp
    for p in range(0, 8):
      if p + 1 in untag_ports:
        up = up | (1 << (7 - p))

    return struct.pack('!HBB', vlanid, up, tp)

  config = FieldProperty(value, onget=get_conf, onset=set_conf)

class VLANID802DeleteMessage(MessageStructure):
  value = Payload()
  vlanid = FieldProperty(value,
                         onget=lambda v: None if len(v) == 0 else struct.unpack('!H', v)[0],
                         onset=lambda v: struct.pack('!H', v))

class VLANPVIDMessage(MessageStructure):
  value = Payload()
  config = FieldProperty(value,
                         onget=lambda v: None if len(v) == 0 else struct.unpack('!BH', v),
                         onset=lambda v: struct.pack('!BH', v[0], v[1]))

class QOSMessage(MessageStructure):
  value = Payload()
  type = FieldProperty(value,
                       onget=lambda v: None if len(v) == 0 else ord(v),
                       onset=lambda v: chr(v))

class PortbasedQOSMessage(MessageStructure):
  value = Payload()
  config = FieldProperty(value,
                         onget=lambda v: None if len(v) == 0 else struct.unpack('!BB', v),
                         onset=lambda v: struct.pack('!BB', v[0], v[1]))

class BandwidthLimitInMessage(MessageStructure):
  value = Payload()

  def get_conf(payload):
    if payload == None or len(payload) != 5:
      return None
    return struct.unpack('!BI', payload)

  def set_conf(conf):
    port = conf[0]
    bandwidth = conf[1]
    return struct.pack('!BI', port, bandwidth)

  config = FieldProperty(value, onget=get_conf, onset=set_conf)

class BandwidthLimitOutMessage(MessageStructure):
  value = Payload()

  def get_conf(payload):
    if payload == None or len(payload) != 5:
      return None
    return struct.unpack('!BI', payload)

  def set_conf(conf):
    port = conf[0]
    bandwidth = conf[1]
    return struct.pack('!BI', port, bandwidth)

  config = FieldProperty(value, onget=get_conf, onset=set_conf)

class BroadcastBandwidthMessage(MessageStructure):
  value = Payload()

  def get_conf(payload):
    if payload == None or len(payload) != 5:
      return None
    return struct.unpack('!BI', payload)

  def set_conf(conf):
    port = conf[0]
    bandwidth = conf[1]
    return struct.pack('!BI', port, bandwidth)

  config = FieldProperty(value, onget=get_conf, onset=set_conf)

class PortMirrorMessage(MessageStructure):
  value = Payload()

  def get_conf(payload):
    if len(payload) == 0:
      return None
    sp = ord(payload[2])
    source_ports = []
    for p in range(0, 8):
      if sp & (1 << (7 - p)):
        source_ports.append(p + 1)
    return (ord(payload[0]), source_ports)

  def set_conf(conf):
    if conf == None or conf[0] == None:
      return '\x00\x00\x00'
    destination_port = conf[0]
    source_ports = conf[1]
    sp = 0
    for p in range(0, 8):
      if p + 1 in source_ports:
        sp = sp + (1 << (7 - p))
    return chr(destination_port) + '\x00' + chr(sp)

  config = FieldProperty(value,
                         onget=get_conf,
                         onset=set_conf)

class NumberOfPortsMessage(MessageStructure):
  value = Payload()
  ports = FieldProperty(value,
                        onget=lambda v: None if len(v) == 0 else ord(v[0]),
                        onset=lambda v: chr(v))

class IGMPSnoopingStatusMessage(MessageStructure):
  value = Payload()
  vlanid = FieldProperty(value,
                         onget=lambda v: None if len(v) == 0 else struct.unpack('!H', v[2:4])[0] if v[0:2] == '\x00\x01' else 0,
                         onset=lambda v: struct.pack('!HH', 1 if v > 0 else 0, v))


class LoopDetectionMessage(MessageStructure):
  value = Payload()
  enabled = FieldProperty(value,
                          onget=lambda v: v == '\x01',
                          onset=lambda v: '\x01' if v else '\x00')

class BlockUnknownMulticastsMessage(MessageStructure):
  value = Payload()
  enabled = FieldProperty(value,
                          onget=lambda v: v == '\x01',
                          onset=lambda v: '\x01' if v else '\x00')

class IGMPHeaderValidationMessage(MessageStructure):
  value = Payload()
  enabled = FieldProperty(value,
                          onget=lambda v: v == '\x01',
                          onset=lambda v: '\x01' if v else '\x00')

class BroadcastFilteringMessage(MessageStructure):
  value = Payload()
  enabled = FieldProperty(value,
                          onget=lambda v: v == '\x03',
                          onset=lambda v: '\x03' if v else '\x00')

class UnknownMessage0002(MessageStructure):
  value = Payload()

class UnknownMessage0005(MessageStructure):
  value = Payload()

class UnknownMessage000c(MessageStructure):
  value = Payload()

class UnknownMessage000e(MessageStructure):
  value = Payload()

class UnknownMessage000f(MessageStructure):
  value = Payload()

class UnknownMessage0017(MessageStructure):
  value = Payload()

class UnknownMessage1c00(MessageStructure):
  value = Payload()

class UnknownMessage6400(MessageStructure):
  value = Payload()

class UnknownMessage7400(MessageStructure):
  value = Payload()

class UnknownMessage7c00(MessageStructure):
  value = Payload()

class UnknownMessage8000(MessageStructure):
  value = Payload()

class UnknownMessage8800(MessageStructure):
  value = Payload()

class UnknownMessage8c00(MessageStructure):
  value = Payload()

class UnknownMessage9400(MessageStructure):
  value = Payload()

class EndOfMessages(MessageStructure):
  pass

MESSAGE_DISPATCH_MAPPING = {
  0x0001: DeviceModelMessage,
  0x0002: UnknownMessage0002,
  0x0003: DeviceNameMessage,
  0x0004: MacAddressMessage,
  0x0005: UnknownMessage0005,
  0x0006: IPAddressMessage,
  0x0007: NetmaskMessage,
  0x0008: GatewayMessage,
  0x0009: NewPasswordMessage,
  0x000a: PasswordMessage,
  0x000b: DHCPStatusMessage,
  0x000c: UnknownMessage000c,
  0x000d: FirmwareVersionMessage,
  0x000e: UnknownMessage000e,
  0x000f: UnknownMessage000f,
  0x0010: FirmwareUpgradeMessage,
  0x0013: RebootMessage,
  0x0014: EncryptPasswordMessage,
  0x0017: UnknownMessage0017,
  0x0400: FactoryResetMessage,
  0x0c00: SpeedLinkStatusMessage,
  0x1000: PortTrafficStatisticsMessage,
  0x1400: ResetPortTrafficStatisticMessage,
  0x1800: TestCableMessage,
  0x1c00: TestCableResultMessage,
  0x2000: VLANEngineMessage,
  0x2400: VLANIDMessage,
  0x2800: VLANID802Message,
  0x2c00: VLANID802DeleteMessage,
  0x3000: VLANPVIDMessage,
  0x3400: QOSMessage,
  0x3800: PortbasedQOSMessage,
  0x4c00: BandwidthLimitInMessage,
  0x5000: BandwidthLimitOutMessage,
  0x5400: BroadcastFilteringMessage,
  0x5800: BroadcastBandwidthMessage,
  0x5c00: PortMirrorMessage,
  0x6000: NumberOfPortsMessage,
  0x6400: UnknownMessage6400,
  0x6800: IGMPSnoopingStatusMessage,
  0x6c00: BlockUnknownMulticastsMessage,
  0x7000: IGMPHeaderValidationMessage,
  0x7400: UnknownMessage7400,
  0x7c00: UnknownMessage7c00,
  0x8000: UnknownMessage8000,
  0x8800: UnknownMessage8800,
  0x8c00: UnknownMessage8c00,
  0x9000: LoopDetectionMessage,
  0x9400: UnknownMessage9400,
  0xffff: EndOfMessages
}

def get_message_tag(message_type):
  for t in MESSAGE_DISPATCH_MAPPING:
    if MESSAGE_DISPATCH_MAPPING[t] == message_type:
      return t

class Message(Structure):
  tag     = DispatchField(UBInt16())
  length  = LengthField(UBInt16())
  message = DispatchTarget(length, tag, MESSAGE_DISPATCH_MAPPING)

class Frame(Structure):
  version     = UBInt8()
  operation   = UBInt8()
  result      = UBInt16()
  reserved_0  = Magic('\x00\x00\x00\x00')
  _host_mac   = UBInt8Sequence(6)
  host_mac  = FieldProperty(_host_mac,
                            onget=lambda v: unpack_mac(''.join(map(chr, v))),
                            onset=lambda v: tuple(map(ord, pack_mac(v))))
  _device_mac = UBInt8Sequence(6)
  device_mac  = FieldProperty(_device_mac,
                              onget=lambda v: unpack_mac(''.join(map(chr, v))),
                              onset=lambda v: tuple(map(ord, pack_mac(v))))
  reserved_1  = Magic('\x00\x00')
  sequence    = UBInt16()
  signature   = Magic('NSDP')
  reserved_2  = Magic('\x00\x00\x00\x00')
  messages    = FieldArray(Message)

class ProSafeSwitch:
  def __init__(self, model=None, name=None, mac=None, ip=None, netmask=None, gateway=None, dhcp=False, firmware=None, ports=0, password=''):
    self.model = model
    self.name = name
    self.mac = mac
    self.ip = ip
    self.netmask = netmask
    self.gateway = gateway
    self.dhcp = dhcp
    self.firmware = firmware
    self.ports = ports
    self.password = password
    self.portstats = {}
    self.reset_port_stats()
    self.port_mirroring = {
      'source_ports': [],
      'destination_port': None
    }
    self.link_speed = {}
    self.cable_test_results = {}
    self.loop_detection = False
    self.block_unknown_multicast = False
    self.igmp_snooping_vlanid = 0
    self.igmp_header_validation = False
    self.vlans_802 = {}
    self.vlans_port = {}
    self.pvids = [0] * ports
    self.qos_type = QOS_TYPE_DSCP_BASED
    self.qos_port = [QOS_PORT_LOW] * ports
    self.bandwidth_limit_in = [0] * ports
    self.bandwidth_limit_out = [0] * ports
    self.broadcast_filtering = False
    self.broadcast_bandwidth = [0] * ports

  def reset_port_stats(self):
    for p in range(0, self.ports):
      self.portstats[p] = {
        'bytes_received': 0,
        'bytes_sent': 0,
        'crc_error_packets': 0
      }

  def set_message(self, message):
    tag = get_message_tag(type(message))
    self.messages[tag] = message

  def handle_frame(self, frame):
    # only handle protocol version 1
    if frame.version != 1:
      raise ValueError('protocol mismatch')

    # only handle messages for this switch
    if frame.device_mac != self.mac and frame.device_mac != '00:00:00:00:00:00':
      return

    if frame.operation == OPERATION_READ_REQUEST:
      rsp = Frame()
      rsp.version = 1
      rsp.operation = OPERATION_READ_RESPONSE
      rsp.result = 0
      rsp.host_mac = frame.host_mac
      rsp.device_mac = self.mac
      rsp.sequence = frame.sequence

      for msg in frame.messages:
        unhandled = False
        unknown = True

        if type(msg.message) == DeviceModelMessage:
          msg.message.value = self.model
          rsp.messages.append(msg)
        elif type(msg.message) == DeviceNameMessage:
          msg.message.value = self.name
          rsp.messages.append(msg)
        elif type(msg.message) == MacAddressMessage:
          msg.message.mac = self.mac
          rsp.messages.append(msg)
        elif type(msg.message) == IPAddressMessage:
          msg.message.ip = self.ip
          rsp.messages.append(msg)
        elif type(msg.message) == NetmaskMessage:
          msg.message.netmask = self.netmask
          rsp.messages.append(msg)
        elif type(msg.message) == GatewayMessage:
          msg.message.ip = self.gateway
          rsp.messages.append(msg)
        elif type(msg.message) == DHCPStatusMessage:
          msg.message.enabled = self.dhcp
          rsp.messages.append(msg)
        elif type(msg.message) == FirmwareVersionMessage:
          msg.message.value = self.firmware
          rsp.messages.append(msg)
        elif type(msg.message) == EncryptPasswordMessage:
          msg.message.encrypted = False
          rsp.messages.append(msg)
        elif type(msg.message) == NumberOfPortsMessage:
          msg.message.ports = self.ports
          rsp.messages.append(msg)
        elif type(msg.message) == SpeedLinkStatusMessage:
          for p in range(0, self.ports):
            slsm = SpeedLinkStatusMessage()
            slsm.port_speed = (p, self.link_speed[p] if self.link_speed.has_key(p) else LINK_SPEED_0)
            rsp.messages.append(slsm.get_message())
        elif type(msg.message) == PortTrafficStatisticsMessage:
          for p in range(0, self.ports):
            ptsm = PortTrafficStatisticsMessage()
            ptsm.get_message() # call to populate parent
            ptsm.empty = False
            ptsm.data.port = p + 1
            ptsm.data.bytes_sent = self.portstats[p]['bytes_sent']
            ptsm.data.bytes_received = self.portstats[p]['bytes_received']
            ptsm.data.crc_error_packets = self.portstats[p]['crc_error_packets']
            rsp.messages.append(ptsm.get_message())
        elif type(msg.message) == PortMirrorMessage:
          pmm = PortMirrorMessage()
          pmm.config = (self.port_mirroring['destination_port'], self.port_mirroring['source_ports'])
          rsp.messages.append(pmm.get_message())
        elif type(msg.message) == TestCableResultMessage:
          port, result, meters = msg.message.port_result_meters
          result, meters = self.cable_test_results[port] if self.cable_test_results.has_key(port) else (CABLE_TEST_NO_CABLE, 1)
          msg.message.port_result_meters = (port, result, meters)
          rsp.messages.append(msg)
        elif type(msg.message) == LoopDetectionMessage:
          msg.message.enabled = self.loop_detection
          rsp.messages.append(msg)
        elif type(msg.message) == BlockUnknownMulticastsMessage:
          msg.message.enabled = self.block_unknown_multicast
          rsp.messages.append(msg)
        elif type(msg.message) == VLANEngineMessage:
          msg.message.type = self.vlan_engine_type
          rsp.messages.append(msg)
        elif type(msg.message) == IGMPSnoopingStatusMessage:
          msg.message.vlanid = self.igmp_snooping_vlanid
          rsp.messages.append(msg)
        elif type(msg.message) == IGMPHeaderValidationMessage:
          msg.message.enabled = self.igmp_header_validation
          rsp.messages.append(msg)
        elif type(msg.message) == VLANIDMessage:
          if msg.message.config == None:
            for vlanid in self.vlans_port:
              ports = self.vlans_port[vlanid]
              vlanmsg = VLANIDMessage()
              vlanmsg.config = (vlanid, ports)
              rsp.messages.append(vlanmsg.get_message())
        elif type(msg.message) == VLANID802Message:
          if msg.message.config == None:
            for vlanid in self.vlans_802:
              tag_ports, untag_ports = self.vlans_802[vlanid]
              vlanmsg = VLANID802Message()
              vlanmsg.config = (vlanid, tag_ports, untag_ports)
              rsp.messages.append(vlanmsg.get_message())
          else:
            vlanid = msg.message.config[0]
            vlanmsg = VLANID802Message()
            if self.vlans_802.has_key(vlanid):
              tag_ports, untag_ports = self.vlans_802[vlanid]
              vlanmsg.config = (vlanid, tag_ports, untag_ports)
            else:
              # raise error? vlan config unkbown
              vlanmsg.value = '\x00\x00\x00\x00' # what should be returned? gs108ev2 seems to return conf for vlanid=1 when requesting non existing
            rsp.messages.append(vlanmsg.get_message())
        elif type(msg.message) == VLANPVIDMessage:
          for p in range(0, self.ports):
            pvidmsg = VLANPVIDMessage()
            pvidmsg.config = (p + 1, self.pvids[p])
            rsp.messages.append(pvidmsg.get_message())
        elif type(msg.message) == QOSMessage:
          msg.message.type = self.qos_type
          rsp.messages.append(msg)
        elif type(msg.message) == PortbasedQOSMessage:
          if msg.message.config == None:
            for p in range(0, self.ports):
              pqm = PortbasedQOSMessage()
              pqm.config = (p + 1, self.qos_port[p])
              rsp.messages.append(pqm.get_message())
          else:
            pass # TODO handle single ports?
        elif type(msg.message) == BandwidthLimitOutMessage:
          if msg.message.config == None:
            for p in range(0, self.ports):
              bwm = BandwidthLimitOutMessage()
              bwm.config = (p + 1, self.bandwidth_limit_out[p])
              rsp.messages.append(bwm.get_message())
          else:
            pass # TODO handle single ports?
        elif type(msg.message) == BandwidthLimitInMessage:
          if msg.message.config == None:
            for p in range(0, self.ports):
              bwm = BandwidthLimitInMessage()
              bwm.config = (p + 1, self.bandwidth_limit_in[p])
              rsp.messages.append(bwm.get_message())
          else:
            pass # TODO handle single ports?
        elif type(msg.message) == BroadcastFilteringMessage:
          msg.message.enabled = self.broadcast_filtering
          rsp.messages.append(msg)
        elif type(msg.message) == BroadcastBandwidthMessage:
          if msg.message.config == None:
            for p in range(0, self.ports):
              bwm = BroadcastBandwidthMessage()
              bwm.config = (p + 1, self.broadcast_bandwidth[p])
              rsp.messages.append(bwm.get_message())
          else:
            pass # TODO handle single ports?
        elif type(msg.message) == EndOfMessages:
          break
        else:
          unhandled = True

        if type(msg.message) == UnknownMessage0002: # TODO: Product Type?
          msg.message.value = '\x00\x00'
          rsp.messages.append(msg)
        elif type(msg.message) == UnknownMessage0005: # TODO: Location?
          msg.message.value = ''
          rsp.messages.append(msg)
        elif type(msg.message) == UnknownMessage000c: # TODO: Number of image?
          msg.message.value = '\x01'
          rsp.messages.append(msg)
        elif type(msg.message) == UnknownMessage000e: # TODO: Image2 firmware version
          msg.message.value = ''
          rsp.messages.append(msg)
        elif type(msg.message) == UnknownMessage000f: # TODO: Active image?
          msg.message.value = '\x01'
          rsp.messages.append(msg)
        elif type(msg.message) == UnknownMessage7c00:
          msg.message.value = '\x02'
          rsp.messages.append(msg)
        elif type(msg.message) == UnknownMessage7400:
          msg.message.value = '\x00\x00\x00\x08\x7f\xfc\xff\xff'
          rsp.messages.append(msg)
        elif type(msg.message) == UnknownMessage0017: # TODO: related to new password?
          rsp.result = 0x0300
        elif type(msg.message) == UnknownMessage6400: # TODO: maybe related to 802.1Q vlan (max vlan group?)
          msg.message.value = '\x00\x20'
          rsp.messages.append(msg)
        elif type(msg.message) == UnknownMessage8c00: # TODO: this appeared after setting 0x08 to 0x12 in Unknown7400 "Not Support TLV (Get Port Admin Status)"
          msg.message.value = ''
          rsp.messages.append(msg)
        elif type(msg.message) == UnknownMessage8800: # TODO:
          msg.message.value = ''
          rsp.messages.append(msg)
        elif type(msg.message) == UnknownMessage9400: # TODO: this appeared after setting 0x08 to 0x10 in Unknown7400 "Not Support TLV (Get Port Admin Status)". 9400 is mentioned in http://seclists.org/fulldisclosure/2016/Jan/77
          msg.message.value = ''
          rsp.messages.append(msg)
        else:
          unknown = False

        if unknown:
          print '*' * 40
          print repr(msg)
          print '*' * 40

        if not unknown and unhandled:
          print 'UNHANDLED READ:'
          print repr(msg)

      eom = EndOfMessages()
      rsp.messages.append(eom.get_message())
      return rsp

    elif frame.operation == OPERATION_WRITE_REQUEST:
      rsp = Frame()
      rsp.version = 1
      rsp.operation = OPERATION_WRITE_RESPONSE
      rsp.result = 0
      rsp.host_mac = frame.host_mac
      rsp.device_mac = self.mac
      rsp.sequence = frame.sequence
      # TODO: Check whether the password change exploit is also simulated
      for msg in frame.messages:
        if type(msg.message) == PasswordMessage:
          if msg.message.value != self.password:
            rsp.result = 0x0700
            rsp.messages.append(msg)
            break
        elif type(msg.message) == NewPasswordMessage:
          self.password = msg.message.value
        elif type(msg.message) == IPAddressMessage:
          self.ip = msg.message.ip
        elif type(msg.message) == NetmaskMessage:
          self.netmask = msg.message.netmask
        elif type(msg.message) == GatewayMessage:
          self.gateway = msg.message.ip
        elif type(msg.message) == DHCPStatusMessage:
          self.dhcp = msg.message.enabled
        elif type(msg.message) == ResetPortTrafficStatisticMessage:
          self.reset_port_stats()
        elif type(msg.message) == PortMirrorMessage:
          self.port_mirroring['destination_port'], self.port_mirroring['source_ports'] = msg.message.config
        elif type(msg.message) == TestCableMessage:
          print 'Testing cable on port %d' % ord(msg.message.value[0]) # TODO
        elif type(msg.message) == LoopDetectionMessage:
          self.loop_detection = msg.message.enabled
        elif type(msg.message) == BlockUnknownMulticastsMessage:
          self.block_unknown_multicast = msg.message.enabled
        elif type(msg.message) == IGMPSnoopingStatusMessage:
          self.igmp_snooping_vlanid = msg.message.vlanid
        elif type(msg.message) == IGMPHeaderValidationMessage:
          self.igmp_header_validation = msg.message.enabled
        elif type(msg.message) == VLANEngineMessage:
          self.vlan_engine_type = msg.message.type
          if msg.message.type == VLAN_ENGINE_TYPE_PORT_BASIC or msg.message.type == VLAN_ENGINE_TYPE_PORT_ADVANCED:
            self.vlans_port = {1: [1, 2, 3, 4, 5, 6, 7, 8]}
          elif msg.message.type == VLAN_ENGINE_TYPE_802_BASIC or msg.message.type == VLAN_ENGINE_TYPE_802_ADVANCED:
            pass
        elif type(msg.message) == VLANIDMessage:
          vlanid, ports = msg.message.config
          self.vlans_port[vlanid] = ports
        elif type(msg.message) == VLANID802Message:
          vlanid, tag_ports, untag_ports = msg.message.config
          self.vlans_802[vlanid] = (tag_ports, untag_ports)
        elif type(msg.message) == VLANID802DeleteMessage:
          vlanid = msg.message.vlanid
          if vlanid != None:
            if self.vlans_802.has_key(vlanid):
              del self.vlans_802[vlanid]
        elif type(msg.message) == VLANPVIDMessage:
          port, pvid = msg.message.config
          self.pvids[port - 1] = pvid
        elif type(msg.message) == QOSMessage:
          self.qos_type = msg.message.type
        elif type(msg.message) == PortbasedQOSMessage:
          port, value = msg.message.config
          self.qos_port[port - 1] = value
        elif type(msg.message) == BandwidthLimitInMessage:
          port, limit = msg.message.config
          self.bandwidth_limit_in[port - 1] = limit
        elif type(msg.message) == BandwidthLimitOutMessage:
          port, limit = msg.message.config
          self.bandwidth_limit_out[port - 1] = limit
        elif type(msg.message) == BroadcastFilteringMessage:
          self.broadcast_filtering = msg.message.enabled
        elif type(msg.message) == BroadcastBandwidthMessage:
          port, limit = msg.message.config
          self.broadcast_bandwidth[port - 1] = limit
        elif type(msg.message) == BroadcastBandwidthMessage:
          port, limit = msg.message.config
          self.broadcast_bandwidth[port - 1] = limit
        elif type(msg.message) == EndOfMessages:
          break
        else:
          print 'UNHANDLED WRITE:'
          print repr(msg)

      eom = EndOfMessages()
      rsp.messages.append(eom.get_message())
      return rsp
