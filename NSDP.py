import struct, binascii
import Protocol

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
