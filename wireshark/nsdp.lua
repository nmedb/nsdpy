proto_nsdp = Proto ('nsdp', 'Netgear Switch Discovery Protocol')

local OP = {
  READ_REQUEST = 0x01,
  READ_RESPONSE = 0x02,
  WRITE_REQUEST = 0x03,
  WRITE_RESPONSE = 0x04
}

local LINK_SPEED = {
  NONE = 0x00,
  HALF_10M = 0x01,
  FULL_10M = 0x02,
  HALF_100M = 0x03,
  FULL_100M = 0x04,
  FULL_1000M = 0x05,
  FULL_10G = 0x06,
}

local PORT_SPEED = {
  DISABLED = 0x00,
  AUTO = 0x01,
  HALF_10M = 0x02,
  FULL_10M = 0x03,
  HALF_100M = 0x04,
  FULL_100M = 0x05,
}

local PORT_LIMIT = {
  UNLIMITED = 0,
  KB_512 = 1,
  KB_1024 = 2,
  KB_2048 = 3,
  KB_2096 = 4,
  KB_8192 = 5,
  KB_16384 = 6,
  KB_32768 = 7,
  KB_65536 = 8,
  KB_131072 = 9,
  KB_262144 = 10,
  KB_524288 = 11,
}

local CABLE_STATUS = {
  OK = 0,
  NONE = 1,
  OPEN = 2,
  SHORT_CIRCUIT = 3,
  FIBER = 4,
  SHORTED = 5,
  UNKNOWN = 6,
  CROSSTALK = 7,
}

local VLAN_ENGINE = {
  NONE = 0x00,
  BASIC_PORT = 0x01,
  ADVANCED_PORT = 0x02,
  BASIC_802_1Q = 0x03,
  ADVANCED_802_1Q = 0x04,
}

local QOS_PRIORITY = {
  HIGH = 1,
  MEDIUM = 2,
  NORMAL = 3,
  LOW = 4,
}

local QOS_TYPE = {
  PORT = 1,
  DSCP = 2,
}

local TLV = {
  NONE = 0x0000,
  MODEL = 0x0001,
  PRODUCT_TYPE = 0x0002,
  SYSTEM_NAME = 0x0003,
  MAC_ADDRESS = 0x0004,
  LOCATION = 0x0005,
  IP = 0x0006,
  NETMASK = 0x0007,
  GATEWAY = 0x0008,
  SET_PASSWORD = 0x0009,
  PASSWORD_AUTH = 0x000a,
  DHCP = 0x000b,
  FIRMWARE_IMAGES = 0x000c,
  FIRMWARE_1_VERSION = 0x000d,
  FIRMWARE_2_VERSION = 0x000e,
  ACTIVE_FIRMWARE_IMAGE = 0x000f,
  FIRMWARE_UPGRADE = 0x0010,
  REBOOT = 0x0013,
  PASSWORD_ENCRYPTION = 0x0014, -- @todo PASSWORD_METHOD? AUTH_METHOD?
  PASSWORD_SALT = 0x0017, -- @todo some kind of salt for v2 passwords?
  PASSWORD_AUTH_V2 = 0x001a, -- @todo enhanced password auth?
  FACTORY_RESET = 0x0400,
  LINK_SPEED = 0x0c00,
  TRAFFIC_STATISTICS = 0x1000,
  RESET_TRAFFIC_STATISTICS = 0x1400,
  CABLE_TEST = 0x1800,
  CABLE_TEST_RESULT = 0x1c00,
  VLAN = 0x2000,
  VLAN_CONFIG_ID = 0x2400,
  VLAN_CONFIG_802_Q = 0x2800,
  DELETE_VLAN = 0x2c00,
  PVID = 0x3000,
  QOS = 0x3400,
  PORT_QOS = 0x3800,
  INGRESS = 0x4c00,
  EGRESS = 0x5000,
  BROADCAST_FILTERING = 0x5400,
  BROADCAST_BANDWIDTH = 0x5800,
  MIRRORING = 0x5c00,
  NUMBER_OF_PORTS = 0x6000,
  IGMP_SNOOPING = 0x6800,
  BLOCK_UNKNOWN_MULTICASTS = 0x6c00,
  IGMP_HEADER_VALIDATION = 0x7000,
  TLV_BITMAP = 0x7400,
  SERIAL_NUMBER = 0x7800,
  LOOP_DETECTION = 0x9000,
  PORT_SPEED = 0x9400,
  POWER_SAVING = 0xa800,

  UNKNOWN_6400 = 0x6400,
  UNKNOWN_7c00 = 0x7c00, -- @todo is queried at login? some 1 byte setting?
  UNKNOWN_8000 = 0x8000,
  UNKNOWN_8800 = 0x8800,
  UNKNOWN_8c00 = 0x8c00,

  END_OF_MESSAGES = 0xffff,
}

local CAPABILITIES = {
  [4] = 'Multicast 0?',
  [5] = 'Multicast 1?',
  [6] = 'Multicast 2?',
  [7] = 'VLAN 0?',
  [9] = 'Port mirroring',
  [10] = 'Broadcast filtering 0?',
  [11] = 'Broadcast filtering 1?',
  [12] = 'Rate limit 0?',
  [13] = 'Rate limit 1?',
  [17] = 'QOS 0?',
  [18] = 'QOS 1?',
  [19] = 'QOS 2?',
  [20] = 'VLAN 1?',
  [21] = 'VLAN 2?',
  [22] = 'VLAN 3?',
  [23] = 'VLAN port',
  [26] = 'Cable test',
  [27] = 'Port statistics',
  [31] = 'Factory reset',
}

local vs_tlvs = {
  [TLV.NONE] = 'None',
  [TLV.MODEL] = 'Model',
  [TLV.PRODUCT_TYPE] = 'Product type',
  [TLV.SYSTEM_NAME] = 'Name',
  [TLV.MAC_ADDRESS] = 'MAC',
  [TLV.LOCATION] = 'Location',
  [TLV.IP] = 'IP address',
  [TLV.NETMASK] = 'Netmask',
  [TLV.GATEWAY] = 'Gateway',
  [TLV.SET_PASSWORD] = 'Set password',
  [TLV.PASSWORD_AUTH] = 'Password auth',
  [TLV.DHCP] = 'DHCP',
  [TLV.FIRMWARE_IMAGES] = 'Firmware images',
  [TLV.FIRMWARE_1_VERSION] = 'Firmware 1 version',
  [TLV.FIRMWARE_2_VERSION] = 'Firmware 2 version',
  [TLV.ACTIVE_FIRMWARE_IMAGE] = 'Active firmware image',
  [TLV.FIRMWARE_UPGRADE] = 'Firmware upgrade',
  [TLV.REBOOT] = 'Reboot',
  [TLV.PASSWORD_ENCRYPTION] = 'Password encryption',
  [TLV.PASSWORD_SALT] = 'Password salt',
  [TLV.PASSWORD_AUTH_V2] = 'Password auth (V2)',
  [TLV.FACTORY_RESET] = 'Factory reset',
  [TLV.LINK_SPEED] = 'Speed/link status',
  [TLV.TRAFFIC_STATISTICS] = 'Port traffic statistic',
  [TLV.RESET_TRAFFIC_STATISTICS] = 'Reset port traffic statistic',
  [TLV.CABLE_TEST] = 'Test cable',
  [TLV.CABLE_TEST_RESULT] = 'Cable test result',
  [TLV.VLAN] = 'VLAN engine',
  [TLV.VLAN_CONFIG_ID] = 'VLAN config',
  [TLV.VLAN_CONFIG_802_Q] = 'VLAN config (802.1q)',
  [TLV.DELETE_VLAN] = 'Delete VLAN',
  [TLV.PVID] = 'PVID',
  [TLV.QOS] = 'QOS',
  [TLV.PORT_QOS] = 'Portbased QOS',
  [TLV.INGRESS] = 'Ingress rate',
  [TLV.EGRESS] = 'Egress rate',
  [TLV.BROADCAST_FILTERING] = 'Broadcast filtering',
  [TLV.BROADCAST_BANDWIDTH] = 'Broadcast bandwidth',
  [TLV.MIRRORING] = 'Port mirroring',
  [TLV.NUMBER_OF_PORTS] = 'Number of ports',
  [TLV.IGMP_SNOOPING] = 'IGMP snooping status',
  [TLV.BLOCK_UNKNOWN_MULTICASTS] = 'Block unknown multicasts',
  [TLV.IGMP_HEADER_VALIDATION] = 'IGMP header validation',
  [TLV.TLV_BITMAP] = 'Capabilities (TLV bitmap)',
  [TLV.SERIAL_NUMBER] = 'Serial number',
  [TLV.LOOP_DETECTION] = 'Loop detection',
  [TLV.PORT_SPEED] = 'Port speed',
  [TLV.POWER_SAVING] = 'Power saving',
  [TLV.END_OF_MESSAGES] = 'End of messages'
}

local vs_on_off = {
  [0] = 'Off',
  [1] = 'On',
}

proto_nsdp.fields.version = ProtoField.uint8('nsdp.version', 'Version')
proto_nsdp.fields.operation = ProtoField.uint8('nsdp.operation', 'Type', base.HEX, {
  [OP.READ_REQUEST] = 'Read Request',
  [OP.READ_RESPONSE] = 'Read Response',
  [OP.WRITE_REQUEST] = 'Write Request',
  [OP.WRITE_RESPONSE] = 'Write Response'
})
proto_nsdp.fields.result = ProtoField.uint16('nsdp.result', 'Result', base.HEX, {
  [0x0000] = 'Success',
  [0x0001] = 'Protocol version mismatch',
  [0x0002] = 'Command not supported',
  [0x0003] = 'TLV not supported',
  [0x0004] = 'TLV length error',
  [0x0005] = 'TLV value error',
  [0x0006] = 'IP not allowed',
  [0x0007] = 'Incorrect password',
  [0x0008] = 'Boot code firmware download',
  [0x0009] = 'Incorrect username',
  [0x000a] = 'Incorrect password', -- @todo is this really: configure_via_web ?
  [0x000c] = 'TFTP call error',
  [0x000d] = 'Incorrect password2',
  [0x000e] = 'Auth failed lock',
  [0x000f] = 'Management disabled',
  [0x0081] = 'TFTP call error2',
  [0x0082] = 'TFTP out of memory',
  [0x0083] = 'Firmware upgrade failed',
  [0x0084] = 'TFTP timeout',
  [0x00f0] = 'Command scheduled',
  [0x00f1] = 'Command in progress',
  [0x00f2] = 'TFTP in progress',
  [0x00f8] = 'Internal error',
  [0x00ff] = 'Timeout'
})
proto_nsdp.fields.result_tlv = ProtoField.uint16('nsdp.result.tlv', 'TLV', base.HEX, vs_tlvs)
proto_nsdp.fields.host_mac = ProtoField.ether('nsdp.host_mac', 'Host', base.HEX)
proto_nsdp.fields.device_mac = ProtoField.ether('nsdp.device_mac', 'Device', base.HEX)
proto_nsdp.fields.sequence = ProtoField.uint16('nsdp.sequence', 'Sequence', base.HEX)

proto_nsdp.fields.port_number = ProtoField.uint8('nsdp.port.number', 'Port')
proto_nsdp.fields.link_speed = ProtoField.uint8('nsdp.port.link.speed', 'Link speed', base.HEX, {
  [LINK_SPEED.NONE] = 'None',
  [LINK_SPEED.HALF_10M] = '10 Mbps (half)',
  [LINK_SPEED.FULL_10M] = '10 Mbps (full)',
  [LINK_SPEED.HALF_100M] = '100 Mbps (half)',
  [LINK_SPEED.FULL_100M] = '100 Mbps (full)',
  [LINK_SPEED.FULL_1000M] = '1 Gbps',
  [LINK_SPEED.FULL_10G] = '10 Gbps',
})
proto_nsdp.fields.port_speed = ProtoField.uint8('nsdp.port.speed', 'Port speed', base.HEX, {
  [PORT_SPEED.DISABLED] = 'Disabled',
  [PORT_SPEED.AUTO] = 'Auto',
  [PORT_SPEED.HALF_10M] = '10 Mbps (half)',
  [PORT_SPEED.FULL_10M] = '10 Mbps (full)',
  [PORT_SPEED.HALF_100M] = '100 Mbps (half)',
  [PORT_SPEED.FULL_100M] = '100 Mbps (full)',
})
proto_nsdp.fields.port_flow_control = ProtoField.uint8('nsdp.port.flow_control', 'Flow control', base.HEX, vs_on_off)
proto_nsdp.fields.port_limit = ProtoField.uint8('nsdp.port.limit', 'Limit', base.HEX, {
  [PORT_LIMIT.UNLIMITED] = 'Unlimited',
  [PORT_LIMIT.KB_512] = '512 Kbps',
  [PORT_LIMIT.KB_1024] = '1 Mbps',
  [PORT_LIMIT.KB_2048] = '2 Mbps',
  [PORT_LIMIT.KB_2096] = '4 Mbps',
  [PORT_LIMIT.KB_8192] = '8 Mbps',
  [PORT_LIMIT.KB_16384] = '16 Mbps',
  [PORT_LIMIT.KB_32768] = '32 Mbps',
  [PORT_LIMIT.KB_65536] = '64 Mbps',
  [PORT_LIMIT.KB_131072] = '128 Mbps',
  [PORT_LIMIT.KB_262144] = '256 Mbps',
  [PORT_LIMIT.KB_524288] = '512 Mbps',
})

proto_nsdp.fields.messages = ProtoField.new('Messages', 'nsdp.messages', ftypes.BYTES)
proto_nsdp.fields.tlv = ProtoField.uint16('nsdp.message.tlv', 'TLV', base.HEX, vs_tlvs)
proto_nsdp.fields.length = ProtoField.uint16('nsdp.message.length', 'Length', base.HEX)
proto_nsdp.fields.data = ProtoField.new('Data', 'nsdp.message.data', ftypes.BYTES)

proto_nsdp.fields.bytes_recived = ProtoField.uint64('nsdp.bytes_received', 'Bytes received')
proto_nsdp.fields.bytes_send = ProtoField.uint64('nsdp.bytes_send', 'Bytes send')
proto_nsdp.fields.total_packets = ProtoField.uint64('nsdp.packets.total', 'Total packets')
proto_nsdp.fields.broadcast_packets = ProtoField.uint64('nsdp.packets.broadcast', 'Broadcast packets')
proto_nsdp.fields.multicast_packets = ProtoField.uint64('nsdp.packets.multicast', 'Multicast packets')
proto_nsdp.fields.crc_errors = ProtoField.uint64('nsdp.crc_errors', 'CRC errors')

proto_nsdp.fields.cable_status = ProtoField.uint32('nsdp.cable.status', 'Cable status', base.HEX, {
  [CABLE_STATUS.OK] = 'Ok',
  [CABLE_STATUS.NONE] = 'No cable',
  [CABLE_STATUS.OPEN] = 'Open cable',
  [CABLE_STATUS.SHORT_CIRCUIT] = 'Short circuit',
  [CABLE_STATUS.FIBER] = 'Fiber cable',
  [CABLE_STATUS.SHORTED] = 'Shorted cable',
  [CABLE_STATUS.UNKNOWN] = 'Unknown',
  [CABLE_STATUS.CROSSTALK] = 'Crosstalk',
})
proto_nsdp.fields.cable_meters = ProtoField.uint32('nsdp.cable.meters', 'Meters', base.DEC)

proto_nsdp.fields.vlan_id = ProtoField.uint16('nsdp.vlan.id', 'VLAN ID')

proto_nsdp.fields.qos_priotity = ProtoField.uint8('nsdp.qos.priority', 'Priority', base.DEC, {
  [QOS_PRIORITY.HIGH] = 'High',
  [QOS_PRIORITY.MEDIUM] = 'Medium',
  [QOS_PRIORITY.NORMAL] = 'Normal',
  [QOS_PRIORITY.LOW] = 'Low',
})

proto_nsdp.fields.serial = ProtoField.new('Serial', 'nsdp.serial', ftypes.STRINGZ)

proto_nsdp.fields.unknown = ProtoField.new('Unknown', 'nsdp.unknown', ftypes.BYTES)

-- helper function for port_limit tlv's
function port_limit (tree, tvb, i, l)
  local subtree, i, l = ts(tree, tvb, i, l)
  if l == 0 then
    append_query(subtree)
  elseif l == 5 then
    subtree:add(proto_nsdp.fields.port_number, tvb(i + 0, 1))
    subtree:add(proto_nsdp.fields.port_limit, tvb(i + 1, 4))
  else
    ae(subtree, 'Invalid length')
  end
  return subtree
end

-- helper function for generating tlv subtree
function ts (tree, tvb, i, l)
  if not tree then return end
  local tlv = tvb(i, 2):uint()
  local tlv_length = tvb(i + 2, 2):uint()
  local name = vs_tlvs[tlv]
  return tree:add(tvb(i, l), name), i + 4, tlv_length
end

-- @todo name means primitive field?
-- function for generating simple ProtoField with optional data
function pf (fieldtype, abbr, name, base, valuestring)
  local field = fieldtype(abbr, name, base, valuestring)
  return function (tree, tvb, i, l)
    if not tree then
      return field
    end
    if l - 4 > 0 then
      return tree:add(field, tvb(i + 4, l - 4))
    else
      return append_query(tree:add(tvb(i, l), name))
    end
  end
end

-- helper function for parse errors
function parse_error (tree, tvb, i, l, error_message)
  local tlv = tvb(i, 2):uint()
  local msg = tree:add(tvb(i, l), string.format('%s (Error = %s)', vs_tlvs[tlv], error_message))
  msg:add(proto_nsdp.fields.tlv, tvb(i, 2))
  msg:add(proto_nsdp.fields.length, tvb(i + 2, 2))
  if l - 4 > 0 then
    msg:add(proto_nsdp.fields.data, tvb(i + 4, l - 4))
  end
  return msg
end

-- helper function for port list bitmaps
function ports_bitmap (name, tree, tvb, i, l)
  local ports_buffer = tvb(i, l)
  local bitmap = ports_buffer:uint()
  local fs = string.format('%%s (%s):', string.format('0x%%0%dx', l * 2))
  local ports = tree:add(ports_buffer, string.format(fs, name, bitmap))
  if bitmap ~= 0 then
    local number_of_ports = l * 8
    for i = 1, number_of_ports do
      local mask = bit32.lshift(1, (number_of_ports - i))
      if bit32.band(mask, bitmap) ~= 0 then
	ports:append_text(' ' .. i)
      end
    end
  end
  return ports
end

-- helper function for appending error message to messages
function ae (tree, message)
  if tree then
    tree:append_text(string.format(' (Error = %s)', message))
  end
  return tree
end

-- helper function
function append_query (tree)
  if tree then
    tree:append_text(' ?')
  end
  return tree
end

local tlvs = {
  [TLV.MODEL] = pf(ProtoField.string, 'nsdp.model', vs_tlvs[TLV.MODEL], FT_STRING),
  [TLV.PRODUCT_TYPE] = pf(ProtoField.uint16, 'nsdp.product_type', vs_tlvs[TLV.PRODUCT_TYPE]),
  [TLV.SYSTEM_NAME] = pf(ProtoField.string, 'nsdp.name', vs_tlvs[TLV.SYSTEM_NAME], FT_STRING),
  [TLV.MAC_ADDRESS] = pf(ProtoField.ether, 'nsdp.mac', vs_tlvs[TLV.MAC_ADDRESS], base.HEX),
  [TLV.LOCATION] = pf(ProtoField.string, 'nsdp.location', vs_tlvs[TLV.LOCATION], FT_STRING),
  [TLV.IP] = pf(ProtoField.ipv4, 'nsdp.ip', vs_tlvs[TLV.IP]),
  [TLV.NETMASK] = pf(ProtoField.ipv4, 'nsdp.netmask', vs_tlvs[TLV.NETMASK]),
  [TLV.GATEWAY] = pf(ProtoField.ipv4, 'nsdp.gateway', vs_tlvs[TLV.GATEWAY]),
  [TLV.SET_PASSWORD] = pf(ProtoField.bytes, 'nsdp.set_password', vs_tlvs[TLV.SET_PASSWORD]),
  [TLV.PASSWORD_AUTH] = pf(ProtoField.bytes, 'nsdp.password', vs_tlvs[TLV.PASSWORD_AUTH]),
  [TLV.DHCP] = pf(ProtoField.uint8, 'nsdp.dhcp', vs_tlvs[TLV.DHCP], base.HEX, vs_on_off),
  [TLV.FIRMWARE_IMAGES] = pf(ProtoField.uint8, 'nsdp.firmware.images', vs_tlvs[TLV.FIRMWARE_IMAGES]),
  [TLV.FIRMWARE_1_VERSION] = pf(ProtoField.string, 'nsdp.firmware.version1', vs_tlvs[TLV.FIRMWARE_1_VERSION], FT_STRING),
  [TLV.FIRMWARE_2_VERSION] = pf(ProtoField.string, 'nsdp.firmware.version2', vs_tlvs[TLV.FIRMWARE_2_VERSION], FT_STRING),
  [TLV.ACTIVE_FIRMWARE_IMAGE] = pf(ProtoField.uint8, 'nsdp.firmware.active_image', vs_tlvs[TLV.ACTIVE_FIRMWARE_IMAGE]),
  [TLV.FIRMWARE_UPGRADE] = pf(ProtoField.uint8, 'nsdp.firmware.upgrade', vs_tlvs[TLV.FIRMWARE_UPGRADE]),
  [TLV.REBOOT] = pf(ProtoField.uint8, 'nsdp.reboot', vs_tlvs[TLV.REBOOT]),

  [TLV.PASSWORD_ENCRYPTION] = pf(ProtoField.uint32, 'nsdp.password_encryption', vs_tlvs[TLV.PASSWORD_ENCRYPTION], base.HEX, {
    [0x01] = 'Xor',
    [0x10] = 'Enhanced v1?',
    [0x11] = 'Enhanced v2?',
  }),

  [TLV.PASSWORD_SALT] = pf(ProtoField.bytes, 'nsdp.password.salt', vs_tlvs[TLV.PASSWORD_SALT]),

  [TLV.PASSWORD_AUTH_V2] = pf(ProtoField.bytes, 'nsdp.password_v2', vs_tlvs[TLV.PASSWORD_AUTH_V2]),

  [TLV.FACTORY_RESET] = pf(ProtoField.uint8, 'nsdp.factory_reset', vs_tlvs[TLV.FACTORY_RESET]),

  [TLV.LINK_SPEED] = function (tree, tvb, i, l)
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 0 then
      append_query(subtree)
    elseif l == 3 then
      subtree:add(proto_nsdp.fields.port_number, tvb(i + 0, 1))
      subtree:add(proto_nsdp.fields.link_speed, tvb(i + 1, 1))
      subtree:add(proto_nsdp.fields.port_flow_control, tvb(i + 2, 1))
    else
      ae(subtree, 'Invalid length')
    end
    return subtree
  end,

  [TLV.TRAFFIC_STATISTICS] = function (tree, tvb, i, l)
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 0 then
      append_query(subtree)
    elseif l == 49 then
      subtree:add(proto_nsdp.fields.port_number, tvb(i + 0, 1))
      subtree:add(proto_nsdp.fields.bytes_recived, tvb(i + 1, 8))
      subtree:add(proto_nsdp.fields.bytes_send, tvb(i + 9, 8))
      subtree:add(proto_nsdp.fields.total_packets, tvb(i + 17, 8))
      subtree:add(proto_nsdp.fields.broadcast_packets, tvb(i + 25, 8))
      subtree:add(proto_nsdp.fields.multicast_packets, tvb(i + 33, 8))
      subtree:add(proto_nsdp.fields.crc_errors, tvb(i + 41, 8))
    else
      ae(subtree, 'Invalid length')
    end
    return subtree
  end,

  [TLV.RESET_TRAFFIC_STATISTICS] = pf(ProtoField.uint8, 'nsdp.reset_traffic_statistics', vs_tlvs[TLV.RESET_TRAFFIC_STATISTICS]),
  [TLV.CABLE_TEST] = pf(ProtoField.uint8, 'nsdp.test_cable', vs_tlvs[TLV.CABLE_TEST]),

  [TLV.CABLE_TEST_RESULT] = function (tree, tvb, i, l)
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 0 then
      append_query(subtree)
    elseif l == 1 or l == 9 then
      subtree:add(proto_nsdp.fields.port_number, tvb(i + 0, 1))
      if l == 9 then
	subtree:add(proto_nsdp.fields.cable_status, tvb(i + 1, 4))
	subtree:add(proto_nsdp.fields.cable_meters, tvb(i + 5, 4))
      else
	append_query(subtree)
      end
    else
      ae(subtree, 'Invalid length')
    end
    return subtree
  end,

  [TLV.VLAN] = pf(ProtoField.uint8, 'nsdp.vlan.engine', vs_tlvs[TLV.VLAN], base.HEX, {
    [VLAN_ENGINE.NONE] = 'None',
    [VLAN_ENGINE.BASIC_PORT] = 'Basic port',
    [VLAN_ENGINE.ADVANCED_PORT] = 'Advanced port',
    [VLAN_ENGINE.BASIC_802_1Q] = 'Basic 802.1q',
    [VLAN_ENGINE.ADVANCED_802_1Q] = 'Advanced 802.1q',
  }),

  [TLV.VLAN_CONFIG_ID] = function (tree, tvb, i, l)
    if not tree then return end
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 0 then
      append_query(subtree)
    elseif l and l > 0 then
      subtree:add(proto_nsdp.fields.vlan_id, tvb(i + 0, 2))
      if l > 2 then
	ports_bitmap('Ports', subtree, tvb, i + 2, l - 2)
      end
    end
    return subtree
  end,

  [TLV.VLAN_CONFIG_802_Q] = function (tree, tvb, i, l)
    if not tree then return end
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 0 then
      append_query(subtree)
    elseif l then
      subtree:add(proto_nsdp.fields.vlan_id, tvb(i + 0, 2))
      if l > 2 then
	local bitmap_length = (l - 2) / 2
	ports_bitmap('Tagged ports', subtree, tvb, i + 2, bitmap_length)
	ports_bitmap('Member ports', subtree, tvb, i + 2 + bitmap_length, bitmap_length)
      end
    end
    return subtree
  end,

  [TLV.DELETE_VLAN] = function (tree, tvb, i, l)
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 2 then
      subtree:add(proto_nsdp.fields.vlan_id, tvb(i, 2))
    else
       ae(subtree, 'Missing VLAN ID')
    end
    return subtree
  end,

  [TLV.PVID] = function (tree, tvb, i, l)
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 0 then
      append_query(subtree)
    elseif l == 3 then
      subtree:add(proto_nsdp.fields.port_number, tvb(i + 0, 1))
      subtree:add(proto_nsdp.fields.vlan_id, tvb(i + 1, 2))
    else
      ae(subtree, 'Invalid length')
    end
    return subtree
  end,

  [TLV.QOS] = pf(ProtoField.uint8, 'nsdp.qos', vs_tlvs[TLV.QOS], base.HEX, {
    [QOS_TYPE.PORT] = 'Port based',
    [QOS_TYPE.DSCP] = 'DSCP',
  }),

  [TLV.PORT_QOS] = function (tree, tvb, i, l)
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 0 then
      append_query(subtree)
    elseif l == 2 then
      subtree:add(proto_nsdp.fields.port_number, tvb(i + 0, 1))
      subtree:add(proto_nsdp.fields.qos_priotity, tvb(i + 1, 1))
    else
      ae(subtree, 'Invalid length')
    end
    return subtree
  end,

  [TLV.INGRESS] = port_limit,
  [TLV.EGRESS] = port_limit,

  [TLV.BROADCAST_FILTERING] = pf(ProtoField.uint8, 'nsdp.broadcast_filtering', vs_tlvs[TLV.BROADCAST_FILTERING], base.HEX, {
    [0x00] = 'Off',
    [0x03] = 'On',
  }),

  [TLV.BROADCAST_BANDWIDTH] = port_limit,

  [TLV.MIRRORING] = function (tree, tvb, i, l)
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 0 then
      append_query(subtree)
    elseif l and l > 2 then
      subtree:add(proto_nsdp.fields.port_number, tvb(i + 0, 1))
      ports_bitmap('Ports', subtree, tvb, i + 2, l - 2)
    else
      ae(subtree, 'Invalid length')
    end
    return subtree
  end,

  [TLV.NUMBER_OF_PORTS] = pf(ProtoField.uint8, 'nsdp.number_of_ports', vs_tlvs[TLV.NUMBER_OF_PORTS]),
  [TLV.IGMP_SNOOPING] = pf(ProtoField.uint8, 'nsdp.igmp.snooping', vs_tlvs[TLV.IGMP_SNOOPING], base.HEX, vs_on_off),
  [TLV.BLOCK_UNKNOWN_MULTICASTS] = pf(ProtoField.uint8, 'nsdp.block_unknown_multicasts', vs_tlvs[TLV.BLOCK_UNKNOWN_MULTICASTS], base.HEX, vs_on_off),
  [TLV.IGMP_HEADER_VALIDATION] = pf(ProtoField.uint8, 'nsdp.igmp.header_validation', vs_tlvs[TLV.IGMP_HEADER_VALIDATION], base.HEX, vs_on_off),

  [TLV.TLV_BITMAP] = function (tree, tvb, i, l)
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 0 then
      append_query(subtree)
    elseif l == 8 then
      for j = 0, 7 do
	local bitmap = tvb(i + (7 - j), 1):uint()
	for k = 0, 7 do
	  local b = 8 * j + k
	  local mask = bit32.lshift(1, k)
	  if bit32.band(mask, bitmap) ~= 0 then
	    if CAPABILITIES[b] then
	      subtree:add(tvb(i + (7 - j), 1), CAPABILITIES[b])
	    else
	      subtree:add(tvb(i + (7 - j), 1), string.format('Unknown (bit %d)', b))
	    end
	  end
	end
      end
    else
      ae(subtree, 'Invalid length')
    end
    return subtree
  end,

  [TLV.SERIAL_NUMBER] = function (tree, tvb, i, l)
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 0 then
      append_query(subtree)
    elseif l == 21 then
      subtree:add(proto_nsdp.fields.unknown, tvb(i, 1))
      subtree:add(proto_nsdp.fields.serial, tvb(i + 1, 14))
      subtree:add(proto_nsdp.fields.unknown, tvb(i + 15, l - 15))
    else
      ae(subtree, 'Invalid length')
    end
    return subtree
  end,

  [TLV.LOOP_DETECTION] = pf(ProtoField.uint8, 'nsdp.loop_detection', vs_tlvs[TLV.LOOP_DETECTION], base.HEX, vs_on_off),

  [TLV.PORT_SPEED] = function (tree, tvb, i, l)
    local subtree, i, l = ts(tree, tvb, i, l)
    if l == 0 then
      append_query(subtree)
    elseif l == 3 then
      subtree:add(proto_nsdp.fields.port_number, tvb(i + 0, 1))
      subtree:add(proto_nsdp.fields.port_speed, tvb(i + 1, 1))
      subtree:add(proto_nsdp.fields.port_flow_control, tvb(i + 2, 1))
    else
      ae(subtree, 'Invalid length')
    end
    return subtree
  end,

  [TLV.POWER_SAVING] = pf(ProtoField.uint8, 'nsdp.power_saving', vs_tlvs[TLV.POWER_SAVING], base.HEX, vs_on_off),
  [TLV.END_OF_MESSAGES] = function (tree, tvb, i, l)
    return ts(tree, tvb, i, l)
  end,
}

-- register fields
for tlv, field in pairs(tlvs) do
if type(field) == 'function' then
    proto_nsdp.fields[tlv] = field(nil)
  end
end

-- dissector function
function proto_nsdp.dissector (tvb, packet, root)
  if tvb:len() == 0 then return end
  packet.cols.protocol = proto_nsdp.name

  nsdp = root:add(proto_nsdp, tvb(0))
  nsdp:add(proto_nsdp.fields.version, tvb(0, 1))
  nsdp:add(proto_nsdp.fields.operation, tvb(1, 1))
  nsdp:add(proto_nsdp.fields.result, tvb(2, 2))
  nsdp:add(proto_nsdp.fields.result_tlv, tvb(4, 2))
  nsdp:add(proto_nsdp.fields.host_mac, tvb(8, 6))
  nsdp:add(proto_nsdp.fields.device_mac, tvb(14, 6))
  nsdp:add(proto_nsdp.fields.sequence, tvb(22, 2))

  messages = nsdp:add(proto_nsdp.fields.messages, tvb(32, tvb:len() - 32))
  local i = 32
  while i < tvb:len() do
    local tlv = tvb(i, 2):uint()
    local l = tvb(i + 2, 2):uint()
    local msg = nil
    local f = tlvs[tlv]
    if f then
      if type(f) == 'function' then
        msg = f(messages, tvb, i, l + 4)
      end
    else
      msg = messages:add(tvb(i, l + 4), string.format('Unknown TLV 0x%04x', tlv))
      msg:add(proto_nsdp.fields.tlv, tvb(i, 2))
      msg:add(proto_nsdp.fields.l, tvb(i + 2, 2))
      if l > 0 then
        msg:add(proto_nsdp.fields.data, tvb(i + 4, l))
      end
    end
    i = i + l + 4
  end
end

local dissector_table = DissectorTable.get('udp.port')
for port = 63321, 63324 do
  dissector_table:add(port, proto_nsdp)
end
