'''
NSDP protocol implementation and packet handler
'''
# pylint: disable=invalid-name

import fcntl
import socket
import struct

from construct import BitStruct, Byte, Const, Default, Embedded, Enum
from construct import ExprAdapter, Flag, GreedyBytes, Int, Long, Optional, Pass
from construct import Prefixed, RepeatUntil, Short, Struct, Switch
from construct import SymmetricAdapter, this

class XorEncrypted(SymmetricAdapter):
    """Optionally xor-encrypted."""
    __slots__ = ['key']
    def __init__(self, subcon, key):
        super(XorEncrypted, self).__init__(subcon)
        self.key = key
    def _decode(self, obj, context):
        if context.has_key('encrypted') and context.encrypted:
            key = self.key * (1 + len(obj) // len(self.key))
            obj = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(obj, key))
        return obj

def PasswordString(subcon, key):
    'A password string which is optionally xor encrypted'
    return XorEncrypted(subcon, key)

Password = Struct('password' / PasswordString(GreedyBytes,
                                              'NtgrSmartSwitchRock'))

MacAddress = ExprAdapter(
    Byte[6],
    encoder=lambda obj, ctx: [int(octet, 16) for octet in obj.split(':')],
    decoder=lambda obj, ctx: ':'.join('%02x' % b for b in obj)
)
IPv4Address = ExprAdapter(
    Byte[4],
    encoder=lambda obj, ctx: [int(octet) for octet in obj.split('.')],
    decoder=lambda obj, ctx: '.'.join('%d' % b for b in obj)
)
MAC = Optional(Struct('address' / MacAddress))
IPv4 = Optional(Struct('address' / IPv4Address))
PortsByte = ExprAdapter(
    Byte,
    encoder=lambda obj, ctx:
      sum([1 << (7 - p) for p in xrange(0, 8) if p + 1 in obj]),
    decoder=lambda obj, ctx:
      [p + 1 for p in xrange(0, 8) if obj & (1 << (7 - p))]
)
TLVBitmap = Optional(Struct('unknown' / Long))

Unknown = Optional(Struct('unknown' / GreedyBytes))
LinkSpeedEnum = Enum(
    Byte,
    speed_0=0,
    speed_half_10m=1,
    speed_full_10m=2,
    speed_half_100m=3,
    speed_full_100m=4,
    speed_1000m=5,
    speed_10g=6
)
CableStatusEnum = Enum(
    Int,
    ok=0,
    no_cable=1,
    open_cable=2,
    short_circuit=3,
    fiber_cable=4,
    shorted_cable=5,
    unknown=6,
    crosstalk=7
)
PortLimit = Optional(
    Struct('port' / Byte,
           'limit' / Enum(
               Int,
               limit_0=0,
               limit_none=0,
               limit_512k=1,
               limit_1m=2,
               limit_2m=3,
               limit_4m=4,
               limit_8m=5,
               limit_16m=6,
               limit_32m=7,
               limit_64m=8,
               limit_128m=9,
               limit_256m=10,
               limit_512m=11))
)
PortSpeedFlowcontrol = Optional(
    Struct('port' / Byte,
           'speed' / Enum(
               Byte,
               disabled=0,
               auto=1,
               hd10m=2,
               fd10m=3,
               hd100m=4,
               fd100m=5),
           'flowcontrol' / Flag)
)
BroadcastFilteringEnabled = Optional(
    Struct('enabled' / ExprAdapter(
        Byte,
        encoder=lambda o, c: o == 0x03,
        decoder=lambda o, c: '\x03' if o else '\x00')
       )
)

MessageType = Enum(
    Short,
    # Information
    product_name=0x0001,
    product_type=0x0002, # guess
    system_name=0x0003,
    mac=0x0004,
    location=0x0005, # guess
    ip=0x0006,
    netmask=0x0007,
    gateway=0x0008,
    change_password=0x0009,
    password=0x000a,
    dhcp=0x000b,
    firmware_images=0x000c, # guess
    firmware_version=0x000d,
    firmware_version2=0x000e, # guess
    firmware_active_image=0x000f, # guess
    password_encryption=0x0014,
    password_salt=0x0017, # guess
    password_auth_v1=0x0018, # guess
    password_auth_v2=0x001a, # guess
    link_speed=0x0c00,
    traffic_stats=0x1000,
    cable_test_result=0x1c00,
    vlan_engine=0x2000,
    vlan_config_id=0x2400,
    vlan_config_802_1q=0x2800,
    pvid=0x3000,
    qos=0x3400,
    port_qos=0x3800,
    ingress=0x4c00,
    egress=0x5000,
    broadcast_filtering=0x5400,
    broadcast_bandwidth=0x5800,
    mirror=0x5c00,
    ports=0x6000,
    igmp_snooping=0x6800,
    block_unknown_multicasts=0x6c00,
    igmp_header_validation=0x7000,
    tlv_bitmap=0x7400,
    loop_detection=0x9000,
    port_speed=0x9400,
    port_led_control=0xa000,
    power_saving=0xa800,
    loop_prevention=0xf000,

    # Actions
    firmware_upgrade=0x0010,
    reboot=0x0013,
    factory_reset=0x0400,
    reset_traffic_stats=0x1400,
    test_cable=0x1800,
    delete_vlan=0x2c00,

    # Messages with unknown meaning
    unknown6400=0x6400,
    unknown7800=0x7800,
    unknown7c00=0x7c00,
    unknown8000=0x8000,
    unknown8800=0x8800,
    unknown8c00=0x8c00,

    # End of messages-marker
    end_of_messages=0xffff,

    default=Pass
)

Message = 'message' / Struct(
    'tag' / MessageType,
    Embedded(Prefixed(Short, Switch(this.tag, {
        'product_name': Optional(Struct('name' / GreedyBytes)),
        'product_type': Optional(Struct('type' / Short)),
        'system_name': Optional(Struct('name' / GreedyBytes)),
        'location': Optional(Struct('location' / GreedyBytes)),
        'mac': MAC,
        'ip': IPv4,
        'netmask': IPv4,
        'gateway': IPv4,
        'change_password': Password,
        'password': Password,
        'dhcp': Optional(Struct('enabled' / Flag)),
        'firmware_images': Optional(Struct('images' / Byte)),
        'firmware_version': Optional(Struct('version' / GreedyBytes)),
        'firmware_version2': Optional(Struct('version' / GreedyBytes)),
        'firmware_active_image': Optional(Struct('image' / Byte)),
        'password_encryption': Optional(
            Struct('type' / Enum(Int, none=0, xor=1, v1=8, v2a=16, v2b=17))
        ),
        'password_salt': Optional(Struct('salt' / GreedyBytes)),
        'link_speed': Optional(
            Struct('port' / Byte, 'speed' / LinkSpeedEnum, 'flowcontrol' / Flag)
        ),
        'traffic_stats': Optional(
            Struct('port' / Byte,
                   'received' / Long,
                   'sent' / Long,
                   Default(Long[3], [0, 0, 0]),
                   'crc_errors' / Long)
        ),
        'cable_test_result': Optional(
            Struct('port' / Byte,
                   Embedded(Optional(Struct('status' / CableStatusEnum,
                                            'meters' / Int))))
        ),
        'vlan_engine': Optional(
            Struct('type' / Enum(
                Byte,
                none=0,
                basic_port=1,
                advanced_port=2,
                basic_802_1q=3,
                advanced_802_1q=4
            ))
        ),
        'vlan_config': Optional(
            Struct('vlanid' / Short,
                   Embedded(Optional(Struct('member_ports' / PortsByte))))
        ),
        'vlan_config_802_1q': Optional(
            Struct('vlanid' / Short, Embedded(Optional(
                Struct('tagged_ports' / PortsByte,
                       'member_ports' / PortsByte)
            )))
        ),
        'pvid': Optional(Struct('port' / Byte, 'vlanid' / Short)),
        'qos': Optional(Struct('type' / Enum(Byte, port=1, dscp=2))),
        'port_qos': Optional(
            Struct('port' / Byte,
                   'priority' / Enum(
                       Byte,
                       high=1,
                       medium=2,
                       normal=3,
                       low=4))
        ),
        'ingress': PortLimit,
        'egress': PortLimit,
        'broadcast_filtering': BroadcastFilteringEnabled,
        'broadcast_bandwidth': PortLimit,
        'mirror': Optional(
            Struct('destination_port' / Byte,
                   Default(Byte, 0),
                   'source_ports' / PortsByte)
        ),
        'ports': Optional(Struct('ports' / Byte)),
        'igmp_snooping': Optional(Struct('enabled' / Flag, 'vlanid' / Short)),
        'block_unknown_multicasts': Optional(Struct('enabled' / Flag)),
        'igmp_header_validation': Optional(Struct('enabled' / Flag)),
        'tlv_bitmap': TLVBitmap,
        'loop_detection': Optional(Struct('enabled' / Flag)),
        'firmware_upgrade': Struct(Default(Byte, 1)),
        'reboot': Struct(Default(Byte, 1)),
        'factory_reset': Struct(Default(Byte, 1)),
        'reset_traffic_stats': Struct(Default(Byte, 1)),
        'test_cable': Struct('port' / Byte, Default(Byte, 1)),
        'delete_vlan': Struct('vlanid' / Short),
        'password_auth_v1': Optional(Struct('hash' / GreedyBytes)),
        'password_auth_v2': Optional(Struct('hash' / GreedyBytes)),
        'unknown6400': Unknown,
        'unknown7c00': Unknown,
        'unknown8000': Unknown,
        'unknown8800': Unknown,
        'unknown8c00': Unknown,
        'port_led_control': Optional(
            Struct('led' / Enum(
                Byte,
                speed_activity=0,
                speed=1,
                off=2))
        ),
        'power_saving': Optional(Struct('enabled' / Flag)),
        'port_speed': PortSpeedFlowcontrol,
        'loop_prevention': Optional(Struct('enabled' / Flag)),
        'end_of_messages': Pass,
    }, default=Unknown)))
)

Packet = 'packet' / Struct(
    'version' / Byte,
    'operation' / Enum(Byte,
                       read_req=1,
                       read_rsp=2,
                       write_req=3,
                       write_rsp=4,),
    'result' / Enum(Byte,
                    success=0x00,
                    protocol_version_mismatch=0x01,
                    command_not_supported=0x02,
                    tlv_not_supported=0x03,
                    tlv_length_error=0x04,
                    tlv_value_error=0x05,
                    ip_not_allowed=0x06,
                    incorrect_password=0x07,
                    boot_code_firmware_download=0x08,
                    incorrect_username=0x09,
                    configure_via_web=0x0a,
                    tftp_call_error=0x0c,
                    incorrect_password2=0x0d,
                    auth_failed_lock=0x0e,
                    management_disabled=0x0f,
                    tftp_call_error2=0x81,
                    tftp_out_of_memory=0x82,
                    firmware_upgrade_failed=0x83,
                    tftp_timeout=0x84,
                    command_scheduled=0xf0,
                    command_in_progress=0xf1,
                    tftp_in_progress=0xf2,
                    internal_error=0xf8,
                    timeout=0xff),
    'unknown_0' / Default(Byte, 0),
    'tlv' / Default(MessageType, 0),
    'unknown_1' / Default(Short, 0),
    'host_mac' / MacAddress,
    'device_mac' / MacAddress,
    'unknown_2' / Default(Short, 0),
    'sequence' / Short,
    Const(b'NSDP'),
    'unknown_3' / Default(Int, 0),
    'messages' / RepeatUntil(
        lambda obj, lst, ctx: obj.tag == 'end_of_messages',
        Message
    )
)

SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

class PacketHandler(object):
    'Handler for sending and receiving NSDP packets'
     # pylint: disable=too-many-instance-attributes
    def __init__(self, interface=None, mode='host', timeout=None):
        self.last_addr = None
        if interface is None:
            interface = PacketHandler._get_default_interface()
        self.interface = interface
        self.ip_addr = self._get_ip()
        self.mac = self._get_mac()
        if mode == 'host':
            attr, local, remote = 'host_mac', 63321, 63322
        else:
            attr, local, remote = 'device_mac', 63322, 63321
        self.addr_attr, self.local_port, self.remote_port = attr, local, remote
        self.timeout = timeout
        self.recv_socket = self._get_socket('255.255.255.255', self.local_port)
        self.send_socket = self._get_socket(self.ip_addr, self.local_port)
        self.data = ''

    @staticmethod
    def _get_default_interface():
        'Get the interface of the default route'
        with open('/proc/net/route') as route_file:
            for line in route_file.readlines()[1:]:
                val = line.strip().split()
                interface, destination, flags = val[0], val[1], val[3]
                if destination != '00000000' and int(flags, 16) & 2:
                    return interface
        return None

    def _get_ip(self):
        'Get the IP address of the interface'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        iface = struct.pack('256s', self.interface[:15])
        addr = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, iface)
        return socket.inet_ntoa(addr[20:24])

    def _get_mac(self):
        'Get the MAC address of the interface'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        iface = struct.pack('256s', self.interface[:15])
        addr = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR, iface)[18:24]
        return ':'.join(['%02x' % ord(char) for char in addr])

    def _get_socket(self, ip_addr, port):
        'Get an UDP socket bound to the ip address and port given'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(self.timeout)
        sock.bind((ip_addr, port))
        return sock

    def send(self, packet):
        'Send an NSDP packet'
        self.send_socket.sendto(
            Packet.build(packet),
            ('255.255.255.255', self.remote_port)
        )

    def receive(self, raw=False):
        'Receive an NSDP packet'
        addr_attr = self.addr_attr
        addr = ['00:00:00:00:00:00', self.mac]
        packet = None
        try:
            while packet is None and getattr(packet, addr_attr) not in addr:
                self.data, self.last_addr = self.recv_socket.recvfrom(4096)
                packet = Packet.parse(self.data)
        except socket.timeout:
            self.last_addr = None
            return None
        return self.data if raw else packet
