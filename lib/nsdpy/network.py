'''
NSDP packet handler
'''

import fcntl
import socket
import struct

from protocol import Packet

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
