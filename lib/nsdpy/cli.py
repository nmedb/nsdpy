'Command Line Interface'

from binascii import unhexlify
from construct import Container
from argparse import _StoreConstAction, Action, Namespace
from argparse import ArgumentError, ArgumentParser

class CommandAction(_StoreConstAction):
    'A command parser action'
    # pylint: disable=too-few-public-methods
    def __init__(self, option_strings, dest, **kwargs):
        action = option_strings[0][2:]
        super(CommandAction, self).__init__(
            option_strings,
            'action',
            action,
            **kwargs
        )

class MessageAction(Action):
    'The base class for all message parser actions'
    def __init__(self, option_strings, nargs='?',
                 target=None, validate=None, **kwargs):
        self.target = target
        self.validate = validate
        dest = kwargs.get('dest')
        dest = dest.replace('-', '_')
        kwargs['dest'] = dest.replace('.', '_')
        super(MessageAction, self).__init__(option_strings,
                                            nargs=nargs,
                                            **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        msg = Container(tag=self.dest)
        if values is None:
            MessageAction.suggest_action(namespace, 'read')
        elif self.target is not None:
            if type(values) != list:
                values = [values]
            if self.validate is not None:
                values = self._validate(values)
            if type(self.target) != list:
                target = [self.target]
            else:
                target = self.target
            for trg, val in zip(target, values):
                setattr(msg, trg, val)
        MessageAction.append(namespace, msg)
        setattr(namespace, self.dest, True)

    @staticmethod
    def append(namespace, value):
        'Appends a message'
        items = getattr(namespace, 'messages', [])
        items.append(value)
        setattr(namespace, 'messages', items)

    @staticmethod
    def suggest_action(namespace, action):
        'Add a suggested action'
        actions = getattr(namespace, 'suggested_actions', [])
        if type(action) == list:
            actions.extend(action)
        else:
            actions.append(action)
        setattr(namespace, 'suggested_actions', actions)

    def _validate(self, values):
        'Validate the arguments according to given validators'
        if len(values) > len(self.validate):
            needed, given = len(self.validate), len(values)
            msg = 'need at most %d arguments - %d given' % (needed, given)
            raise ArgumentError(self, msg)
        clean_values = []
        for validate, value in zip(self.validate, values):
            validate = getattr(self, 'validate_' + validate)
            clean_values.append(validate(value))
        return clean_values

    def validate_integer(self, value, min_value=0,
                         max_value=65535, name='value'):
        'Validate value a an integer with a minimum and maximum value'
        if not isinstance(value, int):
            try:
                base = 16 if len(value) > 2 and value[:2] == '0x' else 10
                value = int(value, base)
            except ValueError:
                value = None
        if value is None or value < min_value or value > max_value:
            msg = '%s must be an integer between %d and %d' % (
                name, min_value, max_value)
            raise ArgumentError(self, msg)
        return value

    def validate_byte(self, value):
        'Validate as a 8-bit integer'
        return self.validate_integer(value, 0, 255)

    def validate_short(self, value):
        'Validate as a 16-bit integer'
        return self.validate_integer(value, 0, 65535)

    def validate_int(self, value):
        'Validate as a 32-bit integer'
        return self.validate_integer(value, 0, 4294967295)

    def validate_long(self, value):
        'Validate as a 64-bit integer'
        return self.validate_integer(value, 0, 18446744073709551615L)

    def validate_port(self, port):
        'Validate as a port number between 1 and 255'
        return self.validate_integer(port, 1, 255, 'port')

    def validate_vlanid(self, vlanid):
        'Validate as a VLAN ID between 1 and 4095'
        return self.validate_integer(vlanid, 1, 4095, 'vlanid')

    def validate_link_speed(self, speed):
        'Validate as link speed'
        mapping = {
            '0': 'speed_0',
            'zero': 'speed_0',
            'none': 'speed_0',
            'hald10m': 'speed_half_10m',
            'full10m': 'speed_full_10m',
            'half100m': 'speed_half_100m',
            'full100m': 'speed_full_100m',
            '1000m': 'speed_1000m',
            '10g': 'speed_10g',
        }
        if not mapping.has_key(speed):
            valid = "', '".join(mapping.keys())
            msg = "invalid choice: '%s' (choose from '%s')" % (speed, valid)
            raise ArgumentError(self, msg)
        return mapping[speed]

    def validate_port_speed(self, speed):
        'Validate as port speed'
        mapping = {
            '0': 'disabled',
            'disabled': 'disabled',
            'auto': 'auto',
            'half10m': 'hd10m',
            'full10m': 'fd10m',
            'half100m': 'hd100m',
            'full100m': 'fd100m',
        }
        if not mapping.has_key(speed):
            valid = "', '".join(mapping.keys())
            msg = "invalid choice: '%s' (choose from '%s')" % (speed, valid)
            raise ArgumentError(self, msg)
        return mapping[speed]

    def validate_port_status(self, status):
        'Validate as port status'
        mapping = {
            'ok': 'ok',
            'no-cable': 'no_cable',
            'none': 'no_cable',
            'open': 'open_cable',
            'short-circuit': 'short_circuit',
            'fiber': 'fiber_cable',
            'fiber-cable': 'fiber_cable',
            'shorted': 'shorted_cable',
            'shorted-cable': 'shorted_cable',
            'unknown': 'unknown',
            'crosstalk': 'crosstalk',
        }
        if not mapping.has_key(status):
            valid = "', '".join(mapping.keys())
            msg = "invalid choice: '%s' (choose from '%s')" % (status, valid)
            raise ArgumentError(self, msg)
        return mapping[status]

    def validate_on_off(self, value):
        'Validate as on/off'
        if value not in ['on', 'off']:
            msg = "invalid choice: '%s' (choose from 'on', 'off')" % value
            raise ArgumentError(self, msg)
        return value == 'on'

    def validate_qos_priority(self, priority):
        'Validate as QOS priority'
        priorities = ['low', 'normal', 'medium', 'high']
        if priority not in priorities:
            valid = "', '".join(priorities)
            msg = "invalid choice: '%s' (choose from '%s')" % (priority, valid)
            raise ArgumentError(self, msg)
        return priority

    def validate_limit(self, limit):
        'Validate as bandwidth limit'
        mapping = {
            '0': 'limit_0',
            'zero': 'limit_0',
            'none': 'limit_0',
            '512k': 'limit_512k',
            '1m': 'limit_1m',
            '2m': 'limit_2m',
            '4m': 'limit_4m',
            '8m': 'limit_8m',
            '16m': 'limit_16m',
            '32m': 'limit_32m',
            '64m': 'limit_64m',
            '128': 'limit_128',
            '256m': 'limit_256m',
            '512m': 'limit_512m',
        }
        if not mapping.has_key(limit):
            valid = "', '".join(mapping.keys())
            msg = "invalid choice: '%s' (choose from '%s')" % (limit, valid)
            raise ArgumentError(self, msg)
        return mapping[limit]

    def validate_portlist(self, portlist):
        'Validate as a portlist'
        portlist = [int(port) for port in portlist.split(',')]
        for port in portlist:
            self.validate_port(port)
        return portlist

    def validate_ip(self, ip_addr):
        'Validate as an IP address'
        try:
            octets = ip_addr.split('.')
            if len(octets) != 4:
                raise ValueError()
            for octet in octets:
                octet = int(octet)
                if octet < 0 or octet > 255:
                    raise ValueError()
        except:
            raise ArgumentError(self, "invalid ip address: '%s'" % ip_addr)
        return ip_addr

    def validate_mac(self, mac):
        'Validate as a MAC address'
        try:
            octets = mac.split(':')
            if len(octets) != 6:
                raise ValueError()
            for octet in octets:
                octet = ord(unhexlify(octet))
                if octet < 0 or octet > 255:
                    raise ValueError()
        except:
            raise ArgumentError(self, "invalid mac address: '%s'" % mac)
        return mac

    def validate_unhexlify(self, data):
        'Validate as a hexlified binary string'
        try:
            return unhexlify(data)
        except:
            raise ArgumentError(self, "invalid payload")

class CommandMessageAction(MessageAction):
    'A command message action'
    def __init__(self, option_strings, **kwargs):
        super(CommandMessageAction, self).__init__(option_strings,
                                                   nargs=0,
                                                   **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        MessageAction.suggest_action(namespace, 'write')
        MessageAction.append(namespace, Container(tag=self.dest))

class ChoiceMessageAction(MessageAction):
    'An message action with multiple choices'
    def __init__(self, option_strings, target='type', **kwargs):
        super(ChoiceMessageAction, self).__init__(option_strings,
                                                  nargs='?',
                                                  target=target,
                                                  **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if type(values) == str:
            values = values.replace('-', '_')
            values = values.replace('.', '_')
        super(ChoiceMessageAction, self).__call__(parser,
                                                  namespace,
                                                  values,
                                                  option_string)

class ToggleMessageAction(ChoiceMessageAction):
    'An message action for enabling or disabling something'
    def __init__(self, option_strings, target='enabled', **kwargs):
        super(ToggleMessageAction, self).__init__(option_strings,
                                                  choices=['on', 'off'],
                                                  target=target,
                                                  **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if values in ['on', 'off']:
            values = values == 'on'
        super(ToggleMessageAction, self).__call__(parser, namespace,
                                                  values,
                                                  option_string)

class ValueMessageAction(MessageAction):
    'A message action with a value'
    def __init__(self, option_strings, target=None, **kwargs):
        super(ValueMessageAction, self).__init__(option_strings,
                                                 target=target,
                                                 **kwargs)

def add_commands(parser):
    'Add command actions to parser'
    command_group = parser.add_mutually_exclusive_group(required=True)
    command_group.add_argument('--discover', action=CommandAction,
                              help='discover switches')
    command_group.add_argument('--simulate', action=CommandAction,
                              help='simulate switch')
    command_group.add_argument('--read', action=CommandAction,
                              help='read settings from one or more switches')
    command_group.add_argument('--write', action=CommandAction,
                              help='write settings to one or more switches')
    return command_group

def get_parser():
    'Build and return argument parser'
    parser = ArgumentParser(description='Netgear ProSafe switch utility')

    add_commands(parser)

    parser.add_argument('--debug', action='store_true', help='print debugging information')
    parser.add_argument('--interface', help='the network interface to use')
    parser.add_argument('--target', default='00:00:00:00:00:00', metavar='MAC')

    command_group = parser.add_argument_group('commands')
    command_group.add_argument('--reboot', action=CommandMessageAction)
    command_group.add_argument('--factory-reset', action=CommandMessageAction)
    command_group.add_argument('--reset-traffic-stats',
                               action=CommandMessageAction)
    command_group.add_argument('--firmware-upload', action=CommandMessageAction)

    settings_group = parser.add_argument_group('settings')
    settings_group.add_argument('--qos', action=ChoiceMessageAction,
                                choices=['port', 'dscp'])
    settings_group.add_argument('--vlan-engine', action=ChoiceMessageAction,
                                choices=['basic-port',
                                         'advanced-port',
                                         'basic-802.1q',
                                         'advanced-802.1q'])
    settings_group.add_argument('--password-encryption',
                                action=ChoiceMessageAction,
                                choices=['none', 'xor'])
    settings_group.add_argument('--dhcp', action=ToggleMessageAction)
    settings_group.add_argument('--loop-detection', action=ToggleMessageAction)
    settings_group.add_argument('--igmp-snooping', action=ToggleMessageAction)
    settings_group.add_argument('--broadcast-filtering',
                                action=ToggleMessageAction)
    settings_group.add_argument('--validate-igmpv3-ip-header',
                                action=ToggleMessageAction)
    settings_group.add_argument('--block-unknown-multicast-addresses',
                                action=ToggleMessageAction)
    settings_group.add_argument('--ports', action=ValueMessageAction,
                                validate=['port'], target='ports')
    settings_group.add_argument('--ip', action=ValueMessageAction,
                                validate=['ip'], target='address')
    settings_group.add_argument('--netmask', action=ValueMessageAction,
                                validate=['ip'], target='address')
    settings_group.add_argument('--gateway', action=ValueMessageAction,
                                validate=['ip'], target='address')
    settings_group.add_argument('--mac', action=ValueMessageAction,
                                validate=['mac'], target='address')
    settings_group.add_argument('--location', action=ValueMessageAction,
                                target='location')
    settings_group.add_argument('--system-name', action=ValueMessageAction,
                                target='name')
    settings_group.add_argument('--product-name', action=ValueMessageAction,
                                target='name')
    settings_group.add_argument('--firmware-version', action=ValueMessageAction,
                                target='version')
    settings_group.add_argument('--password', action=ValueMessageAction,
                                target='password')
    settings_group.add_argument('--change-password', action=ValueMessageAction,
                                target='password')
    settings_group.add_argument('--product-type', action=ValueMessageAction,
                                validate=['short'], target='unknown')
    settings_group.add_argument('--firmware-active-image',
                                action=ValueMessageAction,
                                validate=['byte'], target='image')
    settings_group.add_argument('--firmware-version2',
                                action=ValueMessageAction,
                                target='unknown')
    settings_group.add_argument('--pvid', action=ValueMessageAction,
                                nargs='*', validate=['port', 'vlanid'],
                                target=['port', 'vlanid'],
                                metavar=('PORT', 'VLANID'))
    settings_group.add_argument('--link-speed', action=ValueMessageAction,
                                nargs='*', validate=['port', 'link_speed'],
                                target=['port', 'speed'],
                                metavar=('PORT', 'SPEED'))
    settings_group.add_argument('--port-qos', action=ValueMessageAction,
                                nargs='*', validate=['port', 'qos_priority'],
                                target=['port', 'priority'],
                                metavar=('PORT', 'PRIORITY'))
    settings_group.add_argument('--ingress', action=ValueMessageAction,
                                nargs='*', validate=['port', 'limit'],
                                target=['port', 'limit'],
                                metavar=('PORT', 'LIMIT'))
    settings_group.add_argument('--engress', action=ValueMessageAction,
                                nargs='*', validate=['port', 'limit'],
                                target=['port', 'limit'],
                                metavar=('PORT', 'LIMIT'))
    settings_group.add_argument('--broadcast-bandwidth',
                                action=ValueMessageAction,
                                nargs='*', validate=['port', 'limit'],
                                target=['port', 'limit'],
                                metavar=('PORT', 'LIMIT'))
    settings_group.add_argument('--mirror', action=ValueMessageAction,
                                nargs='*', validate=['port', 'portlist'],
                                target=['destination_port', 'source_ports'],
                                metavar=('DESTINATION_PORT', 'SOURCE_PORTS'))
    settings_group.add_argument('--test-cable', action=ValueMessageAction,
                                nargs=1, validate=['port'], target=['port'],
                                metavar='PORT')
    settings_group.add_argument('--delete-vlan', action=ValueMessageAction,
                                nargs=1, validate=['vlanid'],
                                target=['vlanid'], metavar='VLANID')
    settings_group.add_argument('--vlan-config', action=ValueMessageAction,
                                nargs='*', validate=['port', 'portlist'],
                                target=['port', 'member_ports'],
                                metavar=('PORT', 'MEMBER_PORTS'))
    settings_group.add_argument('--vlan-config-802.1q',
                                action=ValueMessageAction,
                                nargs='*',
                                validate=['vlanid', 'portlist', 'portlist'],
                                target=['vlanid', 'tagged_ports', 'member_ports'],
                                metavar=('VLANID', 'TAGGED_PORTS')) # @todo
    settings_group.add_argument('--port-speed', action=ValueMessageAction,
                                nargs='*', # @todo 0|3
                                validate=['port', 'port_speed', 'on_off'],
                                target=['port', 'speed', 'flowcontrol'],
                                metavar=('PORT', 'SPEED')) # @todo
    settings_group.add_argument('--traffic-stats', action=ValueMessageAction,
                                nargs='*',
                                validate=['port', 'long', 'long', 'long'],
                                target=['port', 'received',
                                        'sent', 'crc_errors'],
                                metavar=('PORT', 'RECEIVED')) # @todo
    settings_group.add_argument('--cable-test-result',
                                action=ValueMessageAction,
                                nargs='*',
                                validate=['port', 'port_status', 'int'],
                                target=['port', 'status', 'meters'],
                                metavar=('PORT', 'STATUS')) # @todo
    settings_group.add_argument('--raw', action=ValueMessageAction,
                                nargs=2, validate=['short', 'unhexlify'],
                                target=['tag', 'unknown'],
                                metavar=('TAG', 'DATA'))
    return parser

def parse_args(args=None):
    'Parse command line arguments'
    parser = get_parser()
    namespace = Namespace(args=args, messages=[])
    args = parser.parse_args(namespace=namespace)
    args.messages.append(Container(tag='end_of_messages'))
    return args
