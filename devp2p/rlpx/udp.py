# -*- coding: utf-8 -*-
'''
This module implements the UDP part of the RLPx protocol.

RLPx is a cryptographic peer-to-peer network and protocol suite which provides a
general-purpose transport and interface for applications to communicate via a
p2p network. RLPx utilizes Kademlia-like routing which has been repurposed as a
p2p neighbour discovery protocol. RLPx discovery uses 512-bit public keys as
node ids and sha3(node-id) for xor metric. DHT features are not implemented.
'''
# Rationale in the module:
#
# The wire protocol is based on two layers:
#  - the RLP encoding
#  - the binary representation that is encoded in RLP
# Throught the code, to be clear about this distinction the suffix _binary and
# _encoded/_decoded is used.
#
# The decoding functionality is treated as a form of parsing, and that means
# that parsing erros are part of the API not an exceptional case, because of
# this when an invalid value in encounterred a None value is returned and a
# message is logged.
#
# The encoding functionality is seen as a API for programming only, so with no
# validation, that means that invalid values must not be considered normal and
# are exceptional and unrecoverable from the point of view of this module, so
# Exceptions are used.
#
import time
import struct

import ipaddress
import rlp
import six

from devp2p import crypto
from devp2p import kademlia
from devp2p import slogging
from devp2p import utils

log = slogging.get_logger('p2p.rlpx')

MDC_SIZE = 32   # Modification Detection Code
SIZ_SIZE = 65
TYPE_SIZE = 1

MDC_SLICE = slice(0, MDC_SIZE)
MDC_DATA = slice(MDC_SIZE, None)

SIGNATURE_SLICE = slice(MDC_SIZE, MDC_SIZE + SIZ_SIZE)
SIGNATURE_DATA = slice(MDC_SIZE + SIZ_SIZE, None)

TYPE_SLICE = slice(MDC_SIZE + SIZ_SIZE, MDC_SIZE + SIZ_SIZE + TYPE_SIZE)

PAYLOAD_SLICE = slice(MDC_SIZE + SIZ_SIZE + TYPE_SIZE, None)

RLPx_MIN_SIZE = MDC_SIZE + SIZ_SIZE + TYPE_SIZE
RLPx_VERSION = 4
# Total payload of packet excluding IP headers. To reduce change of
# fragmentation, RLPx max size is 1280 bytes, the minimum size of an IPv6
# datagram.
RLPx_MAX_SIZE = 1280

PUBKEY_LENGTH = kademlia.k_pubkey_size / 8

# Protocol messages constants
RLPX_PING = 1
RLPX_PONG = 2
RLPX_FIND_NEIGHBOURS = 3
RLPX_NEIGHBOURS = 4

EXPIRATION_SECONDS = 60


def timeout():
    ''' Returns the timestamps of the timeout.'''
    return int(time.time() + EXPIRATION_SECONDS)


def biendinan_16bits(integer):
    ''' Returns an 16 bit integer in big-endian format. '''
    if not isinstance(integer, (int, long)):
        raise TypeError('argument integer must be of type int or long')

    if 0 > integer > 65535:
        raise ValueError('integer {} out-of-range'.format(integer))

    return struct.pack('>I', integer)[-2:]


# Packet encapsulation


def unpack_and_verify(message):
    """ Parses a packet. """

    # Packet = [sha3 hash, signatura, byte type, variable payload]
    if RLPx_MIN_SIZE > len(message) > RLPx_MAX_SIZE:
        log.warn('Packet with wrong size {len}'.format(len=len(message)))
        return

    mdc = message[MDC_SLICE]
    data = message[MDC_DATA]

    if mdc != crypto.sha3(data):
        log.warn('Packet with wrong MCD')
        return

    signature = message[SIGNATURE_SLICE]
    signature_data = message[SIGNATURE_DATA]

    signature_data_hash = crypto.sha3(signature_data)
    remote_pubkey = crypto.ecdsa_recover(signature_data_hash, signature)

    if len(remote_pubkey) != PUBKEY_LENGTH:
        log.warn('Public key with the wrong length {len}'.format(len=len(remote_pubkey)))
        return

    # XXX: is it safe to just use ord?
    type_ = ord(message[TYPE_SLICE])
    payload = message[PAYLOAD_SLICE]

    try:
        payload_decoded = rlp.decode(payload)
    except (rlp.DecodingError, rlp.DeserializationError):
        log.warn('Payload is not a valid RPL')
        log.debug('', payload=payload.encode('hex'))
        return

    if not isinstance(payload_decoded, list):
        log.warn('The RPLx payload must be a list of elements')
        log.debug('', payload=payload_decoded)
        return

    return remote_pubkey, type_, payload_decoded, mdc


def pack(private_key, cmd_id, payload_bytes):
    """ Create an RLPx packet """
    # this check is to keep the API symmetric:
    #    pack and encode receive a list of elements
    #    unpack and decode returns lists
    #    pack and unpack receive partially encoded arguments and dont care about the content
    #    encode and decode receive the data, use the right binary representation and return a list RLP encoded
    if not isinstance(payload_bytes, list):
        raise TypeError('payload_bytes needs to be a list of bytes')

    if cmd_id > 127:
        raise ValueError('type cannot have a value larger than 127, got {}'.format(cmd_id))

    # only cmd_id <= 127 are valid, so it's save to use chr() here because in
    # RLP these values are kept intact
    cmd_id = chr(cmd_id)

    encoded_data = rlp.encode(payload_bytes)

    # these can raise AssertionError
    hash_ = crypto.sha3(cmd_id + encoded_data)
    signature = crypto.sign(hash_, private_key)
    mdc = crypto.sha3(signature + cmd_id + encoded_data)

    # hash || signature || packet-type || packet-data
    return mdc + signature + cmd_id + encoded_data


# Encoding


def binary_timestamp(timestamp_expiration):
    if not isinstance(timestamp_expiration, int):
        raise TypeError('timestamp_expiration must be of type int')

    if timestamp_expiration < time.time():
        raise ValueError('timestamp_expiration needs to be in the future')

    return rlp.sedes.big_endian_int.serialize(timestamp_expiration)


def binary_endpoint(ip, udp_port, tcp_port):
    """ Validate the structure and convert the data into the right binary format """
    if not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        raise TypeError('ip must be an IPv4Address or IPv6Address')

    if not isinstance(udp_port, (int, long)):
        raise TypeError('udp_port must be an int or long')

    if not isinstance(tcp_port, (int, long)):
        raise TypeError('tcp_port must be an int or long')

    if 0 > udp_port > 65535:
        raise ValueError('udp_port need to be in the range (0, 65535]')

    if 0 > tcp_port > 65535:
        raise ValueError('tcp_port need to be in the range (0, 65535]')

    # address || udpPort || tcpPort
    payload_binary = [
        ip.packed,
        biendinan_16bits(udp_port),
        biendinan_16bits(tcp_port),
    ]
    return payload_binary


def encode_ping(version, from_endpoint, to_endpoint, timestamp_expiration):
    """ Validate the structure and convert the data into the right binary format """
    if not isinstance(version, int):
        raise TypeError('version must be of type int')

    if not isinstance(timestamp_expiration, int):
        raise TypeError('timestamp_expiration must be of type int')

    if len(from_endpoint) != 3:
        raise ValueError('from_endpoint has 3 fields, got {}'.format(len(from_endpoint)))

    if len(to_endpoint) != 3:
        raise ValueError('from_endpoint has 3 fields, got {}'.format(len(from_endpoint)))

    from_ip, from_udp_port, from_tcp_port = from_endpoint
    to_ip, to_udp_port, to_tcp_port = to_endpoint

    from_binary = binary_endpoint(from_ip, from_udp_port, from_tcp_port)
    to_binary = binary_endpoint(to_ip, to_udp_port, to_tcp_port)

    # version || from || to || timestamp
    version_binary = rlp.sedes.big_endian_int.serialize(version)
    expiration_binary = binary_timestamp(timestamp_expiration)
    payload_binary = [
        version_binary,
        from_binary,
        to_binary,
        expiration_binary,
    ]

    return payload_binary


def encode_pong(to_endpoint, echo, timestamp_expiration):
    """ Validate the structure and convert the data into the right binary format """
    if len(to_endpoint) != 3:
        raise ValueError('to_endpoint has 3 fields, got {}'.format(len(to_endpoint)))

    if not isinstance(timestamp_expiration, int):
        raise TypeError('timestamp_expiration must be of type int')

    to_ip, to_udp_port, to_tcp_port = to_endpoint
    to_binary = binary_endpoint(to_ip, to_udp_port, to_tcp_port)

    # to || echo || timestamp
    expiration_binary = binary_timestamp(timestamp_expiration)
    payload_binary = [to_binary, echo, expiration_binary]  # the echo value is kept as is

    return payload_binary


def encode_find_neighbours(target, timestamp_expiration):
    """ Validate the structure and convert the data into the right binary format """
    if not isinstance(target, six.binary_type):
        raise TypeError('target is must be bytes')

    if not isinstance(timestamp_expiration, int):
        raise TypeError('timestamp_expiration must be of type int')

    # could be larger
    if len(target) != PUBKEY_LENGTH:
        raise ValueError('Invalid target')

    expiration_binary = binary_timestamp(timestamp_expiration)
    payload_binary = [target, expiration_binary]

    return payload_binary


def encode_neighbours(node_list, timestamp_expiration):
    """ Validate the structure and convert the data into the right binary format """
    if not isinstance(node_list, list):
        raise TypeError('node_list needs to be a list')

    if not isinstance(timestamp_expiration, int):
        raise TypeError('timestamp_expiration must be of type int')

    # Endpoint is encoded inline, so we cant reuse another function
    node_list_encoded = []
    for node in node_list:
        if len(node) != 4:
            raise ValueError('Each node needs to have 4 fields [ip, udp, tcp, pubkey]')

        ip, udp_port, tcp_port, pubkey = node

        if 0 > udp_port > 65535:
            raise ValueError('udp_port need to be in the range (0, 65535]')

        if 0 > tcp_port > 65535:
            raise ValueError('tcp_port need to be in the range (0, 65535]')

        # keep symmetry with decoding
        if not isinstance(pubkey, six.binary_type):
            raise ValueError('pubkey must be bytes')

        # ip and pubkey should already be in the correct byte representation
        # XXX: can we check that they are?
        node_list_encoded.append([
            ip.packed,
            biendinan_16bits(udp_port),
            biendinan_16bits(tcp_port),
            pubkey,
        ])

    expiration_binary = binary_timestamp(timestamp_expiration)
    payload_binary = [node_list_encoded, expiration_binary]

    return payload_binary


# Decoding


def decode_expiration(payload):
    """" Convert the binary representation to an object and validate the expiration, since that is part of the protocol. """
    if isinstance(payload, list):
        msg = 'Expiration should be bytes, got an list instead'
        log.warn(msg)
        log.debug('', payload=payload)
        return

    now = time.time()

    expiration_decoded = rlp.sedes.big_endian_int.deserialize(payload)
    if now > expiration_decoded:
        log.warn('Packet expired {expiration} [{difference}]'.format(expiration=expiration_decoded, difference=expiration_decoded - now))
        return

    if now + EXPIRATION_SECONDS < expiration_decoded:
        log.warn('Packet is too far in the future {expiration} [+{difference}]'.format(expiration=expiration_decoded, difference=expiration_decoded - now))
        return

    return expiration_decoded


def decode_endpoint(payload):
    """ Validate the structure and convert the binary representation to an Endpoint object. """

    # Endpoint = [bytes address, uint16_t udp_port, uint16_t tcp_port]
    if len(payload) != 3:
        msg = (
            'Endpoint payload must be comprimised of [address, udp_port, tcp_port], '
            'got an list with {} elements'
        ).format(len(payload))
        log.warn(msg)
        log.debug('', payload=payload)
        return

    ip, udp_port, tcp_port = payload

    # The ip must be RLP encoded, so an IPv4 will have 4 bytes, while an
    # IPv6 16 bytes
    if len(ip) not in (4, 16):
        log.warn('PING.ip field has an invalid value', ip=ip)
        return

    ip_decoded = ipaddress.ip_address(ip)

    # The field ip does _not_ need to be decoded, that is because the RPL
    # protocol is defined to be in network order
    #
    # TODO: make sure the ip is in the valid range (not a private ip like
    # 127.0.0.1)

    try:
        udp_port_decoded = utils.idec(udp_port)
    except (rlp.DecodingError, rlp.DeserializationError):
        log.warn('PING.udp_port is not a valid int in big-endian {port}'.format(udp_port))
        return

    try:
        tcp_port_decoded = utils.idec(tcp_port)
    except (rlp.DecodingError, rlp.DeserializationError):
        log.warn('PING.tcp_port is not a valid int in big-endian {port}'.format(tcp_port))
        return

    return ip_decoded, udp_port_decoded, tcp_port_decoded


def decode_ping(payload):
    """ Validate the structure and convert the binary representation of a ping packet. """

    # PingNode = [h256 version, Endpoint from, Endpoint to, uint32_t timestamp]
    if len(payload) != 4:
        msg = (
            'PING payload must be comprimised of [version, from, to, expiration], '
            'got an list with {} elements'
        ).format(len(payload))
        log.warn(msg)
        log.debug('', payload=payload)
        return

    version, from_, to, expiration = payload

    expiration_decoded = decode_expiration(expiration)
    if expiration_decoded is None:
        return

    version_decoded = rlp.sedes.big_endian_int.deserialize(version)
    if version_decoded != RLPx_VERSION:
        log.warn('Incompatible versions', remote_version=version_decoded, expected_version=RLPx_VERSION)
        return

    remote_address = decode_endpoint(from_)
    if remote_address is None:
        return

    my_address = decode_endpoint(to)
    if my_address is None:
        return

    return version_decoded, remote_address, my_address, expiration_decoded


def decode_pong(payload):
    """ Validate the structure and convert the binary representation of a pong packet. """

    # PongNode = [Endpoint to, h256 echo, uint32_t timestamp]
    if len(payload) != 3:
        msg = (
            'PONG payload must be comprimised of [to, echo, expiration], '
            'got an list with {} elements'
        ).format(len(payload))
        log.warn(msg)
        log.debug('', payload=payload)
        return

    to, echo, expiration = payload

    expiration_decoded = decode_expiration(expiration)
    if expiration_decoded is None:
        return

    # TODO: validate my_address
    my_address = decode_endpoint(to)
    if my_address is None:
        return

    # leave echo alone and let the upper layer take care of it
    return my_address, echo, expiration_decoded


def decode_find_neighbours(payload):
    """ Validate the structure and convert the binary representation of a find_neighbours packet. """

    # FindNeighbours = [NodeId target, uint32_t timestamp]
    if len(payload) != 2:
        msg = (
            'FIND_NEIGHBOURS payload must be comprimised of [target, expiration], '
            'got an list with {} elements'
        ).format(len(payload))
        log.warn(msg)
        log.debug('', payload=payload)
        return

    target, expiration = payload

    expiration_decoded = decode_expiration(expiration)
    if expiration_decoded is None:
        return

    if len(target) != PUBKEY_LENGTH:
        log.warn('FIND_NEIGHBOURS.target with an invalid length {len}'.format(len=len(target)))
        return

    # returning the target/nodeid as bytes like decode_neighbours
    return target, expiration_decoded


def decode_neighbour_item(payload):
    """ Validate the structure and convert the binary representation of an item in the find_neighbours packet. """

    # NeighbourItem = [inline Endpoint endpoint, NodeId node]
    if len(payload) != 4:
        msg = (
            'An element of NEIGHBOURS_LIST payload must be comprimised of '
            '[address, udp_port, tcp_port, node], got an list with {} elements'
        ).format(len(payload))
        log.warn(msg, payload=payload)
        return

    endpoint, nodeid = payload[0:3], payload[3]
    endpoint_decoded = decode_endpoint(endpoint)

    if endpoint_decoded is None:
        return

    # nodeid is kept as bytes
    return list(endpoint_decoded) + [nodeid]


def decode_neighbours(payload):
    """ Validate the structure and convert the binary representation of a neighbours packet. """

    # Neighbours = [NeighbourList list, uint32_t timestamp]
    if len(payload) != 2:
        msg = (
            'NEIGHBOURS payload must be comprimised of [list, expiration], '
            'got an list with {} elements'
        ).format(len(payload))
        log.warn(msg, payload=payload)
        return

    neighbours_list, expiration = payload

    expiration_decoded = decode_expiration(expiration)
    if expiration_decoded is None:
        return

    if not isinstance(neighbours_list, list):
        log.warn('NEIGHBOURS.list must be a list', neighbours_list=neighbours_list)
        return

    neighbours_set = set(map(tuple, neighbours_list))
    if len(neighbours_list) < len(neighbours_set):
        log.info('received duplicates')
        neighbours_list = list(neighbours_set)

    neighbours_decoded_list = []
    for neighbour in neighbours_list:
        neighbour_decoded = decode_neighbour_item(neighbour)

        if neighbour_decoded is None:
            return

        neighbours_decoded_list.append(neighbour_decoded)

    return neighbours_decoded_list, expiration_decoded
