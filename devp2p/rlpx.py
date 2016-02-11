# -*- coding: utf-8 -*-
'''
This module implements the RLPx protocol, a variation of the kademlia with the
adition of signed packets.

The spec can be found at the following URL:

    https://github.com/ethereum/devp2p/blob/master/rlpx.md
'''
import time

import rlp
import slogging

from devp2p import crypto
from devp2p import kademlia
from devp2p import utils

log = slogging.get_logger('p2p.rlpx')

# Protocol packet constants
MDC_SIZE = 32   # Modification Detection Code
SIZ_SIZE = 65
TYPE_SIZE = 1

MDC_SLICE = slice(0, MDC_SIZE)
SIG_SLICE = slice(MDC_SIZE, MDC_SIZE + SIZ_SIZE)
TYPE_SLICE = slice(MDC_SIZE + SIZ_SIZE, MDC_SIZE + SIZ_SIZE + TYPE_SIZE)

MDC_DATA = slice(MDC_SIZE, None)
PAYLOAD_SLICE = slice(MDC_SIZE + SIZ_SIZE + TYPE_SIZE, None)

RLPx_MIN_SIZE = MDC_SIZE + SIZ_SIZE + TYPE_SIZE + 1
RLPx_MAX_SIZE = 1280  # Total payload of packet excluding IP headers
RLPx_VERSION = 4

PUBKEY_LENGTH = kademlia.k_pubkey_size / 8

# Protocol messages constants
RLPX_PING = 1
RLPX_PONG = 2
RLPX_FIND_NEIGHBOURS = 3
RLPX_NEIGHBOURS = 4

EXPIRATION_SECONDS = 60

enc_port = lambda port: utils.ienc4(port)[-2:]
dec_port = utils.idec


def rlpx_unpack(message):
    """ Parses a RLPx PACKET.

    The PACKET has the following structure:

        Packet = [sha3 hash, signatura, byte type, variable payload]
    """
    if RLPx_MIN_SIZE > len(message) > RLPx_MAX_SIZE:
        log.warn('Packet with wrong size {len}'.format(len=len(message)))
        return

    mdc = message[MDC_SLICE]
    data = message[MDC_DATA]

    if mdc != crypto.sha3(data):
        log.warn('Packet with wrong MCD')
        return

    signature = message[SIG_SLICE]
    payload = message[PAYLOAD_SLICE]

    signed_payload = crypto.sha3(payload)
    remote_pubkey = crypto.ecdsa_recover(signed_payload, signature)

    if len(remote_pubkey) != PUBKEY_LENGTH:
        log.warn('Public key with the wrong length {len}'.format(len=len(remote_pubkey)))
        return

    # XXX: is it safe to just use ord?
    type_ = ord(message[TYPE_SLICE])

    try:
        payload_decoded = rlp.decode(payload)
    except (rlp.DecodingError, rlp.DeserializationError):
        log.warn('Payload is not a valid RPL')
        log.debug('', payload=payload)
        return

    if not isinstance(payload_decoded, list):
        log.warn('The RPLx payload must be a list of elements')
        log.debug('', payload=payload_decoded)
        return

    return remote_pubkey, type_, payload_decoded, mdc


def rlpx_expiration(payload):
    """" Parses and validates an expiration, since that is part of the protocol. """
    if isinstance(payload, list):
        msg = 'Expiration should be bytes, got an list instead'
        log.warn(msg)
        log.debug('', payload=payload)
        return

    now = time.time()

    expiration_decoded = rlp.sedes.big_endian_int.deserialize(payload)
    if now > expiration_decoded:
        log.warn('Packet expired {expiration}'.format(expiration=expiration_decoded))
        return

    if now + EXPIRATION_SECONDS < expiration_decoded:
        log.warn('Packet is too away in the future {expiration} [+{difference}]'.format(expiration=expiration_decoded, difference=expiration_decoded - now))
        return

    return expiration_decoded


def rlpx_endpoint(payload):
    """ Parses an ENDPOINT structure.

    The ENDPOINT structure is as follows:

        Endpoint    = [bytes address, uint16_t udp_port, uint16_t tcp_port]
    """
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

    # The field ip does _not_ need to be decoded, that is because the RPL
    # protocol is defined to be in network order
    #
    # TODO: make sure the ip is in the valid range (not a private ip like
    # 127.0.0.1)

    try:
        udp_port_decoded = dec_port(udp_port)
    except (rlp.DecodingError, rlp.DeserializationError):
        log.warn('PING.port is not a valid RPL {port}'.format(port))
        return

    try:
        tcp_port_decoded = dec_port(tcp_port)
    except (rlp.DecodingError, rlp.DeserializationError):
        log.warn('PING.port is not a valid RPL {port}'.format(port))
        return

    return ip, udp_port_decoded, tcp_port_decoded


def rlpx_ping(payload):
    """ Parses a PING packet.

    The PING packet has the following structure:

        packet-type = 0x01
        PingNode    = [h256 version, Endpoint from, Endpoint to, uint32_t timestamp]
    """
    if len(payload) != 4:
        msg = (
            'PING payload must be comprimised of [version, from, to, expiration], '
            'got an list with {} elements'
        ).format(len(payload))
        log.warn(msg)
        log.debug('', payload=payload)
        return

    version, from_, to, expiration = payload

    expiration_decoded = rlpx_expiration(expiration)
    if expiration_decoded is None:
        return

    version_decoded = rlp.sedes.big_endian_int.deserialize(version)
    if version_decoded != RLPx_VERSION:
        log.warn('Incompatible versions', remote_version=version_decoded, expected_version=RLPx_VERSION)
        return

    remote_address = rlpx_endpoint(from_)
    if remote_address:
        return

    my_address = rlpx_endpoint(to)
    if my_address:
        return

    return version_decoded, remote_address, my_address, expiration_decoded


def rlpx_pong(payload):
    """ Parses a PONG packet.

    The PONG packet has the following structure:

        packet-type = 0x02
        PongNode    = [Endpoint to, h256 echo, uint32_t timestamp]
    """
    if len(payload) != 3:
        msg = (
            'PONG payload must be comprimised of [to, echo, expiration], '
            'got an list with {} elements'
        ).format(len(payload))
        log.warn(msg)
        log.debug('', payload=payload)
        return

    to, echo, expiration = payload

    expiration_decoded = rlpx_expiration(expiration)
    if expiration_decoded is None:
        return

    # TODO: validate my_address
    my_address = rlpx_endpoint(to)
    if my_address:
        return

    return my_address, echo, expiration_decoded


def rlpx_find_neighbours(payload):
    """ Parses a FIND_NEIGHBOURS packet.

    The FIND_NEIGHBOURS packet has the following structure:

        packet-type     = 0x03
        FindNeighbours  = [NodeId target, uint32_t timestamp]
    """
    if len(payload) != 2:
        msg = (
            'FIND_NEIGHBOURS payload must be comprimised of [target, timestamp], '
            'got an list with {} elements'
        ).format(len(payload))
        log.warn(msg)
        log.debug('', payload=payload)
        return

    target, expiration = payload

    expiration_decoded = rlpx_expiration(expiration)
    if expiration_decoded is None:
        return

    if len(target) != PUBKEY_LENGTH:
        log.warn('FIND_NEIGHBOURS.target with an invalid length {len}'.format(len=len(target)))
        return

    try:
        target_decoded = utils.big_endian_to_int(payload[0])
    except (rlp.DecodingError, rlp.DeserializationError):
        log.warn('FIND_NEIGHBOURS.target is not a valid RPL {target}'.format(target=target))
        return

    return target_decoded, expiration_decoded


def rlpx_neighbour_item(payload):
    if len(payload) != 4:
        msg = (
            'An element of NEIGHBOURS_LIST payload must be comprimised of '
            '[address, udp_port, tcp_port, node], got an list with {} elements'
        ).format(len(payload))
        log.warn(msg, payload=payload)
        return

    endpoint, nodeid = payload[0:3], payload[3]
    endpoint_decoded = rlpx_endpoint(endpoint)

    if endpoint_decoded is None:
        return

    return list(endpoint_decoded) + [nodeid]


def rlpx_neighbours(payload):
    """ Parses a NEIGHBOURS packet.

    The NEIGHBOURS packet has the following structure:

        packet-type = 0x04
        Neighbours  = [NEIGHBOUR_LIST list, uint32_t timestamp]
    """
    if len(payload) != 2:
        msg =(
            'NEIGHBOURS payload must be comprimised of [list, timestamp], '
            'got an list with {} elements'
        ).format(len(payload))
        log.warn(msg, payload=payload)
        return

    neighbours_list, expiration = payload

    expiration_decoded = rlpx_expiration(expiration)
    if expiration_decoded is None:
        return

    if not isinstance(neighbours_list, list):
        log.warn('NEIGHBOURS.list must be a list', neighbours_list=neighbours_list)
        return

    if len(neighbours_list) < set(map(tuple, neighbours_list)):
        log.info('received duplicates')

    neighbours_decoded_list = []
    for neighbour in neighbours_list:
        neighbour_decoded = rlpx_neighbour_item(neighbour)

        if neighbour_decoded is None:
            return

        neighbours_decoded_list.append(neighbour_decoded)

    return neighbours_decoded_list, expiration_decoded
