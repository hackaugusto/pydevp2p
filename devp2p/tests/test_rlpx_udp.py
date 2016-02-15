# -*- coding: utf8 -*-
import random
import time
from itertools import product

import ipaddress
import pytest

import devp2p.rlpx.udp
from devp2p import crypto
from devp2p import discovery

# TODO:
#  - Test the slices used in the unpack_and_verify


def random_key():
    return hex(random.getrandbits(256))[2:-1].zfill(64).decode('hex')


def public_key(private_key):
    return crypto.privtopub(private_key)


def assert_endpoint(first, second):
    assert first[0] == second[0]
    assert first[1] == second[1]
    assert first[2] == second[2]


PRIVATE_KEY = random_key()
PUBLIC_KEY = public_key(PRIVATE_KEY)

OTHER_KEY = random_key()
OTHER_PUBLIC_KEY = public_key(OTHER_KEY)


def test_expiration_in_the_future():
    assert devp2p.rlpx.udp.timeout() > time.time()


def test_binary_endpoint_validate_type_udp():
    Address = discovery.Address

    with pytest.raises(TypeError):
        Address('127.0.0.1', None)

    with pytest.raises(TypeError):
        Address('127.0.0.1', '')

    with pytest.raises(TypeError):
        Address('127.0.0.1', '1')

    with pytest.raises(TypeError):
        Address('127.0.0.1', u'1')

    with pytest.raises(TypeError):
        Address('127.0.0.1', b'1')

    with pytest.raises(TypeError):
        Address('127.0.0.1', [])

    with pytest.raises(TypeError):
        Address('127.0.0.1', {})

    with pytest.raises(TypeError):
        Address('127.0.0.1', float())


def test_address_validate_type_tcp():
    Address = discovery.Address

    with pytest.raises(TypeError):
        Address('127.0.0.1', 30303, None)

    with pytest.raises(TypeError):
        Address('127.0.0.1', 30303, '')

    with pytest.raises(TypeError):
        Address('127.0.0.1', 30303, '1')

    with pytest.raises(TypeError):
        Address('127.0.0.1', 30303, u'1')

    with pytest.raises(TypeError):
        Address('127.0.0.1', 30303, b'1')

    with pytest.raises(TypeError):
        Address('127.0.0.1', 30303, [])

    with pytest.raises(TypeError):
        Address('127.0.0.1', 30303, {})

    with pytest.raises(TypeError):
        Address('127.0.0.1', 30303, float())


def test_binary_endpoint():
    ip = ipaddress.ip_address(u'127.0.0.1')

    binary = devp2p.rlpx.udp.binary_endpoint(ip, 30303, 30303)

    # 127.0.0.1 in big endian is: \x7f\x00\x00\x01     [4 bytes]
    # 30303 in big endian is: v_                       [2 bytes]
    assert binary == [b'\x7f\x00\x00\x01', b'v_', b'v_']


def test_encode_ping_validate():
    ip = ipaddress.ip_address(u'127.0.0.1')
    timestamp_expiration = devp2p.rlpx.udp.timeout()

    # `from` and to `need` to have [ip, udp_port, tcp_port]
    with pytest.raises(ValueError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[],
            to_endpoint=[],
            timestamp_expiration=timestamp_expiration,
        )

    with pytest.raises(ValueError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[ip, 2, 3],
            to_endpoint=[],
            timestamp_expiration=timestamp_expiration,
        )

    with pytest.raises(ValueError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[ip, 2, 3],
            to_endpoint=[ip, 2],
            timestamp_expiration=timestamp_expiration,
        )

    with pytest.raises(ValueError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[],
            to_endpoint=[ip, 2, 3],
            timestamp_expiration=timestamp_expiration,
        )

    with pytest.raises(ValueError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[ip, 2],
            to_endpoint=[ip, 2, 3],
            timestamp_expiration=timestamp_expiration,
        )

    # version needs to be a number
    with pytest.raises(TypeError):
        devp2p.rlpx.udp.encode_ping(
            version='4',
            from_endpoint=[ip, 2, 3],
            to_endpoint=[ip, 2, 3],
            timestamp_expiration=timestamp_expiration,
        )

    # expiration needs to be a number and in the future
    with pytest.raises(TypeError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[ip, 2, 3],
            to_endpoint=[ip, 2, 3],
            timestamp_expiration='',
        )

    with pytest.raises(TypeError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[ip, 2, 3],
            to_endpoint=[ip, 2, 3],
            timestamp_expiration='{}'.format(time.time()),
        )

    with pytest.raises(ValueError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[ip, 2, 3],
            to_endpoint=[ip, 2, 3],
            timestamp_expiration=-1,
        )

    with pytest.raises(ValueError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[ip, 2, 3],
            to_endpoint=[ip, 2, 3],
            timestamp_expiration=0,
        )

    with pytest.raises(ValueError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[ip, 2, 3],
            to_endpoint=[ip, 2, 3],
            timestamp_expiration=int(time.time()) - 1,
        )

    # ip needs to be ipaddress
    with pytest.raises(TypeError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[1, 2, 3],
            to_endpoint=[ip, 2, 3],
            timestamp_expiration=timestamp_expiration,
        )

    with pytest.raises(TypeError):
        devp2p.rlpx.udp.encode_ping(
            version=4,
            from_endpoint=[ip, 2, 3],
            to_endpoint=[1, 2, 3],
            timestamp_expiration=timestamp_expiration,
        )


def test_ping():
    timestamp_expiration = devp2p.rlpx.udp.timeout()
    version = 4
    from_endpoint = [
        ipaddress.ip_address(u'127.0.0.1'),
        30303,
        42,
    ]
    to_endpoint = [
        ipaddress.ip_address(u'177.135.94.52'),
        8000,
        7000,
    ]

    ping_encoded = devp2p.rlpx.udp.encode_ping(
        version=version,
        from_endpoint=from_endpoint,
        to_endpoint=to_endpoint,
        timestamp_expiration=timestamp_expiration,
    )
    assert ping_encoded

    ping_back = devp2p.rlpx.udp.decode_ping(ping_encoded)

    # ping = [version, from_endpoint, to_endpoint, timestamp_expiration]
    # assert ping == ping_back
    assert ping_back[0] == version

    assert_endpoint(ping_back[1], from_endpoint)
    assert_endpoint(ping_back[2], to_endpoint)

    assert ping_back[3] == timestamp_expiration


def test_pong_echo_unicode():
    timestamp_expiration = devp2p.rlpx.udp.timeout()
    to_endpoint = [
        ipaddress.ip_address(u'177.135.94.52'),
        8000,
        7000,
    ]
    echo = b'¡½¾¼ªÆ«»æßðđħ®↓³£¢{'

    pong_encoded = devp2p.rlpx.udp.encode_pong(
        to_endpoint=to_endpoint,
        echo=echo,
        timestamp_expiration=timestamp_expiration,
    )

    pong_back = devp2p.rlpx.udp.decode_pong(pong_encoded)

    # pong = [to_endpoint, echo, timestamp_expiration]
    # assert pong == pong_back
    assert_endpoint(pong_back[0], to_endpoint)

    assert pong_back[1] == echo
    assert pong_back[2] == timestamp_expiration


def test_pong_echo_empty():
    timestamp_expiration = devp2p.rlpx.udp.timeout()
    to_endpoint = [
        ipaddress.ip_address(u'177.135.94.52'),
        8000,
        7000,
    ]
    echo = b''

    pong_encoded = devp2p.rlpx.udp.encode_pong(
        to_endpoint=to_endpoint,
        echo=echo,
        timestamp_expiration=timestamp_expiration,
    )

    pong_back = devp2p.rlpx.udp.decode_pong(pong_encoded)

    # pong = [to_endpoint, echo, timestamp_expiration]
    # assert pong == pong_back  # this will compare the containers too, we just want to compare the items
    assert_endpoint(pong_back[0], to_endpoint)

    assert pong_back[1] == echo
    assert pong_back[2] == timestamp_expiration


def test_find_neighbours_validate_type_key():
    timestamp_expiration = devp2p.rlpx.udp.timeout()

    with pytest.raises(TypeError):
        devp2p.rlpx.udp.encode_find_neighbours(None, timestamp_expiration)

    with pytest.raises(TypeError):
        devp2p.rlpx.udp.encode_find_neighbours([], timestamp_expiration)

    with pytest.raises(ValueError):
        devp2p.rlpx.udp.encode_find_neighbours('', timestamp_expiration)

    with pytest.raises(ValueError):
        devp2p.rlpx.udp.encode_find_neighbours('a' * (devp2p.rlpx.udp.PUBKEY_LENGTH + 1), timestamp_expiration)


def test_find_neighbours_validate_value_key():
    timestamp_expiration = devp2p.rlpx.udp.timeout()
    large_key = '1' * (devp2p.rlpx.udp.PUBKEY_LENGTH + 1)

    with pytest.raises(ValueError):
        devp2p.rlpx.udp.encode_find_neighbours(large_key, timestamp_expiration)


def test_find_neighbours():
    timestamp_expiration = devp2p.rlpx.udp.timeout()

    find_neighbours = (OTHER_PUBLIC_KEY, timestamp_expiration)
    find_neighbours_encoded = devp2p.rlpx.udp.encode_find_neighbours(
        target=OTHER_PUBLIC_KEY,
        timestamp_expiration=timestamp_expiration,
    )
    find_neighbours_back = devp2p.rlpx.udp.decode_find_neighbours(find_neighbours_encoded)

    assert find_neighbours == find_neighbours_back
    assert find_neighbours_back[0] == OTHER_PUBLIC_KEY
    assert find_neighbours_back[1] == timestamp_expiration


def test_packing_validate_value():
    with pytest.raises(TypeError):
        # the type_ is an integer
        devp2p.rlpx.udp.pack(PRIVATE_KEY, [], '')

    with pytest.raises(TypeError):
        # the privkey is not a list
        devp2p.rlpx.udp.pack([], devp2p.rlpx.udp.RLPX_PING, '')


def test_packing():
    payload_data = [
        [],
        [1, 2, 3],
        [[1, 2], 3],
        [1, [2], 3],
        [1, 'æßÐª/?€', 3],
    ]

    payload_expected = [
        [],
        ['\x01', '\x02', '\x03'],
        [['\x01', '\x02'], '\x03'],
        ['\x01', ['\x02'], '\x03'],
        ['\x01', 'æßÐª/?€', '\x03'],
    ]

    command_ids = [
        devp2p.rlpx.udp.RLPX_PING,
        devp2p.rlpx.udp.RLPX_PONG,
        devp2p.rlpx.udp.RLPX_FIND_NEIGHBOURS,
        devp2p.rlpx.udp.RLPX_NEIGHBOURS,
    ]

    for (payload, expected), type_ in product(zip(payload_data, payload_expected), command_ids):
        packet = devp2p.rlpx.udp.pack(PRIVATE_KEY, type_, payload)
        remote_key_back, type_back, payload_back, mdc = devp2p.rlpx.udp.unpack_and_verify(packet)

        assert len(remote_key_back) == devp2p.rlpx.udp.PUBKEY_LENGTH
        # assert remote_key_back == PUBLIC_KEY
        assert type_ == type_back
        assert expected == payload_back
