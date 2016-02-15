# -*- coding: utf8 -*-
"""
# Node Discovery Protocol

**Node**: an entity on the network
**Node ID**: 512 bit public key of node

The Node Discovery protocol provides a way to find RLPx nodes
that can be connected to. It uses a Kademlia-like protocol to maintain a
distributed database of the IDs and endpoints of all listening nodes.

Each node keeps a node table as described in the Kademlia paper
[[Maymounkov, Mazières 2002][kad-paper]]. The node table is configured
with a bucket size of 16 (denoted `k` in Kademlia), concurrency of 3
(denoted `α` in Kademlia), and 8 bits per hop (denoted `b` in
Kademlia) for routing. The eviction check interval is 75 milliseconds,
and the idle bucket-refresh interval is
3600 seconds.

In order to maintain a well-formed network, RLPx nodes should try to connect
to an unspecified number of close nodes. To increase resilience against Sybil attacks,
nodes should also connect to randomly chosen, non-close nodes.

Each node runs the UDP-based RPC protocol defined below. The
`FIND_DATA` and `STORE` requests from the Kademlia paper are not part
of the protocol since the Node Discovery Protocol does not provide DHT
functionality.

[kad-paper]: http://www.cs.rice.edu/Conferences/IPTPS02/109.pdf

## Joining the network

When joining the network, fills its node table by perfoming a
recursive Find Node operation with its own ID as the `Target`. The
initial Find Node request is sent to one or more bootstrap nodes.

## RPC Protocol

RLPx nodes that want to accept incoming connections should listen on
the same port number for UDP packets (Node Discovery Protocol) and
TCP connections (RLPx protocol).

All requests time out after are 300ms. Requests are not re-sent.

"""
from socket import AF_INET, AF_INET6

import gevent
import gevent.socket
import ipaddress
import rlp
import slogging
from gevent.server import DatagramServer

import rlpx.udp
from devp2p import crypto
from devp2p import kademlia
from devp2p import utils
from service import BaseService

log = slogging.get_logger('p2p.discovery')

RLPX_ENCODERS = {
    'cmd_id': chr,
    'expiration': rlp.sedes.big_endian_int.serialize,
}

# maps the type of the packet to the method in the class that implements the
# protocol
REV_CMD_ID_MAP = {
    rlpx.udp.RLPX_PING: 'ping',
    rlpx.udp.RLPX_PONG: 'pong',
    rlpx.udp.RLPX_FIND_NEIGHBOURS: 'find_node',
    rlpx.udp.RLPX_NEIGHBOURS: 'neighbours',
}

RLPX_DECODERS = {
    rlpx.udp.RLPX_PING: rlpx.udp.decode_ping,
    rlpx.udp.RLPX_PONG: rlpx.udp.decode_pong,
    rlpx.udp.RLPX_FIND_NEIGHBOURS: rlpx.udp.decode_find_neighbours,
    rlpx.udp.RLPX_NEIGHBOURS: rlpx.udp.decode_neighbours,
    'cmd_id': ord,
}


class Address(object):
    """
    Extend later, but make sure we deal with objects Multiaddress.

    https://github.com/haypo/python-ipy
    """

    def __init__(self, ip, udp_port, tcp_port=0):
        if not isinstance(udp_port, (int, long)):
            raise TypeError('udp_port should be a int or long, got: {}'.format(repr(udp_port)))

        if not isinstance(tcp_port, (int, long)):
            raise TypeError('tcp_port should be a int or long, got: {}'.format(repr(tcp_port)))

        if udp_port < 0 or udp_port > 65535:
            raise ValueError('udp_port need to be in the range (0, 65535]')

        if tcp_port < 0 or tcp_port > 65535:
            raise ValueError('tcp_port need to be in the range (0, 65535]')

        tcp_port = tcp_port or udp_port
        self.udp_port = udp_port
        self.tcp_port = tcp_port

        try:
            self._ip = ipaddress.ip_address(ip)
        except ValueError:
            # Possibly a hostname - try resolving it
            # We only want v4 or v6 addresses
            # see https://docs.python.org/2/library/socket.html#socket.getaddrinfo
            ips = [
                unicode(ai[4][0])
                for ai in gevent.socket.getaddrinfo(ip, None)
                if ai[0] == AF_INET or ai[0] == AF_INET6 and ai[4][3] == 0
            ]
            # Arbitrarily choose the first of the resolved addresses
            self._ip = ipaddress.ip_address(ips[0])

    @property
    def ip(self):
        return str(self._ip)

    def update(self, addr):
        if not self.tcp_port:
            self.tcp_port = addr.tcp_port

    def __eq__(self, other):
        return (self.ip, self.udp_port) == (other.ip, other.udp_port)

    def __repr__(self):
        return 'Address(%s, %s, %s)' % (self.ip, self.udp_port, self.tcp_port)

    def to_dict(self):
        return dict(ip=self.ip, udp_port=self.udp_port, tcp_port=self.tcp_port)

    def neighbours_structure(self):
        return (self._ip, self.udp_port, self.tcp_port)


class Node(kademlia.Node):

    def __init__(self, pubkey, address=None):
        kademlia.Node.__init__(self, pubkey)
        assert address is None or isinstance(address, Address)
        self.address = address
        self.reputation = 0
        self.rlpx_version = 0

    @classmethod
    def from_uri(cls, uri):
        ip, port, pubkey = utils.host_port_pubkey_from_uri(uri)
        return cls(pubkey, Address(ip, int(port)))

    def to_uri(self):
        return utils.host_port_pubkey_to_uri(self.address.ip, self.address.udp_port, self.pubkey)


class DiscoveryProtocolTransport(object):

    def send(self, address, message):
        assert isinstance(address, Address)

    def receive(self, address, message):
        assert isinstance(address, Address)


class KademliaProtocolAdapter(kademlia.KademliaProtocol):
    pass


class DiscoveryProtocol(kademlia.WireInterface):

    """
    ## Packet Data
    All packets contain an `Expiration` date to guard against replay attacks.
    The date should be interpreted as a UNIX timestamp.
    The receiver should discard any packet whose `Expiration` value is in the past.
    """
    version = 4

    def __init__(self, app, transport):
        listen_host = app.config['discovery']['listen_host']
        udp_port = app.config['discovery']['listen_port']
        tcp_port = app.config['p2p']['listen_port']

        private_key = app.config['node']['privkey_hex'].decode('hex')
        public_key = crypto.privtopub(private_key)
        enode = utils.host_port_pubkey_to_uri(listen_host, udp_port, public_key)

        self.app = app
        self.transport = transport
        self.privkey = private_key
        self.pubkey = public_key
        self.listen_host = listen_host
        self.ipaddress = ipaddress.ip_address(unicode(listen_host))
        self.udp_port = udp_port
        self.tcp_port = tcp_port

        self.nodes = dict()   # nodeid->Node,  fixme should be loaded
        self.this_node = Node(self.pubkey, self.transport.address)
        self.kademlia = KademliaProtocolAdapter(self.this_node, wire=self)

        log.info('starting discovery proto', this_enode=enode)

    def get_node(self, nodeid, address=None):
        "return node or create new, update address if supplied"
        assert isinstance(nodeid, str)
        assert len(nodeid) == rlpx.udp.PUBKEY_LENGTH
        assert address or (nodeid in self.nodes)
        if nodeid not in self.nodes:
            self.nodes[nodeid] = Node(nodeid, address)
        node = self.nodes[nodeid]
        if address:
            assert isinstance(address, Address)
            node.address = address
        assert node.address
        return node

    def receive(self, address, message):
        """ Parses the RLPx packet and do the dispatch """
        log.debug('<<< message', address=address)
        assert isinstance(address, Address)

        parsed_packet = rlpx.udp.unpack_and_verify(message)
        if parsed_packet is None:
            return

        nodeid, type_, payload, mdc = parsed_packet

        if type_ not in REV_CMD_ID_MAP:
            log.warn('Unknow message type {cmd}'.format(cmd=type_))
            return

        cmd_decoder = RLPX_DECODERS[type_]
        data = cmd_decoder(payload)

        if data is None:
            return

        if nodeid not in self.nodes:  # set intermediary address
            self.get_node(nodeid, address)

        cmd = getattr(self, 'recv_' + REV_CMD_ID_MAP[type_])
        cmd(nodeid, data, mdc)

    def send(self, node, message):
        assert node.address
        log.debug('>>> message', address=node.address)
        self.transport.send(node.address, message)

    def send_ping(self, node):
        """ Send a ping packet. """

        if not isinstance(node, Node):
            raise TypeError('node should be of type Node')

        if node == self.this_node:
            raise ValueError('node should not be self')

        from_ = [self.ipaddress, self.udp_port, self.tcp_port]

        to_address = node.address
        to = [to_address._ip, to_address.udp_port, to_address.tcp_port]

        payload = rlpx.udp.encode_ping(self.version, from_, to, rlpx.udp.timeout())
        message = rlpx.udp.pack(self.privkey, rlpx.udp.RLPX_PING, payload)

        log.debug('>>> ping', remoteid=node)  # log the ping before calling send() to keep the order of logging coherent
        self.send(node, message)

        return message[rlpx.udp.MDC_SLICE]

    def send_pong(self, node, token):
        """ Pong is the reply to a Ping packet. """

        if not isinstance(node, Node):
            raise TypeError('node should be of type Node')

        if node == self.this_node:
            raise ValueError('node should not be self')

        to_address = node.address
        to_node = [to_address._ip, to_address.udp_port, to_address.tcp_port]
        payload = rlpx.udp.encode_pong(to_node, token, rlpx.udp.timeout())
        message = rlpx.udp.pack(self.privkey, rlpx.udp.RLPX_PONG, payload)
        self.send(node, message)

        log.debug('>>> pong', remoteid=node)

    def send_find_node(self, node, target):
        """ Find Node packets are sent to locate nodes close to a given target
        ID.  The receiver should reply with a Neighbors packet containing the
        `k` nodes closest to target that it knows about.
        """
        if not isinstance(target, (int, long)):
            raise TypeError('target must be int or long')

        if node == self.this_node:
            raise ValueError('node should not be self')

        # the rlpx library receives/returns keys as bytes
        target_bytes = utils.int_to_big_endian(target).rjust(rlpx.udp.PUBKEY_LENGTH, '\0')

        payload = rlpx.udp.encode_find_neighbours(target_bytes, rlpx.udp.timeout())
        message = rlpx.udp.pack(self.privkey, rlpx.udp.RLPX_FIND_NEIGHBOURS, payload)
        self.send(node, message)

        log.debug('>>> find_node', remoteid=node)

    def send_neighbours(self, node, neighbours_list):
        """ Neighbors is the reply to Find Node. It contains up to `k` nodes
        that the sender knows which are closest to the requested `Target`.
        """
        if not isinstance(neighbours_list, list):
            raise TypeError('neighbours must be a list')

        if len(neighbours_list) == 0:
            raise ValueError('neighbours must not be empty')

        if not all(isinstance(entry, Node) for entry in neighbours_list):
            raise ValueError('All neighbours must not be of type Node')

        node_list = []
        for neighbour in neighbours_list:
            node_data = list(neighbour.address.neighbours_structure()) + [neighbour.pubkey]
            node_list.append(node_data)

        # the neighbours structure is composed of [list<nodes>, timestamp],
        # this is the break down of the memory needed to encode it all:
        #
        # [16 bytes] for the ipv6 address, or 4 bytes for ipv4
        # [ 2 bytes] for each port number
        # [64 bytes] for the public key / nodeid
        # [ 4 bytes] for the timestamp
        #
        # The node data without RLP encoding is 84 bytes
        # For the RLP encoding we need +5 bytes for the length
        #
        # The timestamp will use 5 bytes encoded
        #
        # So, to respect the spec and stay bellow 1280 bytes we can have at
        # most 15 entries [(1280 - 5) / 84]
        #
        # XXX: We need to account for the encapsulation overhead too
        node_list = node_list[:12]

        payload = rlpx.udp.encode_neighbours(node_list, rlpx.udp.timeout())
        message = rlpx.udp.pack(self.privkey, rlpx.udp.RLPX_NEIGHBOURS, payload)
        self.send(node, message)

        log.debug('>>> neighbours', remoteid=node, count=len(node_list))

    def recv_ping(self, nodeid, payload_decoded, mdc):
        version, from_, to, __ = payload_decoded

        if version != self.version:
            log.warn('incompatible version received')
            return

        try:
            from_ip, from_udp_port_decoded, from_tcp_port_decoded = from_
            to_ip, to_udp_port_decoded, to_tcp_port_decoded = to
        except ValueError:
            log.error("couldn't unpack values")
            return

        # Some clients seem to double encode the data
        try:
            remote_address = Address(from_ip, from_udp_port_decoded, from_tcp_port_decoded)
        except TypeError as e:
            log.warn("Ping.from: Peer sent data with the wrong encoding", e=e)
            log.debug('', payload=payload_decoded)
            return
        except ValueError as e:
            log.warn("PING.from: invalid value", e=e)
            log.debug('', payload=payload_decoded)
            return

        # TODO: validate my_address
        try:
            my_address = Address(to_ip, to_udp_port_decoded, to_tcp_port_decoded)  # noqa F841
        except TypeError as e:
            log.warn("Ping.to: Peer sent data with the wrong encoding", e=e)
            log.debug('', payload=payload_decoded)
            return
        except ValueError as e:
            log.warn("PING.to: invalid value", e=e)
            log.debug('', payload=payload_decoded)
            return

        node = self.get_node(nodeid)
        log.debug('<<< ping', node=node)

        node.address.update(remote_address)
        self.kademlia.recv_ping(node, echo=mdc)

    def recv_pong(self, nodeid,  payload, mdc):
        try:
            to, echo, __ = payload
        except ValueError:
            # XXX: remove nodeid from kademlia?
            log.warn("couldn't unpack values")
            return

        try:
            to_ip, to_udp_port_decoded, to_tcp_port_decoded = to
        except ValueError:
            log.error("couldn't unpack values")
            return

        try:
            my_address = Address(to_ip, to_udp_port_decoded, to_tcp_port_decoded)  # noqa F841
        except TypeError as e:
            log.warn("Ping.to: Peer sent data with the wrong encoding", e=e)
            log.debug('', payload=payload)
            return
        except ValueError as e:
            log.warn("PING.to: invalid value", e=e)
            log.debug('', payload=payload)
            return

        if nodeid in self.nodes:
            node = self.get_node(nodeid)
            self.kademlia.recv_pong(node, echo)
        else:
            log.warn('<<< unexpected pong from unkown node', node=node)

        log.debug('<<< pong', node=node)

    def recv_find_node(self, nodeid, payload, mdc):
        target, __ = payload

        node = self.get_node(nodeid)
        try:
            target_int = utils.big_endian_to_int(target)
            self.kademlia.recv_find_node(node, target_int)
        except AssertionError:
            log.exception("Can't add node: invalid data")
            return

        log.debug('<<< find_node', node=node)

    def recv_neighbours(self, nodeid, payload_decoded, mdc):
        neighbours_list, __ = payload_decoded
        node = self.get_node(nodeid)

        node_list = []
        for neighbour in neighbours_list:
            try:
                remote_ip, remote_udp_port_decoded, remote_tcp_port_decoded, remote_node_id = neighbour
            except ValueError:
                log.warn("couldn't unpack values")
                return

            try:
                remote_address = Address(remote_ip, remote_udp_port_decoded, remote_tcp_port_decoded)
            except TypeError as e:
                log.warn("Neighbours: Peer sent data with the wrong encoding", e=e)
                log.debug('', payload=payload_decoded)
                return
            except ValueError:
                log.warn("Neighbours: Received an invalid value", e=e)
                log.debug('', payload=payload_decoded)
                return

            remote_node = self.get_node(remote_node_id, remote_address)
            node_list.append(remote_node)

        log.debug('<<< neighbours', node=node, count=len(node_list), neighbours=node_list)
        self.kademlia.recv_neighbours(node, node_list)


class NodeDiscovery(BaseService, DiscoveryProtocolTransport):

    """
    Persist the list of known nodes with their reputation
    """

    name = 'discovery'
    server = None  # will be set to DatagramServer
    default_config = dict(
        discovery=dict(
            listen_port=30303,
            listen_host='0.0.0.0',
        ),
        node=dict(privkey_hex=''))

    def __init__(self, app):
        BaseService.__init__(self, app)
        log.info('NodeDiscovery init')
        # man setsockopt
        self.protocol = DiscoveryProtocol(app=self.app, transport=self)

    @property
    def address(self):
        ip = self.app.config['discovery']['listen_host']
        port = self.app.config['discovery']['listen_port']
        return Address(ip, port)

    def send(self, address, message):
        assert isinstance(address, Address)
        log.debug('sending', size=len(message), to=address)
        try:
            self.server.sendto(message, (address.ip, address.udp_port))
        except gevent.socket.error as e:
            log.critical('udp write error', errno=e.errno, reason=e.strerror)
            log.critical('waiting for recovery')
            gevent.sleep(5.)

    def receive(self, address, message):
        assert isinstance(address, Address)
        self.protocol.receive(address, message)

    def _handle_packet(self, message, ip_port):
        log.debug('handling packet', address=ip_port, size=len(message))
        assert len(ip_port) == 2
        address = Address(ip=ip_port[0], udp_port=ip_port[1])
        self.receive(address, message)

    def start(self):
        log.info('starting discovery')
        # start a listening server
        ip = self.app.config['discovery']['listen_host']
        port = self.app.config['discovery']['listen_port']
        log.info('starting listener', port=port, host=ip)
        self.server = DatagramServer((ip, port), handle=self._handle_packet)
        self.server.start()
        super(NodeDiscovery, self).start()

        # bootstap
        nodes = [Node.from_uri(x) for x in self.app.config['discovery']['bootstrap_nodes']]
        if nodes:
            self.protocol.kademlia.bootstrap(nodes)

    def _run(self):
        log.debug('_run called')
        evt = gevent.event.Event()
        evt.wait()

    def stop(self):
        log.info('stopping discovery')
        self.server.stop()
        super(NodeDiscovery, self).stop()
