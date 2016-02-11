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
import time
from socket import AF_INET, AF_INET6

import gevent
import gevent.socket
import ipaddress
import rlp
import slogging
from gevent.server import DatagramServer

import rlpx
from devp2p import crypto
from devp2p import kademlia
from devp2p import utils
from service import BaseService

log = slogging.get_logger('p2p.discovery')

RLPX_ENCODERS = {
    'cmd_id': chr,
    'expiration': rlp.sedes.big_endian_int.serialize,
}

REV_CMD_ID_MAP = {
    rlpx.RLPX_PING: 'ping',
    rlpx.RLPX_PONG: 'pong',
    rlpx.RLPX_FIND_NEIGHBOURS: 'find_node',
    rlpx.RLPX_NEIGHBOURS: 'neighbours',
}

RLPX_DECODERS = {
    rlpx.RLPX_PING: rlpx.rlpx_ping,
    rlpx.RLPX_PONG: rlpx.rlpx_pong,
    rlpx.RLPX_FIND_NEIGHBOURS: rlpx.rlpx_find_neighbours,
    rlpx.RLPX_NEIGHBOURS: rlpx.rlpx_neighbours,
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
            raise TypeError('tcp_port should be a int or long, got: {}'.format(repr(tdp_port)))

        if udp_port < 0:
            raise ValueError('up_port cannot be negative')

        if tcp_port < 0:
            raise ValueError('up_port cannot be negative')

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
                if ai[0] == AF_INET
                or (ai[0] == AF_INET6 and ai[4][3] == 0)
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
        return 'Address(%s:%s)' % (self.ip, self.udp_port)

    def to_dict(self):
        return dict(ip=self.ip, udp_port=self.udp_port, tcp_port=self.tcp_port)

    def to_binary(self):
        """
        struct Endpoint
            unsigned address; // BE encoded 32-bit or 128-bit unsigned (layer3 address; size determins ipv4 vs ipv6)
            unsigned udpPort; // BE encoded 16-bit unsigned
            unsigned tcpPort; // BE encoded 16-bit unsigned
        """
        return list((self._ip.packed, enc_port(self.udp_port), enc_port(self.tcp_port)))
    to_endpoint = to_binary


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
        self.app = app
        self.transport = transport
        self.privkey = app.config['node']['privkey_hex'].decode('hex')
        self.pubkey = crypto.privtopub(self.privkey)
        self.nodes = dict()   # nodeid->Node,  fixme should be loaded
        self.this_node = Node(self.pubkey, self.transport.address)
        self.kademlia = KademliaProtocolAdapter(self.this_node, wire=self)
        this_enode = utils.host_port_pubkey_to_uri(self.app.config['discovery']['listen_host'],
                                                   self.app.config['discovery']['listen_port'],
                                                   self.pubkey)
        log.info('starting discovery proto', this_enode=this_enode)

    def get_node(self, nodeid, address=None):
        "return node or create new, update address if supplied"
        assert isinstance(nodeid, str)
        assert len(nodeid) == rlpx.PUBKEY_LENGTH
        assert address or (nodeid in self.nodes)
        if nodeid not in self.nodes:
            self.nodes[nodeid] = Node(nodeid, address)
        node = self.nodes[nodeid]
        if address:
            assert isinstance(address, Address)
            node.address = address
        assert node.address
        return node

    def sign(self, msg):
        """
        signature: sign(privkey, sha3(packet-type || packet-data))
        signature: sign(privkey, sha3(pubkey || packet-type || packet-data))
            // implementation w/MCD
        """
        msg = crypto.sha3(msg)
        return crypto.sign(msg, self.privkey)

    def pack(self, cmd_id, payload):
        """
        UDP packets are structured as follows:

        hash || signature || packet-type || packet-data
        packet-type: single byte < 2**7 // valid values are [1,4]
        packet-data: RLP encoded list. Packet properties are serialized in the order in
                    which they're defined. See packet-data below.

        Offset  |
        0       | MDC       | Ensures integrity of packet,
        65      | signature | Ensures authenticity of sender, `SIGN(sender-privkey, MDC)`
        97      | type      | Single byte in range [1, 4] that determines the structure of Data
        98      | data      | RLP encoded, see section Packet Data

        The packets are signed and authenticated. The sender's Node ID is determined by
        recovering the public key from the signature.

            sender-pubkey = ECRECOVER(Signature)

        The integrity of the packet can then be verified by computing the
        expected MDC of the packet as:

            MDC = SHA3(sender-pubkey || type || data)

        As an optimization, implementations may look up the public key by
        the UDP sending address and compute MDC before recovering the sender ID.
        If the MDC values do not match, the packet can be dropped.
        """
        assert cmd_id in REV_CMD_ID_MAP
        assert isinstance(payload, list)

        cmd_id = RLPX_ENCODERS['cmd_id'](cmd_id)
        expiration = RLPX_ENCODERS['expiration'](int(time.time() + rlpx.EXPIRATION_SECONDS))
        encoded_data = rlp.encode(payload + [expiration])
        signed_data = crypto.sha3(cmd_id + encoded_data)
        signature = crypto.sign(signed_data, self.privkey)
        # assert crypto.verify(self.pubkey, signature, signed_data)
        # assert self.pubkey == crypto.ecdsa_recover(signed_data, signature)
        # assert crypto.verify(self.pubkey, signature, signed_data)
        assert len(signature) == 65
        mdc = crypto.sha3(signature + cmd_id + encoded_data)
        assert len(mdc) == 32
        return mdc + signature + cmd_id + encoded_data

    def receive(self, address, message):
        """ Parses the RLPx packet and do the dispatch """
        log.debug('<<< message', address=address)
        assert isinstance(address, Address)

        parsed_packet = rlpx.rlpx_unpack(message)
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
        cmd(nodeid, payload, mdc)

    def send(self, node, message):
        assert node.address
        log.debug('>>> message', address=node.address)
        self.transport.send(node.address, message)

    def send_ping(self, node):
        assert isinstance(node, type(self.this_node)) and node != self.this_node
        log.debug('>>> ping', remoteid=node)
        version = rlp.sedes.big_endian_int.serialize(self.version)
        ip = self.app.config['discovery']['listen_host']
        udp_port = self.app.config['discovery']['listen_port']
        tcp_port = self.app.config['p2p']['listen_port']
        payload = [version,
                   Address(ip, udp_port, tcp_port).to_endpoint(),
                   node.address.to_endpoint()]
        assert len(payload) == 3
        message = self.pack(rlpx.RLPX_PING, payload)
        self.send(node, message)
        return message[:32]  # return the MDC to identify pongs

    def recv_ping(self, nodeid, payload_decoded, mdc):
        __, from_, to, __ = payload_decoded

        ip, udp_port_decoded, tcp_port_decoded = from_
        ip, udp_port_decoded, tcp_port_decoded = to

        # Some clients seem to double encode the data
        try:
            remote_address = Address(ip, udp_port_decoded, tcp_port_decoded)
        except TypeError as e:
            log.warn("Peer sent data with the wrong encoding", e=e)
            log.debug('', payload=payload_decoded)
            return
        except ValueError as e:
            log.warn("PING.from: invalid value", e=e)
            log.debug('', payload=payload_decoded)
            return

        # TODO: validate my_address
        try:
            my_address = Address(ip, udp_port_decoded, tcp_port_decoded)
        except TypeError as e:
            log.warn("Peer sent data with the wrong encoding", e=e)
            log.debug('', payload=payload_decoded)
            return
        except ValueError as e:
            log.warn("PING.to: invalid value", e=e)
            log.debug('', payload=payload_decoded)
            return

        node = self.get_node(nodeid)
        node.address.update(remote_address)
        self.kademlia.recv_ping(node, echo=mdc)

        log.debug('<<< ping', node=node)

    def recv_pong(self, nodeid,  payload, mdc):
        __, echo, __ = payload

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
            self.kademlia.recv_find_node(node, target)
        except AssertionError:
            log.warn('Cand add node: invalid data')
            return

        log.debug('<<< find_node', node=node)

    def recv_neighbours(self, nodeid, payload_decoded, mdc):
        neighbours_list, __ = payload_decoded

        node_list = []

        for neighbour in neighbours_list:
            ip, udp_port_decoded, tcp_port_decoded, node_id = neighbour

            try:
                remote_address = Address(ip, udp_port_decoded, tcp_port_decoded)
            except TypeError as e:
                log.warn("Peer sent data with the wrong encoding", e=e)
                log.debug('', payload=payload_decoded)
                return
            except ValueError:
                log.warn("Received an invalid value", e=e)
                log.debug('', payload=payload_decoded)
                return

            remote_node = self.get_node(nodeid, remote_address)
            node_list.append(remote_node)

        node = self.get_node(nodeid)
        self.kademlia.recv_neighbours(node, node_list)

        log.debug('<<< neigbours', node=node, count=len(neighbours))

    def send_pong(self, node, token):
        """
        ### Pong (type 0x02)

        Pong is the reply to a Ping packet.

        Pong packet-type: 0x02
        struct Pong                 <= 66 bytes
        {
            Endpoint to;
            h256 echo;
            unsigned expiration;
        };
        """
        log.debug('>>> pong', remoteid=node)
        payload = [node.address.to_endpoint(), token]
        assert len(payload[0][0]) in (4, 16), payload
        message = self.pack(rlpx.RLPX_PONG, payload)
        self.send(node, message)

    def send_find_node(self, node, target_node_id):
        """
        ### Find Node (type 0x03)

        Find Node packets are sent to locate nodes close to a given target ID.
        The receiver should reply with a Neighbors packet containing the `k`
        nodes closest to target that it knows about.

        FindNode packet-type: 0x03
        struct FindNode             <= 76 bytes
        {
            NodeId target; // Id of a node. The responding node will send back nodes closest to the target.
            unsigned expiration;
        };
        """
        assert isinstance(target_node_id, long)
        target_node_id = utils.int_to_big_endian(target_node_id).rjust(rlpx.PUBKEY_LENGTH, '\0')
        assert len(target_node_id) == rlpx.PUBKEY_LENGTH
        log.debug('>>> find_node', remoteid=node)
        message = self.pack(rlpx.RLPX_FIND_NEIGHBOURS, [target_node_id])
        self.send(node, message)

    def send_neighbours(self, node, neighbours):
        """
        ### Neighbors (type 0x04)

        Neighbors is the reply to Find Node. It contains up to `k` nodes that
        the sender knows which are closest to the requested `Target`.

        Neighbors packet-type: 0x04
        struct Neighbours           <= 1423
        {
            list nodes: struct Neighbour    <= 88: 1411; 76: 1219
            {
                inline Endpoint endpoint;
                NodeId node;
            };

            unsigned expiration;
        };
        """
        assert isinstance(neighbours, list)
        assert not neighbours or isinstance(neighbours[0], Node)
        nodes = []
        for n in neighbours:
            l = n.address.to_endpoint() + [n.pubkey]
            nodes.append(l)
        log.debug('>>> neighbours', remoteid=node, count=len(nodes))
        # FIXME: don't brake udp packet size / chunk message / also when receiving
        message = self.pack(rlpx.RLPX_NEIGHBOURS, [nodes][:12])  # FIXME
        self.send(node, message)


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

    # def _send(self, address, message):
    #     assert isinstance(address, Address)
    #     sock = gevent.socket.socket(type=gevent.socket.SOCK_DGRAM)
    # sock.bind(('0.0.0.0', self.address.port))  # send from our recv port
    #     sock.connect((address.ip, address.port))
    #     log.debug('sending', size=len(message), to=address)
    #     sock.send(message)

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
