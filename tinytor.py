#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""TinyTor is a Tor client implementation."""
__author__ = "Marten4n6"
__license__ = "GPLv3"
__version__ = "0.0.1"

import hashlib
import logging
import operator
import random
import socket
import ssl
import struct
import traceback
from argparse import ArgumentParser
from base64 import b64decode, b16encode, b16decode
from os import urandom
from sys import exit
from threading import Thread
from time import time

try:
    from urllib.request import Request, urlopen
except ImportError:
    # Python2 support.
    from urllib2 import Request, urlopen

try:
    # Set up byte handling for python2.
    range = xrange
    int2byte = chr


    def indexbytes(buf, i):
        return ord(buf[i])


    def intlist2bytes(l):
        return b"".join(chr(c) for c in l)
except NameError:
    # xrange doesn't exist in python3.
    indexbytes = operator.getitem
    intlist2bytes = bytes
    int2byte = operator.methodcaller("to_bytes", 1, "big")

BANNER = """\
  _____  _               _____            
 |_   _|(_) _ __   _   _|_   _|___   _ __ 
   | |  | || '_ \ | | | | | | / _ \ | '__|
   | |  | || | | || |_| | | || (_) || |    @%s (v%s)
   |_|  |_||_| |_| \__, | |_| \___/ |_|    GPLv3 licensed
                   |___/                  
""" % (__author__, __version__)

# Logging
logging.basicConfig(format="[%(levelname)s] %(filename)s - %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


class DirectoryAuthority:
    """This class represents a directory authority."""

    def __init__(self, name, ip, dir_port, tor_port):
        self.name = name
        self.ip = ip
        self.dir_port = dir_port
        self.tor_port = tor_port

    def get_consensus_url(self):
        """
        :return: The URL to directory authority's consensus.
        :rtype: str
        """
        return "http://%s:%s/tor/status-vote/current/consensus" % (
            self.ip, self.dir_port
        )


class OnionRouter:
    """This class represents an onion router in a circuit.."""

    def __init__(self, nickname, ip, dir_port, tor_port, fingerprint, flags=None, key_ntor=None):
        """
        :type nickname: str
        :type ip: str
        :type dir_port: int
        :type tor_port: int
        :type fingerprint: str
        :type flags: list
        :type key_ntor: str
        """
        self.nickname = nickname
        self.ip = ip
        self.dir_port = dir_port
        self.tor_port = tor_port
        self.fingerprint = fingerprint
        self.flags = flags
        self.key_ntor = key_ntor

    def get_descriptor_url(self):
        """:return: The URL to the onion router's descriptor (where keys are stored)."""
        return "http://%s:%s/tor/server/fp/%s" % (self.ip, self.dir_port, self.fingerprint)

    def parse_descriptor(self):
        """Updates the onion router's keys."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0"
        }
        request = Request(url=self.get_descriptor_url(), headers=headers)
        response = urlopen(request)

        for line in response:
            line = line.decode()

            if line.startswith("ntor-onion-key "):
                self.key_ntor = line.split("ntor-onion-key")[1].strip()
                break

    def __str__(self):
        return "OnionRouter(nickname=%s, ip=%s, dir_port=%s, tor_port=%s, fingerprint=%s, flags=%s, key_ntor=%s)" % (
            self.nickname, self.ip, self.dir_port, self.tor_port, self.fingerprint, self.flags, self.key_ntor
        )


class Consensus:
    """
    Hardcoded into each Tor client is the information about 10 beefy Tor nodes run by trusted volunteers.
    These nodes have a very special role - to maintain the status of the entire Tor network.
    These nodes are known as directory authorities (DA’s).

    The status of all the Tor relays is maintained in a living document called the consensus.
    DA’s maintain this document and update it every hour by a vote.

    https://jordan-wright.com/blog/2015/05/14/how-tor-works-part-three-the-consensus/
    """

    def __init__(self):
        # Taken from: https://consensus-health.torproject.org/
        self._directory_authorities = [
            DirectoryAuthority("maatuska", "171.25.193.9", 443, 80),
            DirectoryAuthority("tor26", "86.59.21.38", 80, 443),
            DirectoryAuthority("longclaw", "199.58.81.140", 80, 443),
            DirectoryAuthority("dizum", "194.109.206.212", 80, 443),
            DirectoryAuthority("bastet", "204.13.164.118", 80, 443),
            DirectoryAuthority("gabelmoo", "131.188.40.189", 80, 443),
            DirectoryAuthority("moria1", "128.31.0.34", 9131, 9101),
            DirectoryAuthority("dannenberg", "193.23.244.244", 80, 443),
            DirectoryAuthority("faravahar", "154.35.175.225", 80, 443)
        ]
        self._parsed_consensus = []

    def get_random_directory_authority(self):
        """
        :return: A random directory authority.
        :rtype: DirectoryAuthority
        """
        return random.choice(self._directory_authorities)

    def parse_consensus(self, consensus_url, limit=200):
        """Parses the consensus document into a list of onion routers.

        :type consensus_url: str
        :type limit: int
        """
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0"
        }
        request = Request(url=consensus_url, headers=headers)
        response = urlopen(request, timeout=8)

        onion_router_amount = 1

        # This onion router will only be added if it
        # has the following flags: Fast, Running and Valid
        onion_router = None

        for line in response:
            line = line.decode()

            if line.startswith("r "):
                # This line contains an onion router.
                split_line = line.split(" ")

                nickname = split_line[1]
                identity = split_line[2]
                ip = split_line[6]
                tor_port = int(split_line[7])
                dir_port = int(split_line[8])

                # The fingerprint here is base64 encoded bytes.
                # The descriptor URL uses the base16 encoded value of these bytes.
                # Documentation for this was hard to find...
                identity += "=" * (-len(identity) % 4)
                identity = b16encode(b64decode(identity.encode())).decode()

                onion_router = OnionRouter(nickname, ip, dir_port, tor_port, identity)
            elif line.startswith("s "):
                # This line contains the onion router's flags.
                if onion_router:
                    flags = []

                    for token in line.split(" "):
                        if token == "s":
                            continue
                        flags.append(token.lower().replace("\n", "", 1))

                    if "stable" in flags and "fast" in flags and "valid" in flags and "running" in flags:
                        onion_router_amount += 1
                        onion_router.flags = flags

                        self._parsed_consensus.append(onion_router)

            if onion_router_amount >= limit:
                log.warning("Stopped after reading %s onion routers." % limit)
                break

    def get_random_guard_relay(self):
        """
        :return: A random guard relay.
        :rtype: OnionRouter
        """
        guard_relays = []

        for onion_router in self._parsed_consensus:
            if "guard" in onion_router.flags:
                guard_relays.append(onion_router)

        return random.choice(guard_relays)


class CellDestroyedReason:
    """Enum class which contains all reasons a cell can be destroyed.

    tor-spec.txt 5.4. "Tearing down circuits"
    """
    NONE = 1
    PROTOCOL = 2
    INTERNAL = 3
    REQUESTED = 4
    HIBERNATING = 5
    RESOURCE_LIMIT = 6
    CONNECTION_FAILED = 7
    ONION_ROUTER_IDENTITY = 8
    ONION_ROUTER_CONNECTION_CLOSED = 9
    FINISHED = 9
    TIMEOUT = 10
    DESTROYED = 11
    NO_SUCH_SERVICE = 12


class CommandType:
    """Enum class which contains all available command types.

    tor-spec.txt 3. "Cell Packet format"
    tor-spec.txt 6.1. "Relay cells"
    """

    # Fixed-length command values.
    PADDING = 0
    CREATE = 1
    CREATED = 2
    RELAY = 3
    DESTROY = 4
    CREATE_FAST = 5
    CREATED_FAST = 6
    NETINFO = 8
    RELAY_EARLY = 9
    CREATE2 = 10
    CREATED2 = 11

    # Variable-length command values.
    VERSIONS = 7
    VPADDING = 128
    CERTS = 129
    AUTH_CHALLENGE = 130
    AUTHENTICATE = 131

    #
    # The relay commands.
    #
    # Within a circuit, the OP and the exit node use the contents of
    # RELAY packets to tunnel end-to-end commands and TCP connections
    # ("Streams") across circuits. End-to-end commands can be initiated
    # by either edge; streams are initiated by the OP.
    #
    RELAY_BEGIN = 1
    RELAY_DATA = 2
    RELAY_END = 3
    RELAY_CONNECTED = 4
    RELAY_SENDME = 5
    RELAY_EXTEND = 6
    RELAY_EXTENDED = 7
    RELAY_TRUNCATE = 8
    RELAY_TRUNCATED = 9
    RELAY_DROP = 10
    RELAY_RESOLVE = 11
    RELAY_RESOLVED = 12
    RELAY_BEGIN_DIR = 13
    RELAY_EXTEND2 = 14
    RELAY_EXTENDED2 = 15


class Cell:
    """This class represents a cell.

    tor-spec.txt 3. "Cell Packet format"
    """

    # The length of a Tor cell, in bytes, for link protocol version v.
    # CELL_LEN(v) = 512    if v is less than 4;
    #             = 514    otherwise.
    #
    # tor-spec.txt 0.2. "Security parameters"
    CELL_SIZE = 514

    # The longest allowable cell payload, in bytes. (509)
    #
    # tor-spec.txt 0.2. "Security parameters"
    MAX_PAYLOAD_SIZE = 509

    def __init__(self, circuit_id, command, payload):
        """
        :param circuit_id: Determines which circuit, if any, the cell is associated with.
        :type circuit_id: int
        :param command: The type of command this cell is.
        :type command: int
        :param payload: This is the actual request/response data.
        """
        self.circuit_id = circuit_id
        self.command = command
        self.payload = payload

    def get_bytes(self, max_protocol_version):
        """The byte representation of this cell which can be written to a socket.

        :type max_protocol_version: int
        :rtype: bytes
        """
        # https://docs.python.org/3/library/struct.html
        payload_bytes = b""

        if self.command == CommandType.VERSIONS:
            # The payload in a VERSIONS cell is a series of big-endian two-byte integers.
            payload_bytes = struct.pack("!" + ("H" * len(self.payload)), *self.payload)
        elif self.command == CommandType.NETINFO:
            # Timestamp              [4 bytes]
            # Other OR's address     [variable]
            # Number of addresses    [1 byte]
            # This OR's addresses    [variable]
            #
            # Address format:
            # Type   (1 octet)
            # Length (1 octet)
            # Value  (variable-width)
            #
            # "Length" is the length of the Value field.
            # "Type" is one of:
            #    0x00 -- Hostname
            #    0x04 -- IPv4 address
            #    0x06 -- IPv6 address
            #    0xF0 -- Error, transient
            #    0xF1 -- Error, nontransient
            timestamp = struct.pack("!I", self.payload[0])
            other_or_address = struct.pack("!BB", 4, 4) + socket.inet_aton(self.payload[1][2])
            number_of_addresses = struct.pack("!B", 1)
            this_or_address = struct.pack("!BB", 4, 4) + socket.inet_aton(self.payload[3][2])

            payload_bytes = timestamp + other_or_address + number_of_addresses + this_or_address
        elif self.command == CommandType.CREATE2:
            # A CREATE2 cell contains:
            #     HTYPE     (Client Handshake Type)     [2 bytes]
            #     HLEN      (Client Handshake Data Len) [2 bytes]
            #     HDATA     (Client Handshake Data)     [HLEN bytes]
            payload_bytes = struct.pack("!HH", self.payload[0], self.payload[1]) + self.payload[2]
        else:
            log.error("Invalid payload format for command: " + str(self.command))

        if self.is_variable_length_command(self.command):
            if max_protocol_version < 4:
                header = struct.pack("!HBH", self.circuit_id, self.command, len(payload_bytes))
            else:
                # Link protocol 4 increases circuit ID width to 4 bytes.
                header = struct.pack("!IBH", self.circuit_id, self.command, len(payload_bytes))

            return header + payload_bytes
        else:
            # This is a fixed-length cell.
            if max_protocol_version < 4:
                payload_bytes = struct.pack("!HB509s", self.circuit_id, self.command, payload_bytes)
            else:
                # Link protocol 4 increases circuit ID width to 4 bytes.
                payload_bytes = struct.pack("!IB509s", self.circuit_id, self.command, payload_bytes)

            return payload_bytes

    @staticmethod
    def is_variable_length_command(command):
        """
        On a version 2 connection, variable-length cells are indicated by a
        command byte equal to 7 ("VERSIONS").  On a version 3 or
        higher connection, variable-length cells are indicated by a command
        byte equal to 7 ("VERSIONS"), or greater than or equal to 128.

        See tor-spec.txt 3. "Cell Packet format"

        :type command: int
        :rtype: bool
        """
        if command == CommandType.VERSIONS or command >= 128:
            return True
        else:
            return False


class Ed25519:
    """
    Python implementation of Ed25519, used by the NTOR handshake.
    "Ed25519 is both a signature scheme and a use case for Edwards-form Curve25519."

    References:
        - https://ed25519.cr.yp.to/python/ed25519.py
        - https://gitweb.torproject.org/tor.git/tree/src/test/ed25519_exts_ref.py
        - https://monero.stackexchange.com/questions/9820/recursionerror-in-ed25519-py
        - https://crypto.stackexchange.com/questions/47147/ed25519-is-a-signature-or-just-elliptic-curve
        - https://github.com/Marten4n6/TinyTor/issues/3
    """

    def __init__(self):
        self._b = 256
        self._q = 2 ** 255 - 19
        self._l = 2 ** 252 + 27742317777372353535851937790883648493

        self._d = -121665 * self._inv(121666)
        self._I = self._exp_mod(2, (self._q - 1) // 4, self._q)

        self._By = 4 * self._inv(5)
        self._Bx = self._x_recover(self._By)
        self._B = [self._Bx % self._q, self._By % self._q]

    @staticmethod
    def _hash(m):
        return hashlib.sha512(m).digest()

    def _exp_mod(self, b, e, m):
        if e == 0:
            return 1
        t = self._exp_mod(b, e // 2, m) ** 2 % m
        if e & 1:
            t = (t * b) % m
        return t

    def _inv(self, x):
        return self._exp_mod(x, self._q - 2, self._q)

    def _x_recover(self, y):
        xx = (y * y - 1) * self._inv(self._d * y * y + 1)
        x = self._exp_mod(xx, (self._q + 3) // 8, self._q)
        if (x * x - xx) % self._q != 0:
            x = (x * self._I) % self._q
        if x % 2 != 0:
            x = self._q - x
        return x

    def _edwards(self, P, Q):
        x1 = P[0]
        y1 = P[1]
        x2 = Q[0]
        y2 = Q[1]
        x3 = (x1 * y2 + x2 * y1) * self._inv(1 + self._d * x1 * x2 * y1 * y2)
        y3 = (y1 * y2 + x1 * x2) * self._inv(1 - self._d * x1 * x2 * y1 * y2)
        return [x3 % self._q, y3 % self._q]

    def _scalar_mult(self, P, e):
        if e == 0:
            return [0, 1]
        Q = self._scalar_mult(P, e // 2)
        Q = self._edwards(Q, Q)
        if e & 1:
            Q = self._edwards(Q, P)
        return Q

    def _encode_int(self, y):
        bits = [(y >> i) & 1 for i in range(self._b)]
        return b''.join([int2byte(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(self._b // 8)])

    def _encode_point(self, P):
        x = P[0]
        y = P[1]
        bits = [(y >> i) & 1 for i in range(self._b - 1)] + [x & 1]
        return b''.join([int2byte(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(self._b // 8)])

    @staticmethod
    def _bit(h, i):
        return (indexbytes(h, i // 8) >> (i % 8)) & 1

    def get_public_key(self, sk):
        h = self._hash(sk)
        a = 2 ** (self._b - 2) + sum(2 ** i * self._bit(h, i) for i in range(3, self._b - 2))
        A = self._scalar_mult(self._B, a)
        return self._encode_point(A)

    @staticmethod
    def create_secret_key():
        return urandom(32)

    def _hint(self, m):
        h = self._hash(m)
        return sum(2 ** i * self._bit(h, i) for i in range(2 * self._b))

    def signature(self, m, sk, pk):
        h = self._hash(sk)
        a = 2 ** (self._b - 2) + sum(2 ** i * self._bit(h, i) for i in range(3, self._b - 2))
        r = self._hint(intlist2bytes([indexbytes(h, j) for j in range(self._b // 8, self._b // 4)]) + m)
        R = self._scalar_mult(self._B, r)
        S = (r + self._hint(self._encode_point(R) + pk + m) * a) % self._l
        return self._encode_point(R) + self._encode_int(S)

    def _is_on_curve(self, P):
        x = P[0]
        y = P[1]
        return (-x * x + y * y - 1 - self._d * x * x * y * y) % self._q == 0

    def _decode_int(self, s):
        return sum(2 ** i * self._bit(s, i) for i in range(0, self._b))

    def _decode_point(self, s):
        y = sum(2 ** i * self._bit(s, i) for i in range(0, self._b - 1))
        x = self._x_recover(y)
        if x & 1 != self._bit(s, self._b - 1):
            x = self._q - x
        P = [x, y]
        if not self._is_on_curve(P):
            raise Exception("Decoding point that is not on curve.")

        return P

    def check_valid(self, s, m, pk):
        if len(s) != self._b // 4:
            raise Exception("Signature length is wrong.")
        if len(pk) != self._b // 8:
            raise Exception("Public-key length is wrong.")
        R = self._decode_point(s[0:self._b // 8])
        A = self._decode_point(pk)
        S = self._decode_int(s[self._b // 8:self._b // 4])
        h = self._hint(self._encode_point(R) + pk + m)
        if self._scalar_mult(self._B, S) != self._edwards(R, self._scalar_mult(A, h)):
            raise Exception("Signature does not pass verification.")


class KeyAgreementNTOR:
    """This class handles performing the NTOR handshake.

    This handshake uses a set of DH handshakes to compute a set of
    shared keys which the client knows are shared only with a particular
    server, and the server knows are shared with whomever sent the
    original handshake (or with nobody at all).  Here we use the
    "curve25519" group and representation as specified in "Curve25519:
    new Diffie-Hellman speed records" by D. J. Bernstein.

    See tor-spec.txt 5.1.4. The "ntor" handshake
    """

    PROTOCOL_ID = "ntor-curve25519-sha256-1"
    t_mac = PROTOCOL_ID + ":mac"
    t_key = PROTOCOL_ID + ":key_extract"
    t_verify = PROTOCOL_ID + ":verify"
    m_expand = PROTOCOL_ID + ":key_expand"

    def __init__(self, onion_router):
        """:type onion_router: OnionRouter"""
        self._onion_router = onion_router

        # To perform the handshake, the client needs to know an identity key
        # digest for the server, and an NTOR onion key (a curve25519 public-key) for that server.
        # Call the NTOR onion key "B".
        # The client generates a temporary keypair:
        #   x,X = KEYGEN()
        ed25519 = Ed25519()

        self.x = ed25519.create_secret_key()
        self.X = ed25519.get_public_key(self.x)

    def get_private_key(self):
        """:rtype: bytes"""
        return self.x

    def get_public_key(self):
        """:rtype: bytes"""
        return self.X


class CircuitNode:
    """Represents an onion router in the circuit."""

    ID_LENGTH = 20
    H_LENGTH = 32
    G_LENGTH = 32

    def __init__(self, circuit, onion_router):
        """
        :type circuit: Circuit
        :type onion_router: OnionRouter
        """
        self._circuit = circuit
        self._onion_router = onion_router

    def get_onion_router(self):
        """:rtype: OnionRouter"""
        return self._onion_router

    def get_circuit(self):
        """:return: The circuit this node belongs to."""
        return self._circuit

    def create_onion_skin(self):
        """
        Client-side handshake contents:
            NODEID      Server identity digest  [ID_LENGTH bytes]
            KEYID       KEYID(B)                [H_LENGTH bytes]
            CLIENT_PK   X                       [G_LENGTH bytes]

        See tor-spec.txt 5.1.4. The "ntor" handshake

        :rtype: bytes
        """
        node_id = b16decode(self.get_onion_router().fingerprint.encode())
        key_id = b64decode(self.get_onion_router().key_ntor.encode())
        client_pk = KeyAgreementNTOR(self._onion_router).get_public_key()

        # Validate length.
        if len(node_id) != self.ID_LENGTH:
            log.error("Invalid NODEID length.")
        if len(key_id) != self.H_LENGTH:
            log.error("Invalid KEYID length.")
        if len(client_pk) != self.G_LENGTH:
            log.error("Invalid CLIENT_PK length.")

        return node_id + key_id + client_pk


class Circuit:
    """Handles circuit management."""

    def __init__(self, tor_socket):
        """
        :type tor_socket: TorSocket
        """
        self._tor_socket = tor_socket
        self._circuit_id = random.randint(2 ** 31, 2 ** 31)  # C int value range (4 bytes)

    def get_circuit_id(self):
        """:rtype: int"""
        return self._circuit_id

    def create(self):
        """
        Users set up circuits incrementally, one hop at a time. To create a
        new circuit, OPs send a CREATE/CREATE2 cell to the first node, with
        the first half of an authenticated handshake; that node responds with
        a CREATED/CREATED2 cell with the second half of the handshake. To
        extend a circuit past the first hop, the OP sends an EXTEND/EXTEND2
        relay cell (see section 5.1.2) which instructs the last node in the
        circuit to send a CREATE/CREATE2 cell to extend the circuit.

        See tor-spec.txt 5.1. "CREATE and CREATED cells"
        """
        log.debug("Performing NTOR handshake...")

        circuit_node = CircuitNode(self, self._tor_socket.get_guard_relay())
        onion_skin = circuit_node.create_onion_skin()

        self._tor_socket.send_cell(Cell(self.get_circuit_id(), CommandType.CREATE2, [
            2,
            len(onion_skin),
            onion_skin
        ]))

        log.debug("Waiting for handshake response...")
        cell = self._tor_socket.retrieve_cell()

    def handle_cell(self, cell):
        """Handles a cell response related to this circuit, called by TorSocket.

        :type cell: Cell
        """
        pass


class TorSocket:
    """Handles communicating with the guard relay."""

    def __init__(self, guard_relay):
        """:type guard_relay: OnionRouter"""
        self._guard_relay = guard_relay

        # All implementations MUST support the SSLv3 cipher suite
        # "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" if it is available.
        self._socket = ssl.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            ssl_version=ssl.PROTOCOL_TLSv1_2
        )
        self._protocol_versions = [3]
        self._our_public_ip = "0"
        self._shutdown_requested = False

        # Dictionary of circuits this socket is attached to (key = circuit's ID).
        self._circuits = dict()

    def get_guard_relay(self):
        """
        :return: The guard relay this socket is attached to.
        :rtype: OnionRouter
        """
        return self._guard_relay

    def connect(self):
        """Connects the socket to the guard relay."""
        log.debug("Connecting socket to the guard relay...")
        self._socket.connect((self._guard_relay.ip, self._guard_relay.tor_port))

        # When the in-protocol handshake is used, the initiator sends a
        # VERSIONS cell to indicate that it will not be renegotiating.  The
        # responder sends a VERSIONS cell, a CERTS cell (4.2 below) to give the
        # initiator the certificates it needs to learn the responder's
        # identity, an AUTH_CHALLENGE cell (4.3) that the initiator must include
        # as part of its answer if it chooses to authenticate, and a NETINFO
        # cell (4.5).  As soon as it gets the CERTS cell, the initiator knows
        # whether the responder is correctly authenticated.  At this point the
        # initiator behaves differently depending on whether it wants to
        # authenticate or not. If it does not want to authenticate, it MUST
        # send a NETINFO cell.
        self._send_versions()
        self._retrieve_versions()
        self._retrieve_certs()
        self._retrieve_net_info()
        self._send_net_info()

    def close(self):
        """Closes the tor socket (and circuit)."""
        self._shutdown_requested = True
        self._socket.close()

    def create_circuit(self):
        """Creates a path to the final destination."""
        circuit = Circuit(self)
        circuit.create()

        log.debug("Circuit created, assigned ID: %s" % circuit.get_circuit_id())
        self._circuits[circuit.get_circuit_id()] = circuit

    def send_cell(self, cell):
        """Sends a cell to the guard relay.

        :type cell: Cell
        """
        self._socket.write(cell.get_bytes(max(self._protocol_versions)))

    def retrieve_cell(self, ignore_response=False):
        """Waits for a cell response then parses it into a Cell object.

        :rtype: Cell or None
        """
        # https://docs.python.org/3/library/struct.html

        if max(self._protocol_versions) < 4:
            circuit_id = struct.unpack("!H", self._socket.read(2))[0]
        else:
            # Link protocol 4 increases circuit ID width to 4 bytes.
            circuit_id = struct.unpack("!I", self._socket.read(4))[0]

        command = struct.unpack("!B", self._socket.read(1))[0]

        # Variable length cells have the following format:
        #
        #    CircID                             [CIRCID_LEN octets]
        #    Command                            [1 octet]
        #    Length                             [2 octets; big-endian integer]
        #    Payload (some commands MAY pad)    [Length bytes]
        #
        # Fixed-length cells have the following format:
        #
        #    CircID                              [CIRCID_LEN bytes]
        #    Command                             [1 byte]
        #    Payload (padded with padding bytes) [PAYLOAD_LEN bytes]
        if Cell.is_variable_length_command(command):
            payload_length = struct.unpack("!H", self._socket.read(2))[0]
            payload = self._socket.read(payload_length)
        else:
            payload = self._socket.read(Cell.MAX_PAYLOAD_SIZE)

        # Parse into a cell object here...
        if not ignore_response:
            if command == CommandType.VERSIONS:
                versions = []

                # The payload in a VERSIONS cell is a series of big-endian two-byte integers.
                while payload:
                    versions.append(struct.unpack("!H", payload[:2])[0])
                    payload = payload[2:]

                return Cell(circuit_id, command, versions)
            elif command == CommandType.NETINFO:
                our_address_length = int(struct.unpack("!B", payload[5:][:1])[0])
                our_address = socket.inet_ntoa(payload[6:][:our_address_length])

                return Cell(circuit_id, command, [our_address])
            else:
                log.debug("===== START UNKNOWN CELL =====")
                log.debug("Circuit ID: " + str(circuit_id))
                log.debug("Command type: " + str(command))
                log.debug("Payload: " + str(payload))
                log.debug("===== END UNKNOWN CELL   =====")
                return Cell(circuit_id, command, payload)

    def _receive_cell_loop(self):
        """Loop which receives cells and passes them onto the associated circuit."""
        log.debug("Starting cell receive loop...")

        while True:
            if self._shutdown_requested:
                log.debug("Shutting down cell receive loop...")
                break

            cell = self.retrieve_cell()

            self._circuits[cell.circuit_id].handle(cell)

            log.debug("Cell received, waiting for cell...")

    def _send_versions(self):
        """
        When the "in-protocol" handshake is used, implementations MUST NOT
        list any version before 3, and SHOULD list at least version 3.

        Link protocols differences are:
          1 -- The "certs up front" handshake.
          2 -- Uses the renegotiation-based handshake. Introduces
               variable-length cells.
          3 -- Uses the in-protocol handshake.
          4 -- Increases circuit ID width to 4 bytes.
          5 -- Adds support for link padding and negotiation (padding-spec.txt).
        """
        log.debug("Sending VERSIONS cell...")

        self.send_cell(Cell(0, CommandType.VERSIONS, [3, 4]))

    def _retrieve_versions(self):
        log.debug("Retrieving VERSIONS cell...")
        versions_cell = self.retrieve_cell()

        log.debug("Supported link protocol versions: %s" % versions_cell.payload)
        self._protocol_versions = versions_cell.payload

    def _retrieve_certs(self):
        log.debug("Retrieving CERTS cell...")
        self.retrieve_cell(ignore_response=True)

        log.debug("Retrieving AUTH_CHALLENGE cell...")
        self.retrieve_cell(ignore_response=True)

    def _retrieve_net_info(self):
        log.debug("Retrieving NET_INFO cell...")
        cell = self.retrieve_cell()

        self._our_public_ip = cell.payload[0]
        log.debug("Our public IP address: " + self._our_public_ip)

    def _send_net_info(self):
        """
        If version 2 or higher is negotiated, each party sends the other a NETINFO cell.
        The cell's payload is:

        - Timestamp              [4 bytes]
        - Other OR's address     [variable]
        - Number of addresses    [1 byte]
        - This OR's addresses    [variable]

        Address format:

        - Type   (1 octet)
        - Length (1 octet)
        - Value  (variable-width)
        "Length" is the length of the Value field.
        "Type" is one of:
        - 0x00 -- Hostname
        - 0x04 -- IPv4 address
        - 0x06 -- IPv6 address
        - 0xF0 -- Error, transient
        - 0xF1 -- Error, nontransient
        """
        log.debug("Sending NET_INFO cell...")

        self.send_cell(Cell(0, CommandType.NETINFO, [
            int(time()),
            [0x04, 0x04, self._guard_relay.ip],
            0x01,
            [0x04, 0x04, self._our_public_ip]
        ]))


class TinyTor:
    """High level API for sending HTTP requests over Tor."""

    def __init__(self):
        self._consensus = Consensus()

        while True:
            try:
                directory_authority = self._consensus.get_random_directory_authority()
                consensus_url = directory_authority.get_consensus_url()

                log.debug("Using directory authority \"%s\"..." % directory_authority.name)
                log.debug("Consensus URL: %s" % consensus_url)
                log.debug("Parsing the consensus...")

                # The HTTP request to the consensus may timeout, loop until that doesn't happen.
                self._consensus.parse_consensus(consensus_url)
                break
            except Exception as ex:
                log.error("Failed to parse the consensus: %s" % str(ex))
                log.error("Retrying with a different directory authority...")

    def http_get(self, url):
        """Performs a HTTP request over Tor and returns it's response.

        :type url: str
        :rtype: str
        """
        while True:
            try:
                guard_relay = self._consensus.get_random_guard_relay()

                if guard_relay.dir_port == 0:
                    # Some guard relays don't seem to support retrieving
                    # the descriptors over HTTP.
                    continue

                log.debug("Using guard relay \"%s\"..." % guard_relay.nickname)
                log.debug("Descriptor URL: %s" % guard_relay.get_descriptor_url())
                log.debug("Parsing the guard relays keys...")

                # Populate the guard relay's keys...
                # Filters may block visiting the guard relay's descriptor URL.
                # Let's loop until that doesn't happen.
                guard_relay.parse_descriptor()
                break
            except Exception as ex:
                traceback.print_exc()
                log.info("Retrying with a different guard relay...")

        # Start communicating with the guard relay.
        tor_socket = TorSocket(guard_relay)

        try:
            tor_socket.connect()
            tor_socket.create_circuit()
        except Exception as ex:
            traceback.print_exc()
            log.info("Retrying to perform HTTP request...")

            tor_socket.close()
            self.http_get(url)

        return "TINYTOR_IMPLEMENTATION_IS_NOT_FINISHED"


def main():
    parser = ArgumentParser()
    parser.add_argument("--host", help="the onion service to reach", required=True)
    parser.add_argument("--no-banner", help="prevent the TinyTor banner from being displayed", action="store_true")
    parser.add_argument("-v", "--verbose", help="enable verbose output", action="store_true")

    arguments = parser.parse_args()

    if not arguments.no_banner:
        print(BANNER)
    if not arguments.host.endswith(".onion"):
        log.error("Please specify a valid onion service (--host).")
        exit(1)
    if arguments.verbose:
        log.setLevel(logging.DEBUG)

    tor = TinyTor()
    log.info("Received response: \n%s" % tor.http_get(arguments.host))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        log.error("Interrupted.")
        exit(0)
