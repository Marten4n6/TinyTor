#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""TinyTor is a Tor client implementation."""
__author__ = "Marten4n6"
__license__ = "GPLv3"
__version__ = "0.0.1"

import hashlib
import hmac
import logging
import operator
import random
import socket
import ssl
import struct
import traceback
from argparse import ArgumentParser
from base64 import b64decode, b16encode, b16decode
from hashlib import sha1
from os import urandom
from sys import exit
from time import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR

try:
    from urllib.request import Request, urlopen, HTTPError
except ImportError:
    # Python2 support.
    from urllib2 import Request, urlopen, HTTPError
try:
    # python3
    from urllib.parse import urlparse
except:
    # python2
    from urlparse import urlparse


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
        return "http://%s:%s/tor/status-vote/current/consensus" % (self.ip, self.dir_port)


class OnionRouter:
    """This class represents an onion router in a circuit.."""

    def __init__(self, nickname, ip, dir_port, tor_port, identity):
        """
        :type nickname: str
        :type ip: str
        :type dir_port: int
        :type tor_port: int
        :type identity: str
        """
        self.nickname = nickname
        self.ip = ip
        self.dir_port = dir_port
        self.tor_port = tor_port
        self.identity = identity

        self.flags = None
        self.key_ntor = None

        self._forward_digest = None
        self._backward_digest = None
        self.encryption_key = None
        self.decryption_key = None

    def get_descriptor_url(self):
        """
        :return: The URL to the onion router's descriptor (where keys are stored).
        :rtype: str
        """
        return "http://%s:%s/tor/server/fp/%s" % (self.ip, self.dir_port, self.identity)

    def parse_descriptor(self):
        """Updates the onion router's keys, may raise HTTPError."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0"
        }
        request = Request(url=self.get_descriptor_url(), headers=headers)
        response = urlopen(request, timeout=8)

        for line in response:
            line = line.decode()

            if line.startswith("ntor-onion-key "):
                self.key_ntor = line.split("ntor-onion-key")[1].strip()
                if self.key_ntor[-1] != '=':
                    # The trailing '=' sign MAY be omitted from the base64 encoding
                    self.key_ntor += "="
                break

    def set_shared_secret(self, data):
        """
        When used in the NTOR handshake, the first HASH_LEN bytes form the
        forward digest Df; the next HASH_LEN form the backward digest Db; the
        next KEY_LEN form Kf, the next KEY_LEN form Kb, and the final
        DIGEST_LEN bytes are taken as a nonce to use in the place of KH in the
        hidden service protocol. Excess bytes from K are discarded.

        :type data: bytes
        """
        forward_digest, backward_digest, encryption_key, decryption_key = struct.unpack("!20s20s16s16s", data)

        self._forward_digest = self.set_digest(forward_digest)
        self._backward_digest = self.set_digest(backward_digest)
        self.encryption_key = encryption_key
        self.decryption_key = decryption_key
        self._forward_cipher = Cipher(AES(self.encryption_key), CTR(b'\0' * 16), backend=default_backend()).encryptor()
        self._backward_cipher = Cipher(AES(self.decryption_key), CTR(b'\0' * 16), backend=default_backend()).decryptor()

    def set_digest(self, data):
        digest = sha1()
        digest.update(data)
        return digest

    def get_forward_digest(self, data):
        self._forward_digest.update(data)
        return self._forward_digest.digest()

    def get_backward_digest(self, data):
        data = data[:5] + struct.pack("!4s", b"\x00" * 4) + data[9:]
        self._backward_digest.update(data)
        return self._backward_digest.digest()

    def encrypt(self, relay_payload):
        return self._forward_cipher.update(relay_payload)

    def decrypt(self, relay_payload):
        return self._backward_cipher.update(relay_payload)


class Consensus:
    """
    Hardcoded into each Tor client is the information about 10 beefy Tor nodes run by trusted volunteers.
    These nodes have a very special role - to maintain the status of the entire Tor network.
    These nodes are known as directory authorities (DA's).

    The status of all the Tor relays is maintained in a living document called the consensus.
    DA's maintain this document and update it every hour by a vote.
    """

    def __init__(self):
        # Taken from https://consensus-health.torproject.org/
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
        """Parses the consensus document into a list of onion routers, may raise HTTPError.

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

                if dir_port == 0:
                    # This onion router doesn't support retrieving descriptors over HTTP.
                    onion_router = None
                    continue

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

    def get_random_onion_router(self):
        """
        :return: A random onion router.
        :rtype: OnionRouter
        """
        return random.choice(self._parsed_consensus)

    def get_random_exit_router(self):
        """
        :return: A random exit router.
        :rtype: OnionRouter
        """
        exit_relays = []

        for onion_router in self._parsed_consensus:
            if "exit" in onion_router.flags:
                exit_relays.append(onion_router)

        return random.choice(exit_relays)


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

class RelayCommand:
    # The relay commands.
    #
    # Within a circuit, the OP and the exit node use the contents of
    # RELAY packets to tunnel end-to-end commands and TCP connections
    # ("Streams") across circuits. End-to-end commands can be initiated
    # by either edge; streams are initiated by the OP.
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
        :type payload: dict
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
            payload_bytes = struct.pack("!" + ("H" * len(self.payload["versions"])), *self.payload["versions"])
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
            timestamp = struct.pack("!I", self.payload["timestamp"])
            other_or_address = struct.pack("!BB", 4, 4) + socket.inet_aton(self.payload["other_ip"])
            number_of_addresses = struct.pack("!B", 1)
            this_or_address = struct.pack("!BB", 4, 4) + socket.inet_aton(self.payload["our_ip"])

            payload_bytes = timestamp + other_or_address + number_of_addresses + this_or_address
        elif self.command == CommandType.CREATE2:
            # A CREATE2 cell contains:
            #     H_TYPE     (Client Handshake Type)     [2 bytes]
            #     H_LEN      (Client Handshake Data Len) [2 bytes]
            #     H_DATA     (Client Handshake Data)     [H_LEN bytes]
            payload_bytes = struct.pack("!HH", self.payload["type"], self.payload["length"]) + self.payload["data"]
        elif self.command in (CommandType.RELAY_EARLY, CommandType.RELAY):
            payload_bytes = self.payload["encrypted_payload"]
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
        command byte equal to 7 ("VERSIONS").
        On a version 3 or higher connection, variable-length cells are indicated by a command
        byte equal to 7 ("VERSIONS"), or greater than or equal to 128.

        See tor-spec.txt 3. "Cell Packet format"

        :type command: int
        :rtype: bool
        """
        if command == CommandType.VERSIONS or command >= 128:
            return True
        else:
            return False


class RelayCell(Cell):
    MAX_RELAY_CELL_DATA = Cell.MAX_PAYLOAD_SIZE - 11

    def __init__(self, cell):
        super().__init__(cell.circuit_id, cell.command, cell.payload["encrypted_payload"])

    def parse_cell(self):
        """Parses the relay cell.

        :rtype: dict
        """
        # The payload of each unencrypted RELAY cell consists of:
        #       Relay command           [1 byte]
        #       'Recognized'            [2 bytes]
        #       StreamID                [2 bytes]
        #       Digest                  [4 bytes]
        #       Length                  [2 bytes]
        #       Data                    [PAYLOAD_LEN-11 bytes]
        relay_command = struct.unpack("!B", self.payload[:1])[0]
        recognized = struct.unpack("!H", self.payload[1:][:2])[0]
        stream_id = struct.unpack("!H", self.payload[3:][:2])[0]
        digest = struct.unpack("!4s", self.payload[5:][:4])[0]
        length = struct.unpack("!H", self.payload[9:][:2])[0]
        data = struct.unpack("!498s", self.payload[11:])[0]

        response_data = {
            "command": relay_command,
            "recognized": recognized,
            "stream_id": stream_id,
            "digest": digest,
            "length": length,
            "data": data
        }

        if relay_command == RelayCommand.RELAY_EXTENDED2:
            data_length = struct.unpack("!H", data[:2])[0]
            data = data[2:data_length + 2]
            y = data[:32]
            auth = data[32:]

            response_data["Y"] = y
            response_data["auth"] = auth
        elif relay_command in (RelayCommand.RELAY_DATA, RelayCommand.RELAY_CONNECTED, RelayCommand.RELAY_END):
            pass
        else:
            log.warning("Unsupported relay cell: %d", relay_command)

        return response_data


class Ed25519:
    """
    Python implementation of Ed25519, used by the NTOR handshake.
    "Ed25519 is both a signature scheme and a use case for Edwards-form Curve25519."

    References:
        - https://ed25519.cr.yp.to/python/ed25519.py
        - https://github.com/itdaniher/slownacl/blob/master/curve25519.py
        - https://gitweb.torproject.org/tor.git/tree/src/test/ed25519_exts_ref.py
        - https://monero.stackexchange.com/questions/9820/recursionerror-in-ed25519-py
        - https://crypto.stackexchange.com/questions/47147/ed25519-is-a-signature-or-just-elliptic-curve
        - https://github.com/Marten4n6/TinyTor/pull/4
    """

    def __init__(self):
        self._P = 2 ** 255 - 19
        self._A = 486662

        self._b = 256
        self._q = 2 ** 255 - 19
        self._l = 2 ** 252 + 27742317777372353535851937790883648493

        self._d = -121665 * self._inv(121666)
        self._I = self._exp_mod(2, (self._q - 1) // 4, self._q)

        self._By = 4 * self._inv(5)
        self._Bx = self._x_recover(self._By)
        self._B = [self._Bx % self._q, self._By % self._q]

    def _exp_mod(self, b, e, m):
        if e == 0:
            return 1
        t = self._exp_mod(b, e // 2, m) ** 2 % m
        if e & 1:
            t = (t * b) % m
        return t

    def _inv(self, x):
        return self._exp_mod(x, self._P - 2, self._P)

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

    def get_public_key(self, sk):
        sk = self.clamp(self.unpack(sk))
        return self.pack(self.exp(sk, 9))

    @staticmethod
    def create_secret_key():
        return urandom(32)

    def add(self, n, m, d):
        (xn, zn), (xm, zm), (xd, zd) = n, m, d
        x = 4 * (xm * xn - zm * zn) ** 2 * zd
        z = 4 * (xm * zn - zm * xn) ** 2 * xd
        return x % self._P, z % self._P

    def double(self, n):
        (xn, zn) = n
        x = (xn ** 2 - zn ** 2) ** 2
        z = 4 * xn * zn * (xn ** 2 + self._A * xn * zn + zn ** 2)
        return x % self._P, z % self._P

    def exp(self, n, base):
        one = (base, 1)
        two = self.double(one)

        def f(m):
            if m == 1:
                return one, two
            (pm, pm1) = f(m // 2)
            if m & 1:
                return self.add(pm, pm1, one), self.double(pm1)
            return self.double(pm), self.add(pm, pm1, one)

        ((x, z), _) = f(n)
        return (x * self._inv(z)) % self._P

    def b2i(self, c):
        return c

    def i2b(self, i):
        return i

    def ba2bs(self, ba):
        return bytes(ba)

    @staticmethod
    def clamp(n):
        n &= ~7
        n &= ~(128 << 8 * 31)
        n |= 64 << 8 * 31
        return n

    def unpack(self, s):
        if len(s) != 32:
            raise ValueError("Invalid Curve25519 argument.")
        return sum(self.b2i(s[i]) << (8 * i) for i in range(32))

    def pack(self, n):
        return self.ba2bs([self.i2b((n >> (8 * i)) & 255) for i in range(32)])

    def smult_curve25519(self, n, p):
        n = self.clamp(self.unpack(n))
        p = self.unpack(p)
        return self.pack(self.exp(n, p))


class KeyAgreementNTOR:
    """Handles performing NTOR handshakes."""

    PROTOCOL_ID = b'ntor-curve25519-sha256-1'
    t_mac = PROTOCOL_ID + b':mac'
    t_key = PROTOCOL_ID + b':key_extract'
    t_verify = PROTOCOL_ID + b':verify'
    m_expand = PROTOCOL_ID + b':key_expand'

    def __init__(self, onion_router):
        """:type onion_router: OnionRouter"""
        self._onion_router = onion_router

        # To perform the handshake, the client needs to know an identity key
        # digest for the server, and an NTOR onion key (a curve25519 public
        # key) for that server. Call the NTOR onion key "B".  The client
        # generates a temporary key-pair:
        #     x,X = KEYGEN()
        self._ed25519 = Ed25519()
        self._x = self._ed25519.create_secret_key()
        self._X = self._ed25519.get_public_key(self._x)

        self._B = b64decode(self._onion_router.key_ntor.encode())

        # and generates a client-side handshake with contents:
        #     NODE_ID     Server identity digest  [ID_LENGTH bytes]
        #     KEYID       KEYID(B)                [H_LENGTH bytes]
        #     CLIENT_PK   X                       [G_LENGTH bytes]
        self._handshake = b16decode(self._onion_router.identity.encode())
        self._handshake += self._B
        self._handshake += self._X

    def get_onion_skin(self):
        """:rtype: bytes"""
        return self._handshake

    @staticmethod
    def _hmac_sha256(key, msg):
        h = hmac.HMAC(key, digestmod=hashlib.sha256)
        h.update(msg)
        return h.digest()

    def _kdf_rfc5869(self, key, n):
        """
        In RFC5869's vocabulary, this is HKDF-SHA256 with info == m_expand,
        salt == t_key, and IKM == secret_input.

        See tor-spec.txt 5.2.2. "KDF-RFC5869"

        :type key: bytes
        :type n: int
        :return: The shared key.
        """
        prk = self._hmac_sha256(KeyAgreementNTOR.t_key, key)
        out = b""
        last = b""
        i = 1

        while len(out) < n:
            m = last + KeyAgreementNTOR.m_expand + int2byte(i)
            last = h = self._hmac_sha256(prk, m)
            out += h
            i = i + 1

        return out[:n]

    def complete_handshake(self, Y, auth):
        """
        :type Y: bytes
        :type auth: bytes

        The server's handshake reply is:
            SERVER_PK   Y                       [G_LENGTH bytes]
            AUTH        H(auth_input, t_mac)    [H_LENGTH bytes]

        Updates the onion router's shared secret with the computed key.
        """
        # The client then checks Y is in G^* [see NOTE below], and computes
        # secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
        secret_input = self._ed25519.smult_curve25519(self._x, Y)
        secret_input += self._ed25519.smult_curve25519(self._x, self._B)
        secret_input += b16decode(self._onion_router.identity.encode())
        secret_input += self._B
        secret_input += self._X
        secret_input += Y
        secret_input += b'ntor-curve25519-sha256-1'

        # KEY_SEED = H(secret_input, t_key) -- Not used.
        # verify = H(secret_input, t_verify)
        verify = self._hmac_sha256(KeyAgreementNTOR.t_verify, secret_input)

        # auth_input = verify | ID | B | Y | X | PROTOID | "Server"
        auth_input = verify
        auth_input += b16decode(self._onion_router.identity.encode())
        auth_input += self._B
        auth_input += Y
        auth_input += self._X
        auth_input += KeyAgreementNTOR.PROTOCOL_ID
        auth_input += b'Server'

        # The client verifies that AUTH == H(auth_input, t_mac).
        if auth != self._hmac_sha256(KeyAgreementNTOR.t_mac, auth_input):
            log.error("Server handshake doesn't match verification")
            raise Exception("Server handshake doesn't match verificaiton.")

        self._onion_router.set_shared_secret(self._kdf_rfc5869(secret_input, 72))
        log.debug("Handshake verified, onion router's shared secret has been set.")


class Circuit:
    """Handles circuit management."""

    def __init__(self, tor_socket):
        """
        :type tor_socket: TorSocket
        """
        self._tor_socket = tor_socket
        if self._tor_socket.get_max_protocol_version() < 4:
            self._circuit_id = random.randint(0, (2 ** 16) - 1)  # C int value range (2 bytes)
        else:
            self._circuit_id = random.randint(2 ** 31, (2 ** 32) - 1)  # C int value range (4 bytes)
        self._onion_routers = list()
        self._stream_id = 0

    def get_tor_socket(self):
        """:rtype: TorSocket"""
        return self._tor_socket

    def get_circuit_id(self):
        """:rtype: int"""
        return self._circuit_id

    def get_onion_routers(self):
        """
        :return: A list of onion routers in this circuit.
        :rtype: list[OnionRouter]
        """
        return self._onion_routers

    def create(self, guard_relay):
        """
        Users set up circuits incrementally, one hop at a time. To create a
        new circuit, OPs send a CREATE/CREATE2 cell to the first node, with
        the first half of an authenticated handshake; that node responds with
        a CREATED/CREATED2 cell with the second half of the handshake.

        tor-spec.txt 5.1. "CREATE and CREATED cells"
        """
        log.debug("Creating new circuit...")
        log.debug("Circuit ID:" + str(self._circuit_id))
        key_agreement = KeyAgreementNTOR(guard_relay)

        self._tor_socket.send_cell(Cell(self.get_circuit_id(), CommandType.CREATE2, {
            "type": 2,
            "length": len(key_agreement.get_onion_skin()),
            "data": key_agreement.get_onion_skin()
        }))

        cell = self._tor_socket.retrieve_cell()
        if cell.command != CommandType.CREATED2:
            log.error("Received command is not a CREATED2.")
            raise Exception("Received command is not a CREATED2.")

        key_agreement.complete_handshake(cell.payload["Y"], cell.payload["auth"])
        self._onion_routers.append(guard_relay)

    def create_relay_cell(self, command, stream_id, payload):
        """Creates a encrypted bytes stream that contains the relay payload.

        :rtype: bytes
        """
        # The payload of each unencrypted RELAY cell consists of:
        #       Relay command           [1 byte]
        #       'Recognized'            [2 bytes]
        #       StreamID                [2 bytes]
        #       Digest                  [4 bytes]
        #       Length                  [2 bytes]
        #       Data                    [PAYLOAD_LEN-11 bytes]
        relay_cell = struct.pack("!B", command)
        relay_cell += struct.pack("!H", 0)
        # Rather, RELAY cells that affect the
        # entire circuit rather than a particular stream use a StreamID of zero
        relay_cell += struct.pack("!H", stream_id)
        relay_cell += struct.pack("!4s", b"\x00" * 4)
        relay_cell += struct.pack("!H", len(payload))
        relay_cell += struct.pack("!498s", payload)

        # Calculate and replace the digest.
        calculated_digest = self.get_onion_routers()[-1].get_forward_digest(relay_cell)[:4]
        relay_cell = relay_cell[:5] + calculated_digest + relay_cell[9:]

        # Encrypt the relay cell to the last onion router in the circuit.
        relay_cell = self.encrypt_payload(relay_cell)
        return relay_cell

    def start_stream(self, address, port):
        """Start a new stream to a specific tagret address.

        :type address: str
        :type port: int
        """
        self._stream_id += 1
        log.debug("Starting a stream with stream id: " + str(self._stream_id))
        # The payload format is:
        # ADDRPORT[nul - terminated string]
        # FLAGS[4 bytes]
        # ADDRPORT is made of ADDRESS | ':' | PORT | [00]
        relay_payload = '{}:{}'.format(address, port).encode()
        relay_payload += struct.pack('!BI', 0, 0)
        relay_cell = self.create_relay_cell(RelayCommand.RELAY_BEGIN, self._stream_id, relay_payload)
        self.get_tor_socket().send_cell(Cell(
            self.get_circuit_id(),
            CommandType.RELAY,
            {"encrypted_payload": relay_cell})
        )
        response_cell = RelayCell(self.get_tor_socket().retrieve_cell())
        response_cell.payload = self.decrypt_payload(response_cell.payload)
        parsed_response = response_cell.parse_cell()
        if parsed_response['command'] != RelayCommand.RELAY_CONNECTED:
            log.error("Creating a connection to the address failed.")
            raise Exception("Creating a connection to the address failed.")

    def send_http_get(self):
        """Sends a HTTP GET request out to an address.

        :return: response received from the address
        """
        relay_payload = b'GET / HTTP/1.0\r\n\r\n'
        relay_cell = self.create_relay_cell(RelayCommand.RELAY_DATA, self._stream_id, relay_payload)
        self.get_tor_socket().send_cell(Cell(
            self.get_circuit_id(),
            CommandType.RELAY,
            {"encrypted_payload": relay_cell})
        )
        response_data = self.get_tor_socket().retrieve_relay_data(self)
        return response_data

    def extend(self, onion_router):
        """Extends the circuit to the specified onion router.

        :type onion_router: OnionRouter
        """
        log.debug("Extending the circuit to \"%s\"...", onion_router.nickname)

        key_agreement = KeyAgreementNTOR(onion_router)

        # To extend an existing circuit, the client sends an EXTEND2
        # relay cell to the last node in the circuit.
        #
        # An EXTEND2 cell's relay payload contains:
        #     NSPEC      (Number of link specifiers)     [1 byte]
        #       NSPEC times:
        #         LSTYPE (Link specifier type)           [1 byte]
        #         LSLEN  (Link specifier length)         [1 byte]
        #         LSPEC  (Link specifier)                [LSLEN bytes]
        #     HTYPE      (Client Handshake Type)         [2 bytes]
        #     HLEN       (Client Handshake Data Len)     [2 bytes]
        #     HDATA      (Client Handshake Data)         [HLEN bytes]
        relay_payload = struct.pack("!B", 2)
        relay_payload += struct.pack("!BB4sH", 0, 6, socket.inet_aton(onion_router.ip), onion_router.tor_port)
        relay_payload += struct.pack("!BB20s", 2, 20, b16decode(onion_router.identity.encode()))
        relay_payload += struct.pack("!HH", 2, len(key_agreement.get_onion_skin())) + key_agreement.get_onion_skin()

        relay_cell = self.create_relay_cell(RelayCommand.RELAY_EXTEND2, 0, relay_payload)

        # When speaking v2 of the link protocol or later, clients MUST only send
        # EXTEND2 cells inside RELAY_EARLY cells.
        self.get_tor_socket().send_cell(Cell(
            self.get_circuit_id(),
            CommandType.RELAY_EARLY,
            {"encrypted_payload": relay_cell})
        )

        response_cell = RelayCell(self.get_tor_socket().retrieve_cell())
        if response_cell.command != CommandType.RELAY:
            log.error("Received command is not a RELAY.")
            raise Exception("Received command is not a RELAY.")
        response_cell.payload = self.decrypt_payload(response_cell.payload)
        parsed_response = response_cell.parse_cell()

        key_agreement.complete_handshake(parsed_response["Y"], parsed_response["auth"])
        self._onion_routers.append(onion_router)

    def encrypt_payload(self, relay_payload):
        """Encrypts the relay payload.

        :rtype relay_payload: bytes
        """
        for router in reversed(self.get_onion_routers()):
            relay_payload = router.encrypt(relay_payload)
        return relay_payload

    def decrypt_payload(self, relay_payload):
        """Decrypts the encrypted payload.

        :rtype relay_payload: bytes
        """
        for router in self.get_onion_routers():
            relay_payload = router.decrypt(relay_payload)
            # if 'recognized' = ZERO then probability is high that the relay cell was decrypted
            if relay_payload[1:3] == (b"\x00" * 2):
                digest = router.get_backward_digest(relay_payload)[:4]
                # check that also the digest is correct
                if relay_payload[5:9] == digest:
                    return relay_payload


class TorSocket:
    """Handles communicating with the guard relay."""

    def __init__(self, guard_relay):
        """:type guard_relay: OnionRouter"""
        self._guard_relay = guard_relay

        self._socket = ssl.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            ssl_version=ssl.PROTOCOL_TLSv1_2
        )
        self._protocol_versions = [3]
        self._our_public_ip = "0"
        self._circuits = []

    def get_guard_relay(self):
        """
        :return: The guard relay this socket is attached to.
        :rtype: OnionRouter
        """
        return self._guard_relay

    def get_max_protocol_version(self):
        return max(self._protocol_versions)

    def connect(self):
        """Connects the socket to the guard relay."""
        log.debug("Connecting socket to the guard relay...")
        self._socket.connect((self._guard_relay.ip, self._guard_relay.tor_port))

        # When the in-protocol handshake is used, the initiator sends a
        # VERSIONS cell to indicate that it will not be renegotiating.  The
        # responder sends a VERSIONS cell, a CERTS cell (4.2 below) to give the
        # initiator the certificates it needs to learn the responder's
        # identity, an AUTH_CHALLENGE cell (4.3) that the initiator must include
        # as part of its answer if it chooses to authenticate, and a NET_INFO
        # cell (4.5).  As soon as it gets the CERTS cell, the initiator knows
        # whether the responder is correctly authenticated.  At this point the
        # initiator behaves differently depending on whether it wants to
        # authenticate or not. If it does not want to authenticate, it MUST
        # send a NET_INFO cell.
        self._send_versions()
        self._retrieve_versions()
        self._retrieve_certs()
        self._retrieve_net_info()
        self._send_net_info()

    def send_cell(self, cell):
        """Sends a cell to the guard relay.

        :type cell: Cell
        """
        self._socket.write(cell.get_bytes(self.get_max_protocol_version()))

    def retrieve_cell(self, ignore_response=False):
        """
        Waits for a cell response then parses it into a Cell object.
        Relay cells should be passed onto a RelayCell for decryption and parsing.

        :type ignore_response: True if the response should NOT be parsed.
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
        #    CircuitID                          [CIRCUIT_ID_LEN octets]
        #    Command                            [1 octet]
        #    Length                             [2 octets; big-endian integer]
        #    Payload (some commands MAY pad)    [Length bytes]
        #
        # Fixed-length cells have the following format:
        #
        #    CircuitID                           [CIRCUIT_ID_LEN bytes]
        #    Command                             [1 byte]
        #    Payload (padded with padding bytes) [PAYLOAD_LEN bytes]
        payload = b''
        if Cell.is_variable_length_command(command):
            payload_length = struct.unpack("!H", self._socket.read(2))[0]
            payload = self._socket.read(payload_length)
        else:
            while len(payload) != Cell.MAX_PAYLOAD_SIZE:
                payload += self._socket.read(Cell.MAX_PAYLOAD_SIZE - len(payload))

        if command in (CommandType.PADDING, CommandType.VPADDING):
            return self.retrieve_cell()
        # Parse into a cell object here...
        if not ignore_response:
            if command == CommandType.VERSIONS:
                versions = []

                # The payload in a VERSIONS cell is a series of big-endian two-byte integers.
                while payload:
                    versions.append(struct.unpack("!H", payload[:2])[0])
                    payload = payload[2:]

                return Cell(circuit_id, command, {"versions": versions})
            elif command == CommandType.NETINFO:
                our_address_length = int(struct.unpack("!B", payload[5:][:1])[0])
                our_address = socket.inet_ntoa(payload[6:][:our_address_length])

                return Cell(circuit_id, command, {"our_address": our_address})
            elif command == CommandType.CREATED2:
                # A CREATED2 cell contains:
                #     DATA_LEN      (Server Handshake Data Len) [2 bytes]
                #     DATA          (Server Handshake Data)     [DATA_LEN bytes]
                data_length = struct.unpack("!H", payload[:2])[0]
                data = payload[2:data_length + 2]
                y = data[:32]
                auth = data[32:]

                return Cell(circuit_id, command, {"Y": y, "auth": auth})
            elif command == CommandType.RELAY:
                # The relay commands, should be passed to a relay cell for decryption.
                return Cell(circuit_id, command, {"encrypted_payload": payload})
            elif command == CommandType.DESTROY:
                # The payload of a RELAY_TRUNCATED or DESTROY cell contains a single octet,
                # describing why the circuit is being closed or truncated.
                reason = struct.unpack("!B", payload[:1])[0]

                log.warning("Circuit %s destroyed, reason: %s" % (str(circuit_id), str(reason)))
                return Cell(circuit_id, command, {"reason": reason})
            else:
                log.debug("-*-*-*-*-*- UNKNOWN_CELL -*-*-*-*-*-")
                log.debug("Circuit ID: " + str(circuit_id))
                log.debug("Command type: " + str(command))
                log.debug("Payload: " + str(payload))
                log.debug("-*-*-*-*-*- UNKNOWN_CELL -*-*-*-*-*-")
                return Cell(circuit_id, command, {"payload": payload})

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

        self.send_cell(Cell(0, CommandType.VERSIONS, {"versions": [3, 4]}))

    def _retrieve_versions(self):
        log.debug("Retrieving VERSIONS cell...")
        versions_cell = self.retrieve_cell()

        log.debug("Supported link protocol versions: %s" % versions_cell.payload["versions"])
        self._protocol_versions = versions_cell.payload["versions"]

    def _retrieve_certs(self):
        log.debug("Retrieving CERTS cell...")
        self.retrieve_cell(ignore_response=True)

        log.debug("Retrieving AUTH_CHALLENGE cell...")
        self.retrieve_cell(ignore_response=True)

    def _retrieve_net_info(self):
        log.debug("Retrieving NET_INFO cell...")
        cell = self.retrieve_cell()

        self._our_public_ip = cell.payload["our_address"]
        log.debug("Our public IP address: " + self._our_public_ip)

    def retrieve_relay_data(self, circuit):
        log.debug("Retrieving RELAY_DATA cells...")
        response = b''
        while True:
            cell = RelayCell(self.retrieve_cell())
            if cell.command == CommandType.RELAY:
                cell.payload = circuit.decrypt_payload(cell.payload)
                parsed_response = cell.parse_cell()
                if parsed_response['command'] == RelayCommand.RELAY_DATA:
                    data_length = parsed_response['length']
                    response += parsed_response['data'][:data_length]
                    if data_length < RelayCell.MAX_RELAY_CELL_DATA:
                        return response

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

        self.send_cell(Cell(0, CommandType.NETINFO, {
            "timestamp": int(time()),
            "other_ip": self._guard_relay.ip,
            "our_ip": self._our_public_ip
        }))


class TinyTor:
    """High level API for sending HTTP requests over Tor."""

    def __init__(self):
        self._consensus = Consensus()

        while True:  # The HTTP request to the consensus may timeout.
            try:
                directory_authority = self._consensus.get_random_directory_authority()
                consensus_url = directory_authority.get_consensus_url()

                log.debug("Using directory authority \"%s\"..." % directory_authority.name)
                log.debug("Consensus URL: %s" % consensus_url)
                log.debug("Parsing the consensus...")

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
        while True:  # Filters may block visiting the guard relay's descriptor URL.
            try:
                guard_relay = self._consensus.get_random_guard_relay()

                log.debug("Using guard relay \"%s\"..." % guard_relay.nickname)
                log.debug("Descriptor URL: %s" % guard_relay.get_descriptor_url())
                log.debug("Parsing the guard relays keys...")

                guard_relay.parse_descriptor()
                break
            except Exception:
                traceback.print_exc()
                log.info("Retrying with a different guard relay...")

        # Start communicating with the guard relay.
        tor_socket = TorSocket(guard_relay)
        tor_socket.connect()

        circuit = Circuit(tor_socket)
        circuit.create(guard_relay)

        while True:
            extend_relay = self._consensus.get_random_onion_router()
            if extend_relay.identity not in [router.identity for router in circuit.get_onion_routers()]:
                break
        extend_relay.parse_descriptor()
        circuit.extend(extend_relay)

        while True:
            extend_relay2 = self._consensus.get_random_exit_router()
            if extend_relay2.identity not in [router.identity for router in circuit.get_onion_routers()]:
                break
        extend_relay2.parse_descriptor()
        circuit.extend(extend_relay2)

        circuit.start_stream(url, 80)
        response = circuit.send_http_get()

        return response


def main():
    parser = ArgumentParser()
    #parser.add_argument("--host", help="the onion service to reach", required=True)
    parser.add_argument("--host", help="the url to reach", required=True)
    parser.add_argument("--no-banner", help="prevent the TinyTor banner from being displayed", action="store_true")
    parser.add_argument("-v", "--verbose", help="enable verbose output", action="store_true")

    arguments = parser.parse_args()

    parsed_host = urlparse(arguments.host).geturl()
    if not arguments.no_banner:
        print(BANNER)
    # The onion services v2 and v3 implementations are needed for connections to .oinion-addresses.
    # specs for hidden-services:
    # https://gitweb.torproject.org/torspec.git/tree/rend-spec-v2.txt
    # https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt
    #if not arguments.host.endswith(".onion"):
        #log.error("Please specify a valid onion service (--host).")
        #exit(1)
    if not parsed_host:
        log.error("Please specify a valid url (--host).")
        exit(1)
    if arguments.verbose:
        log.setLevel(logging.DEBUG)

    tor = TinyTor()
    print("Received response: \n%s" % tor.http_get(parsed_host))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        log.error("Interrupted.")
        exit(0)
