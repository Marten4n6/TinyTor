# -*- coding: utf-8 -*-
"""TinyTor is a Tor client implementation."""
__author__ = "Marten4n6"
__license__ = "GPLv3"
__version__ = "0.0.1"

import binascii
import logging
import random
import socket
import ssl
import struct
import subprocess
import urllib.request
from argparse import ArgumentParser
from base64 import b64encode, b64decode, b16encode
from os import urandom
from sys import exit
from time import time

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

    def __init__(self, nickname, ip, dir_port, tor_port, fingerprint, flags=None, key_tap=None):
        """
        :type nickname: str
        :type ip: str
        :type dir_port: int
        :type tor_port: int
        :type fingerprint: str
        :type flags: list
        :type key_tap: bytes
        """
        self.nickname = nickname
        self.ip = ip
        self.dir_port = dir_port
        self.tor_port = tor_port
        self.fingerprint = fingerprint
        self.flags = flags
        self.key_tap = key_tap

    def get_descriptor_url(self):
        """:return: The URL to the onion router's descriptor (where keys are stored)."""
        return "http://%s:%s/tor/server/fp/%s" % (self.ip, self.dir_port, self.fingerprint)

    def parse_descriptor(self):
        """Updates the onion router's keys."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0"
        }
        request = urllib.request.Request(url=self.get_descriptor_url(), headers=headers)
        response = urllib.request.urlopen(request)

        key_tap = ""
        append_tap = False

        for line in response:
            line = line.decode()

            if line.startswith("onion-key"):
                append_tap = True
                continue

            if append_tap:
                if "END RSA PUBLIC KEY" in line:
                    key_tap += line.replace("\n", "")
                    break
                else:
                    key_tap += line

        # IMPORTANT:
        # The openssl rsa command only works with PKCS#8 formatted public keys.
        # "BEGIN RSA PUBLIC KEY" is PKCS#1, which can only contain RSA keys.
        # "BEGIN PUBLIC KEY" is PKCS#8, which can contain a variety of formats.

        # macOS / OSX doesn't support "-RSAPublicKey_in" (https://stackoverflow.com/a/27930720)
        # So fuck it, we'll do it manually then.
        # https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
        # https://www.openssl.org/docs/man1.0.2/apps/asn1parse.html
        # https://stackoverflow.com/a/29707204
        # TODO -
        log.debug("Converting guard public key to DER format...")

        self.key_tap = key_tap

    def __str__(self):
        return "OnionRouter(nickname=%s, ip=%s, dir_port=%s, tor_port=%s, fingerprint=%s, flags=%s, key_tap=%s)" % (
            self.nickname, self.ip, self.dir_port, self.tor_port, self.fingerprint, self.flags, self.key_tap
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

    def parse_consensus(self, consensus_url):
        """Parses the consensus document into a list of onion routers.

        :type consensus_url: str
        """
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0"
        }
        request = urllib.request.Request(url=consensus_url, headers=headers)
        response = urllib.request.urlopen(request, timeout=8)

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

                while True:
                    try:
                        # The fingerprint here is base64 encoded bytes.
                        # The descriptor URL uses the base16 encoded value of these bytes.
                        # Documentation for this was hard to find...
                        identity = b16encode(b64decode(identity.encode())).decode()
                        break
                    except binascii.Error:
                        # Incorrect base64 padding.
                        identity = identity + "="

                onion_router = OnionRouter(nickname, ip, dir_port, tor_port, identity)
            elif line.startswith("s "):
                # This line contains the onion router's flags.
                if onion_router:
                    flags = []

                    for token in line.split(" "):
                        if token == "s":
                            continue
                        flags.append(token.lower().replace("\n", "", 1))

                    if "fast" in flags and "running" in flags and "valid" in flags:
                        onion_router_amount += 1
                        onion_router.flags = flags

                        self._parsed_consensus.append(onion_router)

            if onion_router_amount >= 200:
                log.warning("Stopped after reading 200 onion routers.")
                break

    def get_guard_relay(self):
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

    def get_bytes(self):
        """:return: The byte representation of this cell which can be written to a socket."""
        payload_bytes = b""

        if self.command == CommandType.VERSIONS:
            payload_bytes = struct.pack("!" + ("H" * len(self.payload)), *self.payload)

        return struct.pack("!HBH", self.circuit_id, self.command, len(payload_bytes)) + payload_bytes

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


class HybridEncryption:
    """
    Encryption used to calculate the payload of a CREATE cell ('onion skin').

    See tor-spec.txt 0.4. "A bad hybrid encryption algorithm, for legacy purposes."
    """

    # tor-spec.txt 0.3. "Ciphers"
    KEY_LEN = 16
    PK_ENC_LEN = 128
    PK_PAD_LEN = 42

    PK_DATA_LEN = (PK_ENC_LEN - PK_PAD_LEN)
    PK_DATA_LEN_WITH_KEY = (PK_DATA_LEN - KEY_LEN)

    def encrypt(self, my_public_key, guard_public_key):
        """Encrypts the data with the guard relay's TAP public key.

        :type my_public_key: bytes
        :type guard_public_key: guard_public_key_bytes
        :rtype: bytes
        """
        # M = data

        if len(my_public_key) < self.PK_DATA_LEN:
            # 1. If the length of M is no more than PK_ENC_LEN-PK_PAD_LEN,
            #    pad and encrypt M with PK.
            #
            # "Also note that as used in Tor's protocols, case 1 never occurs."
            # So apparently this should never occur?
            log.error("FAILED TO ENCRYPT USING HYBRID ENCRYPTION, THIS SHOULDN'T HAPPEN.")
            log.error("Please submit an issue on GitHub!")
            exit(1)
        else:
            # 2. Otherwise, generate a KEY_LEN byte random key K.
            random_key_bytes = urandom(self.KEY_LEN)

            # Let M1 = the first PK_ENC_LEN-PK_PAD_LEN-KEY_LEN bytes of M,
            # and let M2 = the rest of M.
            m1 = my_public_key[:self.PK_DATA_LEN_WITH_KEY]
            m2 = my_public_key[self.PK_DATA_LEN_WITH_KEY:]

            # Pad and encrypt K|M1 with PK.
            # tor-spec.txt 0.3. "Ciphers":
            # We use OAEP-MGF1 padding, with SHA-1 as its digest function.
            k_and_m1 = random_key_bytes + m1

            # Thanks https://superuser.com/a/431651
            out, err = subprocess.Popen("(echo '%s' | base64 --decode; echo '%s' | base64 --decode) | "
                                        "openssl rsautl -pubin -inform DER -inkey /dev/stdin -encrypt -in /dev/stdin"
                                        % (b64encode(guard_public_key.encode()).decode(), b64encode(k_and_m1).decode()),
                                        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            output = (out + err).decode()

            # Encrypt M2 with our stream cipher, using the key K.

            # Concatenate these encrypted values.
            return "NOT_FINISHED"


class KeyAgreementTAP:
    """
    This handshake uses Diffie-Hellman in Z_p and RSA to compute a set of
    shared keys which the client knows are shared only with a particular
    server, and the server knows are shared with whomever sent the
    original handshake (or with nobody at all).  It's not very fast and
    not very good.  (See Goldberg's "On the Security of the Tor
    Authentication Protocol".)

    The reason for using TAP instead of NTOR is that
    macOS / OSX comes with LibreSSL (2.2.7) which doesn't support curve25519.
    """

    def __init__(self):
        self._hybrid_encryption = HybridEncryption()
        self._private_key = None
        self._public_key = None

        self._create_private_key()
        self._create_public_key()

    def _create_private_key(self):
        """Generate a RSA private key."""
        out, err = subprocess.Popen("openssl genrsa 1024", shell=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        output = (out + err).decode()

        private_key = ""
        append_key = False

        for line in output.splitlines(keepends=True):
            if "BEGIN RSA PRIVATE KEY" in line:
                private_key += line
                append_key = True
                continue

            if append_key:
                if "END RSA PRIVATE KEY" in line:
                    private_key += line.replace("\n", "")
                    break
                else:
                    private_key += line

        self._private_key = private_key
        log.debug("Created private key (for hybrid encryption)...")

    def _create_public_key(self):
        """:rtype: str"""
        # Calculate (derive) the public key from the private key to DER (bytes) format.
        out, err = subprocess.Popen("echo '%s' | openssl rsa -outform DER -pubout" % self._private_key,
                                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        self._public_key = (out + err)

    def get_public_key(self):
        """:rtype: bytes"""
        return self._public_key

    def get_onion_skin(self, my_public_key, guard_tap_public_key):
        """
        The payload for a CREATE cell is an 'onion skin', which consists of
        the first step of the DH handshake data (also known as g^x).  This
        value is encrypted using the "legacy hybrid encryption" algorithm.

        See tor-spec.txt 5.1.3. The "TAP" handshake

        :type my_public_key: bytes
        :type guard_tap_public_key: bytes
        """
        return self._hybrid_encryption.encrypt(my_public_key, guard_tap_public_key)


class Circuit:
    """Handles circuit management."""

    def __init__(self, tor_socket):
        """
        :type tor_socket: TorSocket
        """
        self._tor_socket = tor_socket
        self._handshake_tap = KeyAgreementTAP()

    def build(self):
        """Builds a path to the "exit" relay."""
        log.debug("Building a circuit...")

        self._send_create_cell()

    def _send_create_cell(self):
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
        log.debug("Sending CREATE cell...")

        # The format of a CREATE cell is one of the following:
        #     HDATA     (Client Handshake Data)     [TAP_C_HANDSHAKE_LEN bytes]
        # or
        #     HTAG      (Client Handshake Type Tag) [16 bytes]
        #     HDATA     (Client Handshake Data)     [TAP_C_HANDSHAKE_LEN-16 bytes]
        self._tor_socket.send_cell(Cell(
            0, CommandType.CREATE, [
                "tap",
                self._handshake_tap.get_onion_skin(
                    self._handshake_tap.get_public_key(),
                    self._tor_socket.get_guard_relay().key_tap
                )
            ]
        ))


class TorSocket:
    """Handles communicating with the guard relay."""

    def __init__(self, guard_relay):
        """:type guard_relay: OnionRouter"""
        self._guard_relay = guard_relay

        # All implementations MUST support the SSLv3 cipher suite
        # "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" if it is available.
        self._socket = ssl.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            ssl_version=ssl.PROTOCOL_SSLv23
        )
        self._protocol_versions = None

        self._connect()

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

        # Build a circuit.
        self._circuit = Circuit(self)
        self._circuit.build()

    def get_guard_relay(self):
        """:return: The guard relay this socket is attached to."""
        return self._guard_relay

    def _connect(self):
        """Connects the socket to the guard relay."""
        log.debug("Connecting socket to the guard relay...")
        self._socket.connect((self._guard_relay.ip, self._guard_relay.tor_port))

    def send_cell(self, cell):
        """Sends a cell to the guard relay.

        :type cell: Cell
        """
        self._socket.write(cell.get_bytes())

    def retrieve_cell(self, ignore_response=False):
        """Waits for a cell response then parses it into a Cell object.

        :rtype: Cell or None
        """
        # https://docs.python.org/3/library/struct.html

        # Link protocol 4 increases circuit ID width to 4 bytes.
        if self._protocol_versions and self._protocol_versions[len(self._protocol_versions) - 1] >= 4:
            circuit_id = struct.unpack("!i", self._socket.read(4))[0]
        else:
            circuit_id = struct.unpack("!H", self._socket.read(2))[0]

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
            else:
                log.debug("===== START UNKNOWN CELL =====")
                log.debug("Circuit ID: " + str(circuit_id))
                log.debug("Command type: " + str(command))
                log.debug("Payload: " + str(payload))
                log.debug("===== END UNKNOWN CELL   =====")
                return Cell(circuit_id, command, payload)

    def _send_versions(self):
        log.debug("Sending VERSIONS cell...")

        self._socket.write(Cell(0, CommandType.VERSIONS, [3, 4, 5]).get_bytes())

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
        self.retrieve_cell(ignore_response=True)

    def _send_net_info(self):
        log.debug("Sending NET_INFO cell...")

        # If version 2 or higher is negotiated, each party sends the other a
        # NETINFO cell.  The cell's payload is:
        #
        #    Timestamp              [4 bytes]
        #    Other OR's address     [variable]
        #    Number of addresses    [1 byte]
        #    This OR's addresses    [variable]
        #
        # Address format:
        #    Type   (1 octet)
        #    Length (1 octet)
        #    Value  (variable-width)
        # "Length" is the length of the Value field.
        # "Type" is one of:
        #    0x00 -- Hostname
        #    0x04 -- IPv4 address
        #    0x06 -- IPv6 address
        #    0xF0 -- Error, transient
        #    0xF1 -- Error, nontransient
        self._socket.write(Cell(0, CommandType.NETINFO, [
            time(),
            0x04, 0x04, self._guard_relay.ip,
            0x01,
            0x04, 0x04, 0
        ]).get_bytes())


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
                guard_relay = self._consensus.get_guard_relay()

                log.debug("Using guard relay \"%s\"..." % guard_relay.nickname)
                log.debug("Descriptor URL: %s" % guard_relay.get_descriptor_url())
                log.debug("Parsing the guard relays keys...")

                # Populate the guard relay's keys...
                # Filters may block visiting the guard relay's descriptor URL.
                # Let's loop until that doesn't happen.
                guard_relay.parse_descriptor()
                break
            except Exception as ex:
                log.error(str(ex))
                log.info("Retrying with a different guard relay...")

        # Start communicating with the guard relay.
        tor_socket = TorSocket(guard_relay)

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

    tinytor = TinyTor()
    log.info("Received response: \n%s" % tinytor.http_get("example.onion"))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        log.error("Interrupted.")
        exit(0)
