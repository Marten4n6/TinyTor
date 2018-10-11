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
import urllib.request
from argparse import ArgumentParser
from base64 import b64decode, b16encode
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

    def __init__(self, nickname, ip, dir_port, tor_port, fingerprint, flags=None, ntor_key=None):
        """
        :type nickname: str
        :type ip: str
        :type dir_port: int
        :type tor_port: int
        :type fingerprint: str
        :type flags: list
        :type ntor_key: str
        """
        self.nickname = nickname
        self.ip = ip
        self.dir_port = dir_port
        self.tor_port = tor_port
        self.fingerprint = fingerprint
        self.flags = flags
        self.ntor_key = ntor_key

    def get_descriptor_url(self):
        """:return: The URL to the onion router's descriptor (where keys are stored)."""
        return "http://%s:%s/tor/server/fp/%s" % (self.ip, self.dir_port, self.fingerprint)

    def parse_descriptor(self):
        # TODO - Parse the descriptor and update the key(s).
        pass

    def __str__(self):
        return "OnionRouter(nickname=%s, ip=%s, dir_port=%s, tor_port=%s, fingerprint=%s, flags=%s, ntor_key=%s)" % (
            self.nickname, self.ip, self.dir_port, self.tor_port, self.fingerprint, self.flags, self.ntor_key
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
                        # The fingerprint is base64 encoded then encoded with base16.
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

    def _connect(self):
        """Connects the socket to the guard relay."""
        log.debug("Connecting socket to the guard relay...")
        self._socket.connect((self._guard_relay.ip, self._guard_relay.tor_port))

    def _send_cell(self, cell):
        """Sends a cell to the guard relay.

        :type cell: Cell
        """
        self._socket.write(cell.get_bytes())

    def _retrieve_cell(self):
        """Waits for a cell response then parses it into a Cell object.

        :rtype: Cell
        """
        # https://docs.python.org/3/library/struct.html

        # Get the cell's circuit ID.
        # Link protocol 4 increases circuit ID width to 4 bytes.
        if self._protocol_versions and self._protocol_versions[len(self._protocol_versions) - 1] >= 4:
            circuit_id = struct.unpack("!i", self._socket.read(4))[0]
        else:
            circuit_id = struct.unpack("!H", self._socket.read(2))[0]

        # Get the cell's command.
        command = struct.unpack("!B", self._socket.read(1))[0]

        # Get the cell's payload.
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
        versions_cell = self._retrieve_cell()

        # When the "renegotiation" handshake is used, implementations
        # MUST list only the version 2.  When the "in-protocol" handshake is
        # used, implementations MUST NOT list any version before 3, and SHOULD
        # list at least version 3.
        log.debug("Supported link protocol versions: %s" % versions_cell.payload)
        self._protocol_versions = versions_cell.payload

    def _retrieve_certs(self):
        log.debug("Retrieving CERTS cell...")
        certs_cell = self._retrieve_cell()

        log.debug("Retrieving AUTH_CHALLENGE cell...")
        auth_cell = self._retrieve_cell()

    def _retrieve_net_info(self):
        log.debug("Retrieving NET_INFO cell...")
        net_info_cell = self._retrieve_cell()

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
        # The address format is a type/length/value sequence as given in
        # section 6.4 below, without the final TTL.
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
        self._socket.write(Cell(
            0, CommandType.NETINFO, [
                time(),
                0x04, 0x04, self._guard_relay.ip,
                0x01,
                0x04, 0x04, 0
            ]
        ).get_bytes())


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
        guard_relay = self._consensus.get_guard_relay()

        log.debug("Using guard relay \"%s\"..." % guard_relay.nickname)
        log.debug("Descriptor URL: %s" % guard_relay.get_descriptor_url())

        # Start communicating with the guard relay.
        tor_socket = TorSocket(guard_relay)


def main():
    parser = ArgumentParser()
    parser.add_argument("--host", help="the onion service to reach", required=True)
    parser.add_argument("--no-banner", help="prevent the TinyTor banner from being displayed", action="store_true")
    parser.add_argument("-v", "--verbose", help="enable verbose output", action="store_true")

    arguments = parser.parse_args()

    if not arguments.no_banner:
        print(BANNER)
    if not arguments.host.endswith(".onion"):
        log.error("Invalid onion service specified.")
        exit(1)
    if arguments.verbose:
        log.setLevel(logging.DEBUG)

    tinytor = TinyTor()
    tinytor.http_get("example.onion")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        log.error("Interrupted.")
        exit(0)
