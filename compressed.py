#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Creates a compressed (as small as possible) version of TinyTor.

NOTICE:
    This was created to be used in EvilOSX (https://github.com/Marten4n6/EvilOSX).
    Please DO NOT USE this, instead use pip (as usual)!
"""
__author__ = "Marten4n6"
__license__ = "GPLv3"

import math
from base64 import b64encode
from hashlib import sha256
from os import path
from sys import exit
from zlib import compress


def convert_size(size_bytes):
    """Converts a byte size to a human readable format.

    :type size_bytes: int
    :rtype: str
    """
    if size_bytes == 0:
        return "0B"

    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)

    return "%s %s" % (s, size_name[i])


def main():
    source_path = path.join(path.dirname(__file__), "tinytor.py")

    with open(source_path, "r") as input_file:
        print("[WARNING] This was created to be used in EvilOSX (https://github.com/Marten4n6/EvilOSX).")
        print("[WARNING] Please DO NOT USE this, instead use pip (as usual)!")
        print("[INFO] Compressing TinyTor (%s)..." % source_path)

        modified_source = ""
        previous_line = ""
        middle_of_docstring = False

        for line in input_file:
            if line.strip().startswith("# "):
                # Strip out comments.
                # print("[DEBUG] Skipping: " + line.replace("\n", ""))
                continue
            elif line.strip().startswith('"""') or middle_of_docstring:
                # Strip out docstrings.
                if len(line.split('"""')) == 3:
                    # Two occurrences found, this is a single line docstring.
                    # print("[DEBUG] Skipping: " + line.replace("\n", ""))
                    continue
                else:
                    previous_line_last_char = previous_line.replace("\n", "")[(len(previous_line) - 2):]

                    if line.strip().startswith('"""'):
                        if previous_line_last_char == ":":
                            # Start of a docstring.
                            # print("[DEBUG] Skipping: " + line.replace("\n", ""))

                            middle_of_docstring = True
                            previous_line = line
                            continue
                        elif middle_of_docstring:
                            # End of a docstring.
                            # print("[DEBUG] Skipping: " + line.replace("\n", ""))

                            middle_of_docstring = False
                            previous_line = line
                            continue

                    if middle_of_docstring:
                        # print("[DEBUG] Skipping: " + line.replace("\n", ""))
                        continue
                    else:
                        modified_source += line
            else:
                modified_source += line
                previous_line = line

        encoded_and_compressed = compress(b64encode(modified_source.encode()))

        bytes_hash = sha256()
        bytes_hash.update(encoded_and_compressed)

        print("[INFO] Old size: " + convert_size(path.getsize(source_path)))
        print("[INFO] New size: " + convert_size(len(encoded_and_compressed)))
        print("[INFO] Python code to dynamically load and use this library:")

        print("======== BEGIN PYTHON CODE ========")
        print("from base64 import b64decode")
        print("from zlib import decompress")
        print("")
        print("# The following is a compressed version of TinyTor (https://github.com/Marten4n6/TinyTor).")
        print("# The source code which generated this is also available there.")
        print("# It's understandable that you wouldn't trust random bytes like this.")
        print("# The SHA256 hash of the bytes is: " + bytes_hash.hexdigest())
        print("tor = %s" % str(encoded_and_compressed))
        print("tor_dict = {}")
        print("exec(b64decode(decompress(tor)), tor_dict)")
        print("")
        print("# Sends a HTTP request over Tor.")
        print('exec("tor = TinyTor()", tor_dict)')
        print('exec(\'tor.http_get("http://example.onion")\', tor_dict)')
        print("======== END PYTHON CODE   ========")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        exit(0)
