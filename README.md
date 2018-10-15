<h1 align="center">
  <br>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="https://github.com/Marten4n6/TinyTor"><img src="https://i.imgur.com/BRgdHy3.png" alt="Logo" width="370"></a>
  <br>
  TinyTor
  <br>
</h1>

<h4 align="center">A tiny Tor client implementation (written in python).</h4>

<p align="center">
  <a href="https://github.com/Marten4n6/TinyTor/blob/master/LICENSE.txt">
      <img src="https://img.shields.io/badge/license-GPLv3-blue.svg?style=flat-square" alt="License">
  </a>
  <a href="https://www.python.org/">
      <img src="https://img.shields.io/badge/python-2.7,%203.7-blue.svg?style=flat-square" alt="Python">
  </a>
  <a href="https://github.com/Marten4n6/TinyTor/issues">
    <img src="https://img.shields.io/github/issues/Marten4n6/TinyTor.svg?style=flat-square" alt="Issues">
  </a>
  <a href="https://travis-ci.org/Marten4n6/TinyTor">
      <img src="https://img.shields.io/travis/Marten4n6/TinyTor/master.svg?style=flat-square" alt="Build Status">
  </a>
  <a href="https://github.com/Marten4n6/TinyTor">
      <img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat-square" alt="Contributing">
  </a>
</p>

---

## Features

TinyTor can be used to communicate with [onion services](https://www.torproject.org/docs/onion-services.html) via [Tor](https://www.torproject.org/about/overview#thesolution). <br/>
Furthermore, it may be used by developers as a simple library. <br/>

**If you're reading this, this implementation is NOT FINISHED yet.**

## How To Use

```bash
# Download or clone this repository
$ git clone https://github.com/Marten4n6/TinyTor

# Go into the repository
$ cd TinyTor

# Send a HTTP request over Tor
$ python tinytor.py --host example.onion
```

### For Developers

```python
from tinytor import TinyTor

tor = TinyTor()
print(tor.http_get("example.onion"))
```

## Motivation

TinyTor was created to communicate anonymously in [EvilOSX](https://github.com/Marten4n6/EvilOSX). <br/>
It's goal is to run **natively** on Linux/macOS, live in a single file and be as small as possible.

## Technical details

TinyTor uses the system's OpenSSL for encryption. <br/>
Because macOS uses [LibreSSL](https://www.libressl.org/) which doesn't currently support curve25519, the TAP handshake is used (instead of NTOR).

| Name                  | Description                                                             |
| --------------------- | ----------------------------------------------------------------------- |
| Entry / guard relay   | This is the entry point to the Tor network.                             |
| Middle relay          | Prevents the guard and exit relay from knowing each other.              |
| Exit relay            | Sends traffic to the final destination intended by the client.          |
| Directory authority   | A trusted server where information about the Tor network is stored.     |
| Consensus             | A document where all Tor relays is maintained.                          |
| Descriptor            | Contains the public keys and other information about a relay.           |
| Cell                  | A command request/response used when communicating with onion routers.  |
| Circuit               | A path through the network connecting a client to its destination.      |

The following steps are followed to create a request over the Tor network:

## Versioning

TinyTor will be maintained under the Semantic Versioning guidelines as much as possible. <br/>
Releases will be numbered with the follow format:
```
<major>.<minor>.<patch>
```

And constructed with the following guidelines:
- Breaking backward compatibility bumps the major
- New additions without breaking backward compatibility bumps the minor
- Bug fixes and misc changes bump the patch

For more information on SemVer, please visit https://semver.org/.

## Disclaimer

This project is <b>NOT</b> related to the official Tor Project. <br/>
For anything dependent on your privacy/security, please use the [Tor Browser](https://www.torproject.org/download/download-easy.html).

## Support Tor

The Tor network relies on volunteers to donate bandwidth. <br/>
<b>Please consider running a relay.</b> You can help make the Tor network:
- faster (and therefore more usable)
- more robust against attacks
- more stable in case of outages
- safer for its users (spying on more relays is harder than on a few)

For more information on volunteering, please visit https://www.torproject.org/getinvolved/volunteer.html.

## Issues

Feel free to submit any issues or concerns [here](https://github.com/Marten4n6/TinyTor/issues).

## References

- [Tor Protocol Specification](https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt)
- [Mini-tor](https://github.com/wbenny/mini-tor)
- [Struct](https://docs.python.org/3/library/struct.html)
- How Tor Works: Part
  [1](https://jordan-wright.com/blog/2015/02/28/how-tor-works-part-one/),
  [2](https://jordan-wright.com/blog/2015/05/09/how-tor-works-part-two-relays-vs-bridges/),
  [3](https://jordan-wright.com/blog/2015/05/14/how-tor-works-part-three-the-consensus/)
- Logo created by [motusora](https://www.behance.net/motusora)

## License

[GPLv3](https://github.com/Marten4n6/TinyTor/blob/master/LICENSE.txt)
