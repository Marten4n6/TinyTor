<h1 align="center">
  <br>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="https://github.com/Marten4n6/TinyTor"><img src="https://i.imgur.com/BRgdHy3.png" alt="Logo" width="370"></a>
  <br>
  TinyTor
  <br>
</h1>

<h4 align="center">A tiny Tor client implementation (in pure python).</h4>

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
  <a href="https://github.com/Marten4n6/TinyTor/pulls">
      <img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat-square" alt="Contributing">
  </a>
</p>

---

## Features

TinyTor can be used to communicate with [onion services](https://www.torproject.org/docs/onion-services.html) via [Tor](https://www.torproject.org/about/overview#thesolution). <br/>
It may be used by developers as a [python package](https://pypi.org/project/tinytor/) or as a command line utility. <br/>

The goals are to have **no dependencies**, live in a **single file** and be **as small as possible**. <br/>
The current file size of TinyTor is only ~37KB (uncompressed). <br/>

**Some warnings**:
- TinyTor assumes OpenSSL is installed on the running machine (native on Linux/macOS)
- This project is **not** related to the official Tor Project
- For anything dependent on your privacy, please use the [Tor Browser](https://www.torproject.org/download/download-easy.html) or [Tails OS](https://tails.boum.org/)

## How To Use

```bash
# Install TinyTor
$ sudo pip3 install tinytor

# Send a HTTP request over Tor
$ tinytor --host example.onion --verbose
```

### From Source
```bash
# Download or clone this repository
$ git clone https://github.com/Marten4n6/TinyTor

# Go into the repository
$ cd TinyTor

# Send a HTTP request over Tor
$ python tinytor.py --host example.onion --verbose
```

### For Developers

```python
from tinytor import TinyTor

tor = TinyTor()
print(tor.http_get("example.onion"))
```

## Motivation

TinyTor was created to communicate anonymously in [EvilOSX](https://github.com/Marten4n6/EvilOSX). <br/>
[compressed.py](https://github.com/Marten4n6/TinyTor/blob/master/compressed.py) is used in EvilOSX, which compresses TinyTor to a *much* smaller size (about ~9KB).

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

## Support Tor

The Tor network relies on volunteers to donate bandwidth. <br/>
<b>Please consider running a relay.</b> You can help make the Tor network:
- faster (and therefore more usable)
- more robust against attacks
- more stable in case of outages
- safer for its users (spying on more relays is harder than on a few)

For more information on volunteering, please visit https://www.torproject.org/getinvolved/volunteer.html.

## Issues

Feel free to submit any issues [here](https://github.com/Marten4n6/TinyTor/issues).

## References

- [Tor Protocol Specification](https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt)
- [Mini-tor](https://github.com/wbenny/mini-tor)
- [Pycepa](https://github.com/pycepa/pycepa)
- [Struct](https://docs.python.org/3/library/struct.html)
- How Tor Works: Part
  [1](https://jordan-wright.com/blog/2015/02/28/how-tor-works-part-one/),
  [2](https://jordan-wright.com/blog/2015/05/09/how-tor-works-part-two-relays-vs-bridges/),
  [3](https://jordan-wright.com/blog/2015/05/14/how-tor-works-part-three-the-consensus/)
- Thanks to [Lucas Ontivero](https://github.com/lontivero) for his code contributions
- Logo created by [motusora](https://www.behance.net/motusora)

## License

[GPLv3](https://github.com/Marten4n6/TinyTor/blob/master/LICENSE.txt)
