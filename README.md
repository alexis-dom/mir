# Welcome to MIR

## What's MIR?

MIR is a small project that I am working on, that executes python scripts hosted on GitHub, using Tor as a Proxy.
Every HTTP request that Python makes, goes thru the Onion Network.

Our main goal is to provide some basic tools, that protects your Internet Identity, and can be run on any public computer without using admin rights.

## First steps

1. Download and install Tor
   [Tor Project](https://www.torproject.org/download/)
2. Using Tor:
   1. Download and install Python 3.9 or above
      [Python](https://www.python.org/downloads/)
   2. Download mir/boot file, and save it as boot.py
      [boot.py](https://raw.githubusercontent.com/alexis-dom/mir/main/boot)
   3. Run boot.py
   4. type check

### Troubleshooting

Most of the errors you will get is because you are not currently running Tor. 
You must have Tor browser running, or else you won't be able to use MIR.

### Known Issues

If the site you are trying to reach is behind CloudFlare, you will get 403 errors, no matter what.
Still need to figure it out if it is because of urllib HTTP/1.1 requests, or because we are using Tor Proxy.

#### Contact

Mastodon: @alexis@mas.to
