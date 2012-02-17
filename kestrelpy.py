#!/usr/bin/env python

"""
A Kestrel client library.
"""

import sys
import socket
import time
import os
import random
import re
from threading import local

__version__ = '0.1a'

SERVER_MAX_KEY_LENGTH = 250
#  kestrel required recompilation for values greater than 1MB,
#  Kestrel may not have this problem.  If you do, this value can be
#  changed by doing "kestrelpy.SERVER_MAX_VALUE_LENGTH = N" after
#  importing this module.
# TODO: Check value length for kestrel
SERVER_MAX_VALUE_LENGTH = 1024*1024

_SOCKET_TIMEOUT = 30

class _Error(Exception):
    pass


class _ConnectionDeadError(Exception):
    pass


class Client(local):
    """Kestrel queue client."""

    # exceptions for Client
    class KestrelKeyError(Exception):
        pass
    class KestrelKeyLengthError(KestrelKeyError):
        pass
    class KestrelKeyCharacterError(KestrelKeyError):
        pass
    class KestrelKeyNoneError(KestrelKeyError):
        pass
    class KestrelKeyTypeError(KestrelKeyError):
        pass
    class KestrelStringEncodingError(Exception):
        pass


    def __init__(self, servers, debug=0,
                 server_max_key_length=SERVER_MAX_KEY_LENGTH,
                 server_max_value_length=SERVER_MAX_VALUE_LENGTH,
                 socket_timeout=_SOCKET_TIMEOUT):
        """
        Create a new Client object with the given list of servers.

        @param servers: C{servers} is passed to L{set_servers}.
        @param debug: whether to display error messages when a server can't be
        contacted.
        @param socket_timeout: timeout in seconds for all calls to a server. Defaults
        to 3 seconds.
        @param server_max_key_length: (default SERVER_MAX_KEY_LENGTH)
        Data that is larger than this will not be sent to the server.
        @param server_max_value_length: (default SERVER_MAX_VALUE_LENGTH)
        Data that is larger than this will not be sent to the server.
        """
        local.__init__(self)
        self.debug = debug
        self.socket_timeout = socket_timeout
        self.set_servers(servers)
        self.stats = {}
        self.server_max_key_length = server_max_key_length
        self.server_max_value_length = server_max_value_length

    def set_servers(self, servers):
        """
        Set the pool of servers used by this client.

        @param servers: an array of servers.
        Servers can be passed in two forms:
            1. Strings of the form C{"host:port"}, which implies a default weight of 1.
            2. Tuples of the form C{("host:port", weight)}, where C{weight} is
            an integer weight value.
        """
        self.servers = [_Host(s, self.debug, 
                              socket_timeout=self.socket_timeout)
                        for s in servers]

    def _expectvalue(self, server, line=None):
        if not line:
            line = server.readline()

        if line and line[:5] == 'VALUE':
            resp, rkey, flags, len = line.split()
            flags = int(flags)
            rlen = int(len)
            return (rkey, flags, rlen)
        else:
            return (None, None, None)

    def _recv_value(self, server, flags, rlen):
        rlen += 2 # include \r\n
        buf = server.recv(rlen)
        if len(buf) != rlen:
            raise _Error("received %d bytes when expecting %d"
                    % (len(buf), rlen))

        if len(buf) == rlen:
            buf = buf[:-2]  # strip \r\n

        return buf

    def check_key(self, key, key_extra_len=0):
        """Checks sanity of key.  Fails if:
            Key length is > SERVER_MAX_KEY_LENGTH (Raises KestrelKeyLength).
            Contains control characters  (Raises KestrelKeyCharacterError).
            Is not a string (Raises KestrelStringEncodingError)
            Is an unicode string (Raises KestrelStringEncodingError)
            Is not a string (Raises KestrelKeyError)
            Is None (Raises KestrelKeyError)
        """
        if isinstance(key, tuple): key = key[1]
        if not key:
            raise Client.KestrelKeyNoneError("Key is None")
        if isinstance(key, unicode):
            raise Client.KestrelStringEncodingError(
                    "Keys must be str()'s, not unicode.  Convert your unicode "
                    "strings using mystring.encode(charset)!")
        if not isinstance(key, str):
            raise Client.KestrelKeyTypeError("Key must be str()'s")

        if isinstance(key, basestring):
            if self.server_max_key_length != 0 and \
                len(key) + key_extra_len > self.server_max_key_length:
                raise Client.KestrelKeyLengthError("Key length is > %s"
                         % self.server_max_key_length)
            for char in key:
                if ord(char) < 33 or ord(char) == 127:
                    raise Client.KestrelKeyCharacterError(
                            "Control characters not allowed")

    def _get_server(self, key):
        serverhash = random.randint(0, len(self.servers))
        server = self.servers[serverhash % len(self.servers)]
        if server.connect():
                return server, key

    def _get(self, key):
        cmd = "GET"
        self.check_key(key)
        server, key = self._get_server(key)

        self._statlog(cmd)

        server.send_cmd("%s %s" % (cmd, key, ))
        try:
            rkey, flags, rlen, = self._expectvalue(server)
        except socket.timeout, e:
            self.debuglog("socket timeout waiting for value")
            return None

        if not rkey:
            return None
        try:
            value = self._recv_value(server, flags, rlen)
        finally:
            server.expect("END")

        return value

    def _set(self, key, data, time):
        if not isinstance(data, str):
            raise TypeError('data must be of type string')
        self.check_key(key)
        self._statlog('set')

        server, key = self._get_server(key)
        flags = 0 # ignored by kestrel
        fullcmd = "set %s %d %d %d\r\n%s" % (key, flags, time, len(data), data)

        server.send_cmd(fullcmd)
        return(server.expect("STORED") == "STORED")


    def add(self, queue, data, expire=None):
        """Add a job onto the queue.

        WARNING:  You should only send strings through to the queue, if not
        the python-kestrel library will serialize these objects and since
        kestrel ignores the flags supplied during a set operation, when the
        object is retrieved from the queue it will not be unserialized.

        :param queue: The name of the key to work against
        :type queue: string
        :param data: The job itself
        :type data: mixed
        :param expire: The expiration time of the job, if a job doesn't get
            used in this amount of time, it will silently die away.
        :type expire: int
        :return: True/False
        :rtype: bool

        """

        if expire is None:
            expire = 0

        ret = self._set(queue, data, expire)

        if ret == 0:
            return False

        return True

    def get(self, queue, timeout=None):
        """Get a job off the queue. (unreliable)

        :param queue: The name of the key to work against
        :type queue: string
        :param timeout: The time to wait for a job if none are on the queue
            when the initial request is made. (seconds)
        :type timeout: int
        :return: The job
        :rtype: mixed

        """

        cmd = '%s' % (queue)

        if timeout is not None:
            cmd = '%s/t=%d' % (cmd, timeout)

        return self._get('%s' % (cmd))

    def next(self, queue, timeout=None):
        """Marks the last job as compelete and gets the next one.

        :param queue: The name of the key to work against
        :type queue: string
        :param timeout: The time to wait for a job if none are on the queue
            when the initial request is made. (seconds)
        :type timeout: int
        :return: The job
        :rtype: mixed

        """

        cmd = '%s/close' % (queue)

        if timeout is not None:
            cmd = '%s/t=%d' % (cmd, timeout)

        return self._get('%s/open' % (cmd))

    def peek(self, queue, timeout=None):
        """Copy a job from the queue, leaving the original in place.

        :param queue: The name of the key to work against
        :type queue: string
        :param timeout: The time to wait for a job if none are on the queue
            when the initial request is made. (seconds)
        :type timeout: int
        :return: The job
        :rtype: mixed

        """

        cmd = '%s/peek' % (queue)

        if timeout is not None:
            cmd = '%s/t=%d' % (cmd, timeout)

        return self._get(cmd)

    def abort(self, queue):
        """Mark a job as incomplete, making it available to another client.

        :param queue: The name of the key to work against
        :type queue: string
        :return: True on success
        :rtype: boolean

        """

        self._get('%s/abort' % (queue))
        return True

    def finish(self, queue):
        """Mark the last job read off the queue as complete on the server.

        :param queue: The name of the key to work against
        :type queue: string
        :return: True on success
        :rtype: bool

        """

        self._get('%s/close' % (queue))
        return True

    def delete(self, key):
        """Delete this queue from the kestrel server.

        :param queue: The name of the key to work against
        :type queue: string
        """

        self.check_key(key)
        server, key = self._get_server(key)
        self._statlog('delete')
        cmd = "delete %s" % key

        server.send_cmd(cmd)
        server.expect("END")

    def close(self):
        """Force the client to disconnect from the server.

        :return: True
        :rtype: bool

        """

        self.disconnect_all()
        return True

    def disconnect_all(self):
        for s in self.servers:
            s.close_socket()

    def flush(self, key):
        for s in self.servers:
            s.connect()
            s.send_cmd('FLUSH %s' % (key))
            s.expect('OK')

    def flush_all(self):
        'Expire all data currently in the kestrel servers.'
        for s in self.servers:
            s.connect()
            s.send_cmd('flush_all')
            s.expect("OK")

    def reload(self):
        """Forces the kestrel server to reload the config.

        :return: True
        :rtype: bool

        """
        for s in self.servers:
            s.connect()
            s.send_cmd('RELOAD')
            s.expect("OK")

    def get_stats(self):
        '''Get statistics from each of the servers.

        @param stat_args: Additional arguments to pass to the kestrel
            "stats" command.

        @return: A list of tuples ( server_identifier, stats_dictionary ).
            The dictionary contains a number of name/value pairs specifying
            the name of the status field and the string value associated with
            it.  The values are not converted from strings.
        '''
        data = []
        for s in self.servers:
            s.connect()

            if s.family == socket.AF_INET:
                name = '%s:%s (%s)' % ( s.ip, s.port, s.weight )
            else:
                name = 'unix:%s (%s)' % ( s.address, s.weight )
            s.send_cmd('stats')

            serverData = {}
            data.append(( name, serverData ))
            readline = s.readline
            while 1:
                line = readline()
                if not line or line.strip() == 'END': break
                stats = line.split(' ', 2)
                serverData[stats[1]] = stats[2]

        return(data)

    def debuglog(self, str):
        if self.debug:
            sys.stderr.write("Kestrel: %s\n" % str)

    def _statlog(self, func):
        if func not in self.stats:
            self.stats[func] = 1
        else:
            self.stats[func] += 1

    def version(self):
        """Get the version for the kestrel server.

        :return: The kestrel server version. e.g. 1.2.3
        :rtype: string

        """
        data = []
        for s in self.servers:
            s.connect()
            s.send_cmd('VERSION')
            data.append(s.readline())

        return ('\n').join(data).split(' ', 1)[1]


class _Host(object):

    def __init__(self, host, debug=0, socket_timeout=_SOCKET_TIMEOUT):
        self.socket_timeout = socket_timeout
        self.debug = debug

        #  parse the connection string
        m = re.match(r'^(?P<proto>unix):(?P<path>.*)$', host)
        if not m:
            m = re.match(r'^(?P<proto>inet):'
                    r'(?P<host>[^:]+)(:(?P<port>[0-9]+))?$', host)
        if not m: m = re.match(r'^(?P<host>[^:]+)(:(?P<port>[0-9]+))?$', host)
        if not m:
            raise ValueError('Unable to parse connection string: "%s"' % host)

        hostData = m.groupdict()
        if hostData.get('proto') == 'unix':
            self.family = socket.AF_UNIX
            self.address = hostData['path']
        else:
            self.family = socket.AF_INET
            self.ip = hostData['host']
            self.port = int(hostData.get('port', 11211))
            self.address = ( self.ip, self.port )

        self.socket = None

        self.buffer = ''

    def debuglog(self, str):
        if self.debug:
            sys.stderr.write("Kestrel: %s\n" % str)

    def connect(self):
        if self.socket:
            return self.socket
        s = socket.socket(self.family, socket.SOCK_STREAM)
        if hasattr(s, 'settimeout'): s.settimeout(self.socket_timeout)
        s.connect(self.address)
        self.socket = s
        self.buffer = ''
        return s

    def close_socket(self):
        if self.socket:
            self.socket.close()
            self.socket = None

    def send_cmd(self, cmd):
        self.socket.sendall(cmd + '\r\n')

    def send_cmds(self, cmds):
        """ cmds already has trailing \r\n's applied """
        self.socket.sendall(cmds)

    def readline(self):
        buf = self.buffer
        recv = self.socket.recv
        while True:
            index = buf.find('\r\n')
            if index >= 0:
                break
            data = recv(4096)
            if not data:
                # connection close, let's kill it and raise
                self.close_socket()
                raise _ConnectionDeadError()

            buf += data
        self.buffer = buf[index+2:]
        return buf[:index]

    def expect(self, text):
        line = self.readline()
        if line != text:
            self.debuglog("while expecting '%s', got unexpected response '%s'"
                    % (text, line))
        return line

    def recv(self, rlen):
        self_socket_recv = self.socket.recv
        buf = self.buffer
        while len(buf) < rlen:
            foo = self_socket_recv(max(rlen - len(buf), 4096))
            buf += foo
            if not foo:
                raise _Error( 'Read %d bytes, expecting %d, '
                        'read returned 0 length bytes' % ( len(buf), rlen ))
        self.buffer = buf[rlen:]
        return buf[:rlen]

    def __str__(self):
        d = ''

        if self.family == socket.AF_INET:
            return "inet:%s:%d%s" % (self.address[0], self.address[1], d)
        else:
            return "unix:%s%s" % (self.address, d)
