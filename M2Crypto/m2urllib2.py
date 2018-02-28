from __future__ import absolute_import

"""
M2Crypto enhancement to Python's urllib2 for handling
'https' url's.

Code from urllib2 is Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007
Python Software Foundation; All Rights Reserved

Summary of changes:
 - Use an HTTPSProxyConnection if the request is going through a proxy.
 - Add the SSL context to the https connection when performing https_open.
 - Add the M2Crypto HTTPSHandler when building a default opener.
"""

import socket

from M2Crypto import SSL, httpslib, six, util

from M2Crypto.six.moves.urllib_parse import urldefrag, urlparse as url_parse
from M2Crypto.six.moves.urllib_response import addinfourl
if util.py27plus:
    from typing import List, Optional  # noqa

# six.moves doesn't support star imports
if six.PY3:
    from urllib.request import *  # noqa other modules want to import
    from urllib.error import *  # noqa other modules want to import
else:
    from urllib2 import *  # noqa


try:
    mother_class = socket._fileobject
except AttributeError:
    mother_class = socket.SocketIO


class _closing_fileobject(mother_class):  # noqa
    """socket._fileobject that propagates self.close() to the socket.

    Python 2.5 provides this as socket._fileobject(sock, close=True).
    """

# for python 3
try:
    AbstractHTTPHandler
except NameError:
    # somehow this won't get imported by the import * above
    import urllib.request
    AbstractHTTPHandler = urllib.request.AbstractHTTPHandler


def _makefile(sock_like, mode, bufsize):
    if six.PY2:
        return socket._fileobject(sock_like, mode=mode, bufsize=bufsize,
                                  close=True)
    if not hasattr(sock_like, '_decref_socketios'):
        def _decref_sios(self):
            self.close()
        sock_like._decref_socketios = _decref_sios.__get__(sock_like,
                                                           type(sock_like))
    return socket.SocketIO(sock_like, mode)


class RefCountingSSLConnection(SSL.Connection):
    """A reference counting SSL connection.

    It can be wrapped into a socket._fileobject or socket.SocketIO instance.
    If the wrapping object is closed or subject to garbage collection,
    this SSL connection is only shut down if there are no more references,
    which were created by RefCountingSSLConnection.makefile, to it.
    """

    def __init__(self, *args, **kwargs):
        SSL.Connection.__init__(self, *args, **kwargs)
        self._refs = 0
        self._closed = False

    def _decref_socketios(self):
        if self._refs > 0:
            self._refs -= 1
        if self._refs == 0 and not self._closed:
            # make sure we close the connection only once
            # (otherwise we end up with a bidirectional shutdown)
            self._closed = True
            SSL.Connection.close(self)

    def close(self):
        self._decref_socketios()

    def makefile(self, mode='rb', bufsize=-1):
        self._refs += 1
        return _makefile(self, mode, bufsize)


class HTTPSHandler(AbstractHTTPHandler):
    def __init__(self, ssl_context=None,
                 ssl_conn_cls=RefCountingSSLConnection):
        # type: (SSL.Context) -> None
        AbstractHTTPHandler.__init__(self)

        if ssl_context is not None:
            assert isinstance(ssl_context, SSL.Context), ssl_context
            self.ctx = ssl_context
        else:
            self.ctx = SSL.Context()
        self._ssl_conn_cls = ssl_conn_cls

    # Copied from urllib2, so we can set the ssl context.
    def https_open(self, req):
        # type: (Request) -> addinfourl
        """Return an addinfourl object for the request, using http_class.

        http_class must implement the HTTPConnection API from httplib.
        The addinfourl return value is a file-like object.  It also
        has methods and attributes including:

            - info(): return a mimetools.Message object for the headers

            - geturl(): return the original request URL

            - code: HTTP status code
        """
        # https://docs.python.org/3.3/library/urllib.request.html#urllib.request.Request.get_host
        try:     # up to python-3.2
            host = req.get_host()
        except AttributeError:  # from python-3.3
            host = req.host
        if not host:
            raise URLError('no host given')

        # Our change: Check to see if we're using a proxy.
        # Then create an appropriate ssl-aware connection.
        full_url = req.get_full_url()
        target_host = url_parse(full_url)[1]

        if target_host != host:
            request_uri = urldefrag(full_url)[0]
            h = httpslib.ProxyHTTPSConnection(host=host, ssl_context=self.ctx,
                                              ssl_conn_cls=self._ssl_conn_cls)
        else:
            try:     # up to python-3.2
                request_uri = req.get_selector()
            except AttributeError:  # from python-3.3
                request_uri = req.selector
            h = httpslib.HTTPSConnection(host=host, ssl_context=self.ctx,
                                         ssl_conn_cls=self._ssl_conn_cls)
        # End our change
        h.set_debuglevel(self._debuglevel)

        headers = dict(req.headers)
        headers.update(req.unredirected_hdrs)
        # We want to make an HTTP/1.1 request, but the addinfourl
        # class isn't prepared to deal with a persistent connection.
        # It will try to read all remaining data from the socket,
        # which will block while the server waits for the next request.
        # So make sure the connection gets closed after the (only)
        # request.
        headers["Connection"] = "close"
        try:
            h.request(req.get_method(), request_uri, req.data, headers)
            r = h.getresponse()
        except socket.error as err:  # XXX what error?
            raise URLError(err)

        # Pick apart the HTTPResponse object to get the addinfourl
        # object initialized properly.

        # Wrap the HTTPResponse object in socket's file object adapter
        # for Windows.  That adapter calls recv(), so delegate recv()
        # to read().  This weird wrapping allows the returned object to
        # have readline() and readlines() methods.
        r.recv = r.read
        if six.PY3:
            r.ssl = h.sock.ssl
            r._timeout = -1.0
            # FIXME Meanwhile master has this:
            # r.recv_into = r.readinto
            # fp = socket.SocketIO(r, 'rb')
            r.recv_into = lambda b: SSL.Connection.recv_into(r, b)
        fp = _makefile(r, mode='rb', bufsize=-1)

        resp = addinfourl(fp, r.msg, req.get_full_url())
        resp.code = r.status
        resp.msg = r.reason
        return resp

    https_request = AbstractHTTPHandler.do_request_


# Copied from urllib2 with modifications for ssl
def build_opener(ssl_context=None, *handlers):
    # type: (Optional[SSL.Context], *object) -> OpenerDirector
    """Create an opener object from a list of handlers.

    The opener will use several default handlers, including support
    for HTTP and FTP.

    If any of the handlers passed as arguments are subclasses of the
    default handlers, the default handlers will not be used.
    """

    def isclass(obj):
        return isinstance(obj, type) or hasattr(obj, "__bases__")

    opener = OpenerDirector()
    default_classes = [ProxyHandler, UnknownHandler, HTTPHandler,
                       HTTPDefaultErrorHandler, HTTPRedirectHandler,
                       FTPHandler, FileHandler, HTTPErrorProcessor]
    skip = []
    for klass in default_classes:
        for check in handlers:
            if isclass(check):
                if issubclass(check, klass):
                    skip.append(klass)
            elif isinstance(check, klass):
                skip.append(klass)
    for klass in skip:
        default_classes.remove(klass)

    for klass in default_classes:
        opener.add_handler(klass())

    # Add the HTTPS handler with ssl_context
    if HTTPSHandler not in skip:
        opener.add_handler(HTTPSHandler(ssl_context))

    for h in handlers:
        if isclass(h):
            h = h()
        opener.add_handler(h)
    return opener
