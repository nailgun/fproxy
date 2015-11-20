var http = require('http');
var net = require('net');
var util = require('util');

// TODO: agent?
// TODO: logging, options

// Create an HTTP tunneling proxy
var proxy = http.createServer(function (req, res) {
    console.log(req.url);  // TODO: logging
    protect(handleRequest, res)(req, res);
});

proxy.on('connect', function(req, clientSocket, head) {
    console.log(req.url);  // TODO: logging
    var res = new http.ServerResponse(req);
    res.assignSocket(clientSocket);
    protect(handleRequest, res)(req, res, head);
});

proxy.listen(1337);

function handleRequest (req, res, head) {
    var downsteam = getDownstreamProxy(req, res);

    try {
        var forwardSocket = net.connect({
            host: downsteam.host,
            port: downsteam.port
        });
    } catch (err) {
        if (err.name == 'RangeError') {
            throw new VisibleError('Invalid downstream proxy port', err, 400);
        } else {
            throw err;
        }
    }

    forwardSocket.on('connect', protect(function () {
        // TODO: try to wrap with clientresponse
        forwardSocket.write(req.method + ' ' + req.url + ' HTTP/' + req.httpVersion+'\r\n');
        Object.keys(req.headers).forEach(function (headerName) {
            var headerValue = req.headers[headerName];
            forwardSocket.write(headerName + ': ' + headerValue + '\r\n');
        });
        forwardSocket.write('\r\n');
        if (head) {
            forwardSocket.write(head);
        }

        forwardSocket.pipe(res.socket);

        if (req.method.toLowerCase() == 'connect') {
            req.socket.pipe(forwardSocket);
        } else {
            req.pipe(forwardSocket);
        }
    }, res));

    forwardSocket.on('error', protect(function (err) {
        forwardSocket.destroy();

        if (err.code == 'ECONNREFUSED') {
            throw new VisibleError(err.message, err);
        } else if (err.code == 'EPIPE') {
            throw new VisibleError('Connection lost', err);
        } else {
            throw err;
        }
    }, res));
}

function getDownstreamProxy (req, res) {
    /*
     * Downstream proxy configuration is taken from Proxy-Authorization header.
     * We can't use custom header here, because most HTTPS clients don't send any
     * HTTP header to a proxy except Proxy-Authorization.
     *
     * For example, to connect via fproxy running at 127.0.0.2:8833
     * and via downstream proxy user:pass@127.0.0.1:8080, issue the following command:
     *
     * curl -vx http://127.0.0.1,8080,user:pass@127.0.0.2:8833/ http://httpbin.org/headers
     */
    var header = req.headers['proxy-authorization'];
    if (!header) {
        throw new VisibleError(res, 'Missing Proxy-Downstream-Proxy or Proxy-Authorization header', null, 400);
    }
    delete req.headers['proxy-authorization'];

    var parts = header.split(' ', 2);
    if (parts.length != 2) {
        throw new VisibleError('Invalid Proxy-Authorization header', null, 400);

    }
    var authMethod = parts[0],
        downstream = parts[1];

    if (authMethod.toLowerCase() != 'basic') {
        throw new VisibleError(res, 'Invalid Proxy-Authorization method (only basic supported)', null, 400);
    }

    downstream = new Buffer(downstream, 'base64').toString();
    parts = downstream.split(',', 3);
    if (parts.length != 3) {
        throw new VisibleError('Invalid Proxy-Authorization header format', null, 400);
    }

    var host = parts[0],
        port = parts[1],
        auth = parts[2];

    if (auth) {
        req.headers['proxy-authorization'] = 'Basic ' + new Buffer(auth).toString('base64');
    }

    return {
        host: host,
        port: port
    };
}

function protect (func, res) {
    if (!res) {
        // TODO: logging
        console.error('CRITICAL: Function '+func+' protected without response');
    }

    return function () {
        try {
            return func.apply(this, arguments);
        } catch (err) {
            if (res) {
                if (err.name == 'VisibleError') {
                    fail(res, err.message, err.code);
                } else {
                    fail(res);
                }
            }

            // TODO: logging
            console.error(err);
        }
    }
}

function fail (res, message, code) {
    // TODO: ServerResponse sends Connection header (but should be proxy-connection)
    res.writeHead(code || 502, {
        'Content-Type': 'text/plain'
    });

    res.end('fproxy: ' + (message || 'Error'));
}

function VisibleError (message, reason, code) {
    Error.call(this, message);
    this.message = message;
    this.reason = reason;
    this.code = code;
}

util.inherits(VisibleError, Error);
VisibleError.prototype.name = 'VisibleError';
