'use strict';

var net = require('net'),
    http = require('http'),
    util = require('util'),
    minimist = require('minimist');

// TODO: agent?
// TODO: connect, read timeouts

var proxy = http.createServer(function (req, res) {
    protect(handleRequest, res)(req, res);
}).on('connect', function (req, clientSocket, head) {
    var res = new http.ServerResponse(req);
    res.assignSocket(clientSocket);
    protect(handleRequest, res)(req, res, head);
});

var main = module.exports = protect(function () {
    var options = minimist(process.argv.slice(2), {
        string: ['port', 'syslog'],
        default: {
            port: '8833'
        }
    });

    proxy.listen(options.port);
    console.log('fproxy: forwarding HTTP/HTTPS proxy server is listening on port ' + options.port);
}, true);

main();

function handleRequest (req, res, head) {
    res.req = req;
    var requestLine = [req.method, req.url, 'HTTP/'+req.httpVersion].join(' ');
    console.log(req.socket.remoteAddress, req.socket.remotePort, requestLine);

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
        forwardSocket.write(requestLine + '\r\n');
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
            throw new VisibleError(err.message, err, 502);
        } else if (err.code == 'EPIPE') {
            throw new VisibleError('Connection lost', err, 502);
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
        console.error('CRITICAL: Function '+func+' protected without response');
    }

    return function () {
        try {
            return func.apply(this, arguments);
        } catch (err) {
            var log = console.trace;
            if (err.name == 'VisibleError' && err.code) {
                log = console.log;
            }

            if (res && res.req) {
                log(res.req.socket.remoteAddress, res.req.socket.remotePort, err);
            } else {
                log(err);
            }

            if (res && res !== true) {
                if (err.name == 'VisibleError') {
                    fail(res, err.message, err.code);
                } else {
                    fail(res);
                }
            }
        }
    };
}

function fail (res, message, code) {
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
