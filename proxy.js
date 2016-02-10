'use strict';

var net = require('net'),
    http = require('http'),
    util = require('util'),
    minimist = require('minimist');

// TODO: read timeouts

var proxy = http.createServer(function (req, res) {
    protect(handleRequest, res)(req, res);
}).on('connect', function (req, clientSocket, head) {
    var res = new http.ServerResponse(req);
    res.assignSocket(clientSocket);
    protect(handleConnect, res)(req, res, head);
});

var main = module.exports = protect(function () {
    var options = minimist(process.argv.slice(2), {
        string: ['port'],
        default: {
            port: '8833'
        }
    });

    proxy.listen(options.port);
    console.log('<5>fproxy: forwarding HTTP/HTTPS proxy server is listening on port ' + options.port);

    process.on('SIGTERM', function () {
        process.exit(0);
    });

    process.on('SIGINT', function () {
        process.exit(0);
    });
}, true);

main();

function prepareRequest (req, res) {
    res.req = req;
    req.line = [req.method, req.url, 'HTTP/'+req.httpVersion].join(' ');

    var downstream = getDownstreamProxy(req);
    logRequest(req, downstream);

    return downstream;
}

function handleConnect (req, res, head) {
    var downstream = prepareRequest(req, res);

    try {
        var downstreamSocket = net.connect({
            host: downstream.host,
            port: downstream.port
        });
    } catch (err) {
        if (err.name == 'RangeError') {
            throw new FProxyError('Invalid downstream proxy port', err, 400);
        } else {
            throw err;
        }
    }

    req.socket.pipe(downstreamSocket);

    downstreamSocket.on('connect', protect(function () {
        downstreamSocket.pipe(res.socket);

        downstreamSocket.write(req.line + '\r\n');
        Object.keys(req.headers).forEach(function (headerName) {
            var headerValue = req.headers[headerName];
            downstreamSocket.write(headerName + ': ' + headerValue + '\r\n');
        });
        downstreamSocket.write('\r\n');
        if (head) {
            downstreamSocket.write(head);
        }
    }, res));

    handleDownstreamErrors(downstreamSocket, res);
}

function handleRequest (req, res) {
    var downstream = prepareRequest(req, res);

    try {
        var downstreamReq = http.request({
            port: downstream['port'],
            hostname: downstream['host'],
            method: req.method,
            path: req.url,
            headers: req.headers
        });
    } catch (err) {
        if (err.name == 'RangeError') {
            throw new FProxyError('Invalid downstream proxy port', err, 400);
        } else {
            throw err;
        }
    }

    req.pipe(downstreamReq);

    downstreamReq.on('response', protect(function (downstreamRes) {
        downstreamRes.pipe(res);
        res.writeHead(downstreamRes.statusCode, downstreamRes.headers);
    }, res));

    handleDownstreamErrors(downstreamReq, res);
}

function getDownstreamProxy (req) {
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
        throw new FProxyError('Missing Proxy-Authorization header', null, 400);
    }
    delete req.headers['proxy-authorization'];

    var parts = header.split(' ', 2);
    if (parts.length != 2) {
        throw new FProxyError('Invalid Proxy-Authorization header', null, 400);

    }
    var authMethod = parts[0],
        downstream = parts[1];

    if (authMethod.toLowerCase() != 'basic') {
        throw new FProxyError('Invalid Proxy-Authorization method (only basic supported)', null, 400);
    }

    downstream = new Buffer(downstream, 'base64').toString();
    parts = downstream.split(',', 3);
    if (parts.length != 3) {
        throw new FProxyError('Invalid Proxy-Authorization header format', null, 400);
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

function handleDownstreamErrors (downstream, res) {
    downstream.on('error', protect(function (err) {
        downstream.destroy();

        if (err.code == 'ECONNREFUSED') {
            throw new FProxyError(err.message, err, 502);
        } else if (err.code == 'EPIPE') {
            throw new FProxyError('Downstream connection lost', err, 502);
        } else if (err.code == 'HPE_INVALID_CONSTANT') {
            throw new FProxyError('Invalid downstream response', err, 502);
        } else if (err.code == 'ETIMEDOUT') {
            throw new FProxyError(err.message, err, 502);
        } else if (err.code == 'ECONNRESET') {
            throw new FProxyError(err.message, err, 502);
        } else if (err.code == 'EHOSTUNREACH') {
            throw new FProxyError(err.message, err, 502);
        } else if (err.code == 'ENETUNREACH') {
            throw new FProxyError(err.message, err, 502);
        } else {
            throw err;
        }
    }, res));
}

function protect (func, res) {
    if (!res) {
        console.error('<2>CRITICAL: Function '+func+' protected without response');
    }

    return function () {
        try {
            return func.apply(this, arguments);
        } catch (err) {
            var log = console.error,
                prefix = '<3>';
            if (err.name == 'FProxyError' && err.code) {
                log = console.log;
                prefix = '<5>';
            }

            if (res && res.req) {
                log(prefix, res.req.socket.remoteAddress, res.req.socket.remotePort, addPrefix(err.toString(), prefix));
            } else {
                log(prefix + addPrefix(err.toString(), prefix));
            }

            if (log == console.error && err.stack) {
                log(prefix + addPrefix(err.stack, prefix));
            }

            if (res && res !== true) {
                if (err.name == 'FProxyError') {
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

function addPrefix (message, prefix) {
    return message.split('\n').join('\n' + prefix);
}

function logRequest (req, downstream) {
    console.log('<6>', req.socket.remoteAddress, req.socket.remotePort, req.line, 'via',
        downstream['host'] + ':' + downstream['port']);
}

function FProxyError (message, reason, code) {
    Error.call(this, message);
    this.message = message;
    this.reason = reason;
    this.code = code;
}

util.inherits(FProxyError, Error);
FProxyError.prototype.name = 'FProxyError';
