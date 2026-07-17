const http = require('http');

function handleAuth(req) {
    return parseToken(req.headers.authorization);
}

function parseToken(header) {
    if (!header) return null;
    return header.split(' ')[1];
}

module.exports = { handleAuth, parseToken };
