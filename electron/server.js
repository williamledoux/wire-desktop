/*
 * Wire
 * Copyright (C) 2017 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

const minimist = require('minimist');
const argv = minimist(process.argv.slice(1));

// Command: asar pack dist/ app.wire.com.asar
const WEB_SERVER_PORT = argv.port;
const WEB_SERVER_LISTEN = '127.0.0.1';
const WEB_SERVER_FILES = argv.path;

//process.send({path: WEB_SERVER_FILES, port: WEB_SERVER_PORT});

const finalhandler = require('finalhandler');
const http = require('http');
const serveStatic = require('serve-static');

// Serve up public folder
const serve = serveStatic(WEB_SERVER_FILES, {
  'index': ['index.html']
});

// Create server
const server = http.createServer(function onRequest (req, res) {
  serve(req, res, finalhandler(req, res));
});

// Listen
server.listen(WEB_SERVER_PORT, WEB_SERVER_LISTEN);

process.send(JSON.stringify({
  started: true,
  message: `Listening on ${WEB_SERVER_LISTEN}:${WEB_SERVER_PORT}, path: ${WEB_SERVER_FILES}`
}));
