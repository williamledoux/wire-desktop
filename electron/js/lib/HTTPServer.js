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

const crypto = require('crypto');
const debug = require('debug');
const finalhandler = require('finalhandler');
const http = require('http');
const serveStatic = require('serve-static');

// Web server CSP
const CSP = [
    "default-src 'none'",
    "connect-src 'self' blob: https://*.giphy.com https://apis.google.com https://www.google.com https://maps.googleapis.com https://*.localytics.com https://api.raygun.io https://*.unsplash.com https://wire.com https://*.wire.com wss://prod-nginz-ssl.wire.com https://*.zinfra.io wss://*.zinfra.io",
    "font-src 'self'",
    //"frame-src 'self' https://accounts.google.com https://*.soundcloud.com https://*.spotify.com https://*.vimeo.com https://*.youtube-nocookie.com",
    "img-src 'self' blob: data: https://*.giphy.com https://*.localytics.com https://*.wire.com https://*.cloudfront.net https://*.zinfra.io",
    // Note: The "blob:" attribute needs to be explicitly set for Chrome 47+: https://code.google.com/p/chromium/issues/detail?id=473904
    "media-src blob: data: *",
    "object-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://apis.google.com https://*.localytics.com https://api.raygun.io https://*.wire.com https://*.zinfra.io",
    "style-src 'self' 'unsafe-inline' https://*.wire.com",

    // Future options
    "worker-src 'self'", // Disabled for now in Chrome behind a flag
    //"referrer no-referrer",
    //"reflected-xss block",
    //"disown-opener",
    //"require-sri-for script style",

    // Broken because of <webview>
    //"sandbox allow-scripts allow-forms allow-same-origin",

    // Electron related
    //"plugin-types application/browser-plugin" // Allow to extend object feature (webview) (only needed if sandbox)
  ].join(';');

class HTTPServer {

  constructor(resolve, options) {

    for(let option in options) {
      this[option] = options[option];
    }

    this.debug = debug('HTTPServer');
    this.maxRetryBeforeReject = 10;
    this.accessToken = false;

    // Prepare serveStatic to serve up public folder
    this.serve = serveStatic(this.WEB_SERVER_FILES, {
      index: ['index.html'],
      setHeaders: (res, path) => {

        // Add security-related headers
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'deny');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Referrer-Header', 'no-referrer');
        res.setHeader('Content-Security-Policy', CSP);

        // Force no cache
        res.setHeader('Cache-Control', 'no-cache');
      }
    });

    // Ensure WEB_SERVER_TOKEN_NAME is alphanumeric only
    if(!this.WEB_SERVER_TOKEN_NAME.match(/^[a-zA-Z0-9]*$/)) {
      this.debug('Token name must be alphanumeric, aborting');
      return false;
    }

    // Create the HTTP server
    this.createServer();

    // Generate the credentials that will be used to validate HTTP requests
    this.generateToken().then((token) => {

      // Expose the token to the class
      this.accessToken = token;

      // Start the webserver
      this.debug('Web server is starting');
      return this.tryToListen();

    }).then((usedPort, accessToken) => {
      this.debug('Web server has started');

      if(resolve) {
        resolve({
          usedPort: usedPort,
          accessToken: this.accessToken,
        });
      }
    });
  }

  generateToken() {
    return new Promise((resolve, reject) => {
      crypto.randomBytes(128, (err, buffer) => {
        if(err) {
          reject(err);
          return false;
        }
        resolve(buffer.toString('base64'));
      });
    });
  }

  createServer() {
    const createServerDebug = debug('ElectronWrapperInit:createServer');

    // Function that terminate the connection
    const end = (res) => {
        res.socket.end();
        res.end();
    };

    this.server = http.createServer((req, res) => {
      const authorizationHeader = req.headers['authorization'];

      // Don't accept requests if accessToken or Authorization header is not a string
      if(typeof this.accessToken !== 'string' || typeof authorizationHeader !== 'string') {
        createServerDebug('Cancelled a request because accessToken and/or authorization header was empty');
        return end(res);
      }

      // Check the token
      if(this.accessToken !== authorizationHeader.replace(new RegExp(`^${this.WEB_SERVER_TOKEN_NAME} `, 'g'), '')) {
        createServerDebug('Cancelled a request because Authorization header was invalid');
        return end(res);
      }

      // Serve the file normally
      //createServerDebug('Serving an authorized request');
      this.serve(req, res, finalhandler(req, res));
    });
  }

  tryToListen(retry = 0) {
    return new Promise((resolve, reject) => {

      // Ensure we do not reach the max retry limit
      if(retry >= this.maxRetryBeforeReject) {
        reject();
        return;
      }

      // Get a random port using Math.random
      const portToUse = Math.round(Math.random() * (65534 - 10000) + 10000) - 1;

      // Listen on the port
      this.debug('Listening on %s:%d, path: %s', this.WEB_SERVER_LISTEN, portToUse, this.WEB_SERVER_FILES);
      this.server.listen(portToUse, this.WEB_SERVER_LISTEN, () => {

        // Everything is okay, resolving the promise
        resolve(portToUse);

      }).once('error', (e) => {

        // Port is probably taken, let's try again
        if(typeof e !== 'undefined') {
          this.debug('Unable to listen on %d, retrying with another port...', portToUse);
          return this.tryToListen(++retry);
        }
      });
    });
  }
}

module.exports = HTTPServer;
