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

// ToDo: Make YT videos fullscreen?
// ToDo: Full sandbox check (webview / webframe / desktopsharing)
// ToDo: See for the Electron crash protocol fix
// ToDo: Start working on app updating process
// ToDo: Refactor preload.js
// ToDo: Add port changing logic if the port is taken for the web server
// ToDo: Find a better way to generate random numbers
// ToDo: CORS on local network (add same CSP as app.wire.com)

'use strict';

// Modules
const {app, BrowserWindow, ipcMain, Menu, shell, protocol} = require('electron');
const fs = require('fs');
const minimist = require('minimist');
const path = require('path');
const raygun = require('raygun');
const debug = require('debug');
const finalhandler = require('finalhandler');
const http = require('http');
const serveStatic = require('serve-static');

// Paths
const APP_PATH = app.getAppPath();
const USER_DATAS_PATH = app.getPath('userData');

// Wrapper modules
const certutils = require('./js/certutils');
const download = require('./js/lib/download');
const googleAuth = require('./js/lib/googleAuth');
const init = require('./js/lib/init');
const locale = require('./locale/locale');
const systemMenu = require('./js/menu/system');
const developerMenu = require('./js/menu/developer');
const tray = require('./js/menu/tray');
const util = require('./js/util');
const windowManager = require('./js/window-manager');

// Web server options
const WEB_SERVER_LISTEN = '127.0.0.1';
const WEB_SERVER_HOST = 'wire://prod.local';
const WEB_SERVER_FILES = path.join(USER_DATAS_PATH, 'app.wire.com.asar');

// Config
const argv = minimist(process.argv.slice(1));
const config = require('./js/config');
const ALLOWED_WEBVIEWS_ORIGIN = config.ALLOWED_WEBVIEWS_ORIGIN;

const PRELOAD_JS = path.join(APP_PATH, 'js', 'preload.js');
const WRAPPER_CSS = path.join(APP_PATH, 'css', 'wrapper.css');

// Static pages
const SPLASH_HTML = 'file://' + path.join(APP_PATH, 'html', 'splash.html');
const CERT_ERR_HTML = 'file://' + path.join(APP_PATH, 'html', 'certificate-error.html');
const ABOUT_HTML = 'file://' + path.join(APP_PATH, 'html', 'about.html');

const ICON = 'wire.' + ((process.platform === 'win32') ? 'ico' : 'png');
const ICON_PATH = path.join(APP_PATH, 'img', ICON);

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
    //"plugin-types application/browser-plugin" // Allow to extend object feature (webview)
  ].join(';');

class HTTPServer {

  constructor(resolve) {

    this.debug = debug('HTTPServer');
    this.resolve = resolve;
    this.maxRetryBeforeReject = 3;

    // Prepare serveStatic to serve up public folder
    this.serve = serveStatic(WEB_SERVER_FILES, {
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

    // Create the HTTP server
    this.createServer();

    // Start the webserver
    this.debug('tryToListen init');
    this.tryToListen().then(() => {
      this.debug('tryToListen OK');
      resolve({
        usedPort: this.portToUse
      });
    });

    return this.server;
  }

  createServer() {
    this.server = http.createServer((req, res) => {
      this.serve(req, res, finalhandler(req, res));
    });
  }

  tryToListen(retry = 0) {
    return new Promise((resolve) => {

      // Ensure we do not reach the max retry limit
      if(retry >= this.maxRetryBeforeReject) {
        return;
      }

      // Get a random port using Math.random
      this.portToUse = Math.round(Math.random() * (65534 - 10000) + 10000) - 1;

      // Listen on the port
      this.debug(`Listening on ${WEB_SERVER_LISTEN}:${this.portToUse}, path: ${WEB_SERVER_FILES}`);
      this.server.listen(this.portToUse, WEB_SERVER_LISTEN, () => {

        // Everything is okay, resolving the promise
        this.debug('Web server has started');
        resolve();

      }).on('error', (e) => {

        // Port is probably taken, let's try again
        if(typeof e !== 'undefined') {
          this.debug(`Unable to listen on ${this.portToUse}, retrying with another port...`);
          this.tryToListen(++retry);
          return false;
        }
      });
    });
  }
}

class ElectronWrapperInit {

  constructor() {

    this.main = false;
    this.browserWindow = false;
    this.browserWindowAbout = false;
    this.enteredWebapp = false;
    this.webServerStarted = false;
    this.shouldQuit = false;
    this.webappVersion = false;
    this.raygunClient = false;
    this.debug = debug('ElectronWrapperInit');

    this.debug('webviewProtection init');
    this.webviewProtection();

    this.debug('platformFixes init');
    this.platformFixes();

    this.debug('appEvents init');
    this.appEvents();

    this.debug('cleanupLogFile init');
    this.cleanupLogFile();

    this.debug('menus init');
    this.menus();

    this.debug('show init');
    this.show();

    this.debug('runWebServer init');
    this.runWebServer().then((res) => {
      const PROD_URL = `http://${WEB_SERVER_LISTEN}:${res.usedPort}`;

      this.debug('registerProtocols init');
      this.registerProtocols(PROD_URL);

      this.debug('ipcEvents init');
      this.ipcEvents();
    });
  }

  // Used to forward wire:// requests to the returned URL
  getBaseUrl() {

    if (!argv.env && config.DEVELOPMENT) {
      switch(init.restore('env', config.INTERNAL)) {
        //case config.PROD: return undefined;
        case config.DEV: return config.DEV_URL;
        case config.EDGE: return config.EDGE_URL;
        case config.INTERNAL: return config.INTERNAL_URL;
        case config.LOCALHOST: return config.LOCALHOST_URL;
        case config.STAGING: return config.STAGING_URL;
      }
    }

    return undefined;
  }

  // <webview> hardening
  webviewProtection() {
    app.on('web-contents-created', (event, contents) => {
      contents.on('will-attach-webview', (event, webPreferences, params) => {

        // Strip away preload scripts as they are unused
        delete webPreferences.preload;
        delete webPreferences.preloadURL;

        // Secure defaults
        webPreferences.nodeIntegration = false;
        webPreferences.sandboxed = true;
        webPreferences.contextIsolation = true;

        // Verify URL being loaded
        if (!params.src.match(ALLOWED_WEBVIEWS_ORIGIN.soundcloud) &&
            !params.src.match(ALLOWED_WEBVIEWS_ORIGIN.spotify) &&
            !params.src.match(ALLOWED_WEBVIEWS_ORIGIN.vimeo) &&
            !params.src.match(ALLOWED_WEBVIEWS_ORIGIN.youtube)
          ) {
          event.preventDefault();
        }
      });
    });
  }

  // Register protocols
  registerProtocols(PROD_URL) {

    const baseURL = this.getBaseUrl() || PROD_URL;

    // Register Wire protocol
    protocol.registerStandardSchemes(['wire'], {
      secure: true,
    });

    app.on('ready', () => {

      protocol.registerHttpProtocol('wire', (request, callback) => {

        // Remove wire://127.0.0.1 and extra slashes
        const url = request.url.substr(WEB_SERVER_HOST.length).replace(/\/$/, '').replace(/^\//, '');
        const redirectPath = `${baseURL}/${url}`;

        //this.debug('%s', redirectPath);

        callback({ method: 'GET', url: redirectPath, referrer: '' });

      }, (error) => {
        if (error) {
          throw new Error('Failed to register protocol');
        }
      });
    });
  }

  runWebServer() {
    return new Promise((resolve) => {
      this.webServer = new HTTPServer(resolve);
    });
  }

  // Misc
  misc() {
    this.raygunClient = new raygun.Client().init({apiKey: config.RAYGUN_API_KEY});

    this.raygunClient.onBeforeSend((payload) => {
      delete payload.details.machineName;
      return payload;
    });

    if (config.DEVELOPMENT) {
      app.commandLine.appendSwitch('ignore-certificate-errors', 'true');
    }
  }

  platformFixes() {

    // Fix indicator icon on Unity
    // Source: https://bugs.launchpad.net/ubuntu/+bug/1559249
    if (process.platform === 'linux') {
      const isUbuntuUnity = process.env.XDG_CURRENT_DESKTOP && process.env.XDG_CURRENT_DESKTOP.includes('Unity');

      if (isUbuntuUnity) {
        process.env.XDG_CURRENT_DESKTOP = 'Unity';
      }
    }

    // Single instance stuff
    // makeSingleInstance will crash the signed mas app
    // see: https://github.com/atom/electron/issues/4688
    if (process.platform !== 'darwin') {
      this.shouldQuit = app.makeSingleInstance((commandLine, workingDirectory) => {
        if (this.browserWindow) {
          windowManager.showPrimaryWindow();
        }
        return true;
      });
      if (process.platform !== 'win32' && this.shouldQuit) {
        // Using exit instead of quit for the time being
        // see: https://github.com/electron/electron/issues/8862#issuecomment-294303518
        app.exit();
      }
    }
  }

  // Auto Update
  autoUpdate() {

    if (process.platform === 'win32') {
      const squirrel = require('./js/squirrel');
      squirrel.handleSquirrelEvent(this.shouldQuit);

      ipcMain.on('wrapper-restart', () => {
        squirrel.installUpdate();
      });

      // Stop further execution on update to prevent second tray icon
      if (this.shouldQuit) {
        return;
      }
    }
  }

  // IPC events
  ipcEvents() {

    ipcMain.once('webapp-version', (event, version) => {
      this.debug('webapp-version fired');

      this.webappVersion = version;
    });

    ipcMain.on('save-picture', (event, fileName, bytes) => {
      this.debug('save-picture fired');

      download(fileName, bytes);
    });

    ipcMain.on('notification-click', () => {
      this.debug('notification-click fired');

      windowManager.showPrimaryWindow();
    });

    ipcMain.on('google-auth-request', (event) => {
      this.debug('google-auth-request fired');

      googleAuth.getAccessToken(config.GOOGLE_SCOPES, config.GOOGLE_CLIENT_ID, config.GOOGLE_CLIENT_SECRET)
        .then((code) => {
          event.sender.send('google-auth-success', code.access_token);
        })
        .catch((error) => {
          event.sender.send('google-auth-error', error);
        });
    });

    if (process.platform !== 'darwin') {
      ipcMain.on('wrapper-reload', () => {
        this.debug('wrapper-reload fired');

        app.relaunch();
        // Using exit instead of quit for the time being
        // see: https://github.com/electron/electron/issues/8862#issuecomment-294303518
        app.exit();
      });
    }

    ipcMain.once('load-webapp', () => {
      this.debug('load-webapp fired');

      let baseURL = WEB_SERVER_HOST + '/index.html?hl=' + locale.getCurrent();
      /*let isWebServerOnline = setInterval(() => {
        this.debug('Checking if web server is online...');

        if(this.webServerStarted) {
          clearInterval(isWebServerOnline);

          this.debug('Accessing %s', baseURL);
          this.browserWindow.loadURL(baseURL);
          this.enteredWebapp = true;
        }
      }, 1000);*/
      this.debug('Accessing %s', baseURL);
      this.browserWindow.loadURL(baseURL);
    });
  }

  showMainWindow() {
    this.main = new BrowserWindowInit();
    this.browserWindow = this.main.browserWindow;
  }

  showAboutWindow() {

    if (!this.browserWindowAbout) {

      this.browserWindowAbout = new BrowserWindow({
        title: '',
        width: 304,
        height: 256,
        resizable: false,
        fullscreen: false,
      });
      this.browserWindowAbout.setMenuBarVisibility(false);
      this.browserWindowAbout.loadURL(ABOUT_HTML);
      this.browserWindowAbout.webContents.on('dom-ready', () => {
        this.browserWindowAbout.webContents.send('about-loaded', {
          webappVersion: this.webappVersion,
        });
      });

      this.browserWindowAbout.on('closed', () => {
        this.browserWindowAbout = false;
      });
    }

    this.browserWindowAbout.show();
  }

  appEvents() {
    app.on('window-all-closed', () => {
      if (process.platform !== 'darwin') {
        app.quit();
      }
    });

    app.on('activate', () => {
      if (this.browserWindow) {
        this.browserWindow.show();
      }
    });

    app.on('before-quit', () => {
      if(this.main) {
        this.main.quitting = true;
      }
    });
  }

  // System Menu & Tray Icon
  menus() {
    app.on('ready', () => {
      let appMenu = systemMenu.createMenu();

      if (config.DEVELOPMENT) {
        appMenu.append(developerMenu);
      }

      appMenu.on('about-wire', () => {
        this.showAboutWindow();
      });

      Menu.setApplicationMenu(appMenu);
      tray.createTrayIcon();
    });
  }

  // Show main window
  show() {
    app.on('ready', () => {
      this.showMainWindow();
    });
  }

  // Archive console.log
  cleanupLogFile() {
    let consoleLog = path.join(USER_DATAS_PATH, config.CONSOLE_LOG);

    fs.stat(consoleLog, (err, stats) => {
      if (!err) {
        fs.rename(consoleLog, consoleLog.replace('.log', '.old'));
      }
    });
  }
};

class BrowserWindowInit {

  constructor() {

    this.debug = debug('BrowserWindowInit');
    this.quitting = false;

    // Start the renderer
    this.browserWindow = new BrowserWindow({
      title: config.NAME,
      titleBarStyle: 'hidden-inset',

      // Window size options
      width: config.DEFAULT_WIDTH_MAIN,
      height: config.DEFAULT_HEIGHT_MAIN,
      minWidth: config.MIN_WIDTH_MAIN,
      minHeight: config.MIN_HEIGHT_MAIN,

      autoHideMenuBar: !init.restore('showMenu', true),
      icon: ICON_PATH,
      show: false,

      backgroundColor: '#000',

      webPreferences: {

        // Disable background throttling
        backgroundThrottling: false,

        // Disable node integration
        nodeIntegration: false,

        // Preload script for the webapp
        preload: PRELOAD_JS,

        // Activate semi-sandbox
        sandboxed: true,

        // Enable <webview>
        webviewTag: true,

        // ToDo: Activate contextIsolation as soon as <webview> is compatible with
        //contextIsolation: true,
      },
    });

    if (init.restore('fullscreen', false)) {
      this.browserWindow.setFullScreen(true);
    } else {
      this.browserWindow.setBounds(init.restore('bounds', this.browserWindow.getBounds()));
    }

    // Load the splash
    this.browserWindow.loadURL(SPLASH_HTML);

    // Set certificate pinning verifications
    this.setCertificateVerification();

    // Fix CORS on backend
    this.fixCorsOnBackend();

    // Open dev tools if asked
    if (argv.devtools) {
      this.browserWindow.webContents.openDevTools();
    }

    // Show the main window
    if (!argv.startup && !argv.hidden) {
      if (!util.isInView(this.browserWindow)) {
        this.browserWindow.center();
      }

      this.discloseWindowID(this.browserWindow);
      this.browserWindow.on('ready-to-show', () => {
        this.browserWindow.show();
      });
    }

    // Browser window listeners
    this.browserWindowListeners();
  }

  browserWindowListeners() {

    this.browserWindow.webContents.on('will-navigate', (event, url) => {
      this.debug('will-navigate fired');

      // Resize the window for auth
      if (url.startsWith(`${WEB_SERVER_HOST}/auth/`)) {
        this.debug('Login page asked');
        util.resizeToSmall(this.browserWindow);
        return;
      }

      // Allow access in the same window to wire://
      if(url.startsWith(`${WEB_SERVER_HOST}/`)) {
        this.debug('Allowing access to wire://');

        // Resize the window if needed
        let size = this.browserWindow.getSize();
        if (size[0] < config.MIN_WIDTH_MAIN || size[1] < config.MIN_HEIGHT_MAIN) {
          this.debug('Resize to big window');
          util.resizeToBig(this.browserWindow);
        }

        return;
      }

      // Prevent navigation by default
      // Prevent Redirect for Drag and Drop on embeds
      // or when no internet is present
      event.preventDefault();

      // Open links like www.wire.com in the browser instead
      if (util.openInExternalWindow(url)) {
        shell.openExternal(url);
        return;
      }
    });

    this.browserWindow.webContents.on('new-window', (event, url) => {
      event.preventDefault();
      shell.openExternal(url);
    });

    this.browserWindow.webContents.on('dom-ready', () => {

      this.browserWindow.webContents.insertCSS(fs.readFileSync(WRAPPER_CSS, 'utf8'));

      if (this.enteredWebapp) {

        setTimeout(() => {

          this.browserWindow.webContents.send('webapp-loaded', {
            electron_version: app.getVersion(),
            notification_icon: path.join(app.getAppPath(), 'img', 'notification.png'),
          });

        }, 2000);

      } else {
        this.browserWindow.webContents.send('splash-screen-loaded');
      }
    });

    this.browserWindow.on('focus', () => {
      this.browserWindow.flashFrame(false);
    });

    this.browserWindow.on('page-title-updated', () => {
      tray.updateBadgeIcon(this.browserWindow);
    });

    this.browserWindow.on('close', (event) => {
      init.save('fullscreen', this.browserWindow.isFullScreen());
      if (!this.browserWindow.isFullScreen()) {
        init.save('bounds', this.browserWindow.getBounds());
      }

      if (!this.quitting) {
        event.preventDefault();
        this.browserWindow.hide();
      }
    });

    // Reload the window if it the webapp crashed
    this.browserWindow.webContents.on('crashed', () => {
      this.browserWindow.reload();
    });
  }

  discloseWindowID(browserWindow) {
    windowManager.setPrimaryWindowId(browserWindow.id);
  }

  setCertificateVerification() {
    this.browserWindow.webContents.session.setCertificateVerifyProc((request, cb) => {
      const {hostname = '', certificate = {}, error} = request;

      if (typeof error !== 'undefined') {
        this.debug('setCertificateVerifyProc', error);
        this.browserWindow.loadURL(CERT_ERR_HTML);
        return cb(-2);
      }

      if (certutils.hostnameShouldBePinned(hostname)) {
        const pinningResults = certutils.verifyPinning(hostname, certificate);
        for (const result of Object.values(pinningResults)) {
          if (result === false) {
            this.debug(`Certutils verification failed for ${hostname}: ${result} is false`);
            this.browserWindow.loadURL(CERT_ERR_HTML);
            return cb(-2);
          }
        }
      }

      return cb(-3);
    });
  }

  // Fix Access-Control-Allow-Origin for the web app
  fixCorsOnBackend() {

    this.browserWindow.webContents.session.webRequest.onHeadersReceived({urls: [
      'https://prod-nginz-https.wire.com/*',
      'https://staging-nginz-https.zinfra.io/*',
    ]}, (details, callback) => {

      this.debug('Access-Control-Allow-Origin disabled for backend');

      //console.log(details);
      details.responseHeaders['Access-Control-Allow-Origin'] = [ WEB_SERVER_HOST ];

      callback({cancel: false, responseHeaders: details.responseHeaders});
    });
  }
};

(new ElectronWrapperInit());
