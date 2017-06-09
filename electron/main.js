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

'use strict';

// Modules
const {app, BrowserWindow, ipcMain, Menu, shell, protocol} = require('electron');
const fs = require('fs');
const minimist = require('minimist');
const path = require('path');
const raygun = require('raygun');
const debug = require('debug');

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

// Web server
const HTTPServer = require('./js/lib/HTTPServer');
const WEB_SERVER_LISTEN = '127.0.0.1';
const WEB_SERVER_HOST = 'wire://prod.local';
const WEB_SERVER_FILES = path.join(USER_DATAS_PATH, 'app.wire.com.asar');
const WEB_SERVER_TOKEN_NAME = 'Local';

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

class ElectronWrapperInit {

  constructor() {

    this.main = false;
    this.browserWindow = false;
    this.browserWindowAbout = false;
    this.enteredWebapp = false;
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

    this.debug('showMainWindow init');
    this.showMainWindow();

    this.debug('runWebServer init');
    this.runWebServer().then((res) => {

      // URL for production is the local web server
      const PROD_URL = `http://${WEB_SERVER_LISTEN}:${res.usedPort}`;

      // Register the wire:// protocol
      this.debug('registerProtocols init');
      this.registerProtocols(PROD_URL);

      // Expose the accessToken and PROD_URL to the BrowserWindowInit class
      //this.debug('Token is %s', res.accessToken);
      app.once('ready', () => {

        if(!this.main) {
          this.debug('Unable to set datas in the BrowserWindowInit class, requests to the web server will likely fail!');
          return;
        }

        this.main.accessToken = res.accessToken;
        this.debug('Token has been set');

        this.main.PROD_URL = PROD_URL;
        this.debug('PROD_URL has been set');
      });

      // Register IPC events
      // (including the load-webapp event which is the event that will load the webapp)
      this.debug('ipcEvents init');
      this.ipcEvents();
    });
  }

  // Used to forward wire:// requests
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
    const webviewProtectionDebug = debug('ElectronWrapperInit:webviewProtection');

    app.on('web-contents-created', (event, contents) => {
      contents.on('will-attach-webview', (event, webPreferences, params) => {
        const url = params.src;

        // Strip away preload scripts as they represent a security risk
        delete webPreferences.preload;
        delete webPreferences.preloadURL;

        // Use secure defaults
        webPreferences.nodeIntegration = false;
        webPreferences.sandboxed = true;
        webPreferences.contextIsolation = true;

        // Verify the URL being loaded
        if (!url.match(ALLOWED_WEBVIEWS_ORIGIN.soundcloud) &&
            !url.match(ALLOWED_WEBVIEWS_ORIGIN.spotify) &&
            !url.match(ALLOWED_WEBVIEWS_ORIGIN.vimeo) &&
            !url.match(ALLOWED_WEBVIEWS_ORIGIN.youtube)
          ) {
            webviewProtectionDebug('Prevented to show an unauthorized <webview>. URL: %s', url);
            event.preventDefault();
        }
      });
    });
  }

  // Register protocols
  registerProtocols(PROD_URL) {

    const registerProtocolsDebug = debug('ElectronWrapperInit:registerProtocols');
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

        registerProtocolsDebug('%s', redirectPath);

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
      (new HTTPServer(resolve, {
        WEB_SERVER_LISTEN: WEB_SERVER_LISTEN,
        WEB_SERVER_HOST: WEB_SERVER_HOST,
        WEB_SERVER_FILES: WEB_SERVER_FILES,
        WEB_SERVER_TOKEN_NAME: WEB_SERVER_TOKEN_NAME,
      }));
    });
  }

  // Misc
  misc() {
    const miscDebug = debug('ElectronWrapperInit:misc');

    // Raygun settings
    this.raygunClient = new raygun.Client().init({apiKey: config.RAYGUN_API_KEY});
    this.raygunClient.onBeforeSend((payload) => {
      delete payload.details.machineName;
      return payload;
    });

    // Disable certificate verification in development env.
    if (config.DEVELOPMENT) {
      miscDebug('WARNING: Certificate errors are ignored!');
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
      this.debug('Accessing %s', baseURL);
      this.browserWindow.loadURL(baseURL);
    });
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
  showMainWindow() {
    app.on('ready', () => {
      this.main = new BrowserWindowInit();
      this.browserWindow = this.main.browserWindow;

      this.main.show();
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
    this.accessToken = false;

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

    // Show the splash
    this.browserWindow.loadURL(SPLASH_HTML);

    // Restore previous window size
    if (init.restore('fullscreen', false)) {
      this.browserWindow.setFullScreen(true);
    } else {
      this.browserWindow.setBounds(init.restore('bounds', this.browserWindow.getBounds()));
    }

    // Session handling
    this.sessionPermissionsHandling();

    // Set certificate pinning verifications
    this.setCertificateVerification();

    // Fix CORS on backend
    this.fixCorsOnBackend();

    // Add Authorization token
    this.addAuthTokenToLocalRequests();

    // Browser window listeners
    this.browserWindowListeners();
  }

  // Show the main window
  show() {

    // Open dev tools if asked
    if (argv.devtools) {
      this.browserWindow.webContents.openDevTools();
    }

    if (!argv.startup && !argv.hidden) {

      if (!util.isInView(this.browserWindow)) {
        this.browserWindow.center();
      }

      this.discloseWindowID(this.browserWindow);

      this.browserWindow.on('ready-to-show', () => {
        this.browserWindow.show();
      });
    }
  }

  getWrapperStyle() {
    return new Promise((resolve, reject) => {

      fs.readFile(WRAPPER_CSS, 'utf8', (err, data) => {
        if(err) {
          reject(err);
          return;
        }
        resolve(data);
      });
    });
  }

  browserWindowListeners() {
    const browserWindowListenersDebug = debug('BrowserWindowInit:browserWindowListeners');

    this.browserWindow.webContents.on('will-navigate', (event, url) => {
      browserWindowListenersDebug('will-navigate fired');

      // Resize the window for auth
      if (url.startsWith(`${WEB_SERVER_HOST}/auth/`)) {
        browserWindowListenersDebug('Login page asked');
        util.resizeToSmall(this.browserWindow);
        return;
      }

      // Allow access in the same window to wire://
      if(url.startsWith(`${WEB_SERVER_HOST}/`)) {
        browserWindowListenersDebug('Allowing access to wire://');

        // Resize the window if needed
        let size = this.browserWindow.getSize();
        if (size[0] < config.MIN_WIDTH_MAIN || size[1] < config.MIN_HEIGHT_MAIN) {
          browserWindowListenersDebug('Resize to big window');
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

      // Overwrite webapp styles
      this.getWrapperStyle().then((css) => {
        this.browserWindow.webContents.insertCSS(css);
        browserWindowListenersDebug('Successfully added wrapper CSS');
      }).catch((err) => {
        browserWindowListenersDebug('WARNING: Unable to add wrapper CSS into the webapp! Error: %o', err);
      });

      if (!this.enteredWebapp) {
        this.browserWindow.webContents.send('splash-screen-loaded');
        return;
      }

      // Webapp loaded
      this.browserWindow.webContents.send('webapp-loaded', {
        electron_version: app.getVersion(),
        notification_icon: path.join(app.getAppPath(), 'img', 'notification.png'),
      });
    });

    this.browserWindow.on('focus', () => {
      this.browserWindow.flashFrame(false);
    });

    this.browserWindow.on('page-title-updated', () => {
      tray.updateBadgeIcon(this.browserWindow);
    });

    this.browserWindow.on('close', (event) => {

      const isFullScreen = this.browserWindow.isFullScreen();

      init.save('fullscreen', isFullScreen);
      if (!isFullScreen) {
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

  // Restrict permissions for the current session
  // Also allow to detect events like fullscreen for Youtube
  sessionPermissionsHandling() {
    const sessionPermissionsHandlingDebug = debug('BrowserWindowInit:sessionPermissionsHandling');

    this.browserWindow.webContents.session.setPermissionRequestHandler((webContents, permission, callback) => {
      const url = webContents.getURL();

      // Enums: 'media', 'geolocation', 'notifications', 'midiSysex', 'pointerLock', 'fullscreen', 'openExternal'
      sessionPermissionsHandlingDebug('URL: %s, Permission: %s', url, permission);

      // Allow fullscreen for Youtube
      if(url.match(ALLOWED_WEBVIEWS_ORIGIN.youtube) &&
          permission === 'fullscreen') {

        sessionPermissionsHandlingDebug('Allowing fullscreen for Youtube');

        // Emit event to browser
        this.browserWindow.webContents.send('youtube-fullscreen', {
          link: url
        });

        return callback(true);
      }

      return callback(false);
    });
  }

  // Certificate verification process
  setCertificateVerification() {
    const setCertificateVerificationDebug = debug('BrowserWindowInit:setCertificateVerification');

    this.browserWindow.webContents.session.setCertificateVerifyProc((request, cb) => {
      const {hostname = '', certificate = {}, error} = request;

      // An error already happened
      if (typeof error !== 'undefined') {
        setCertificateVerificationDebug('setCertificateVerifyProc', error);
        this.browserWindow.loadURL(CERT_ERR_HTML);
        return cb(-2);
      }

      // Certificate pinning
      if (certutils.hostnameShouldBePinned(hostname)) {
        const pinningResults = certutils.verifyPinning(hostname, certificate);
        for (const result of Object.values(pinningResults)) {
          if (result === false) {
            setCertificateVerificationDebug('Certutils verification failed for %s: %s is false', hostname, result);
            this.browserWindow.loadURL(CERT_ERR_HTML);
            return cb(-2);
          }
        }
      }

      setCertificateVerificationDebug('Verification for %s is OK', hostname);
      return cb(-3);
    });
  }

  // Fix CORS
  fixCorsOnBackend() {
    const fixCorsOnBackendDebug = debug('BrowserWindowInit:fixCorsOnBackend');

    this.browserWindow.webContents.session.webRequest.onHeadersReceived({urls: config.BACKEND_URLS}, (details, callback) => {
      fixCorsOnBackendDebug('Access-Control-Allow-Origin modified for a backend request');

      // Override remote Access-Control-Allow-Origin
      details.responseHeaders['Access-Control-Allow-Origin'] = [ WEB_SERVER_HOST ];

      callback({
        cancel: false,
        responseHeaders: details.responseHeaders
      });
    });
  }

  // Add Authorization token
  addAuthTokenToLocalRequests() {
    this.browserWindow.webContents.session.webRequest.onBeforeSendHeaders({urls: `${WEB_SERVER_HOST}/*`}, (details, callback) => {

      // Append the Authorization header for local requests only
      if(details.url.startsWith(`${this.PROD_URL}/`)) {
        details.requestHeaders['Authorization'] = `${WEB_SERVER_TOKEN_NAME} ${this.accessToken}`;
      }

      callback({cancel: false, requestHeaders: details.requestHeaders});
    });
  }
};

(new ElectronWrapperInit());
