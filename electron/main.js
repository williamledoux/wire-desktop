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

// Local files
const INIT_JSON = path.join(USER_DATAS_PATH, 'init.json');
const PRELOAD_JS = path.join(APP_PATH, 'js', 'preload.js');
const WRAPPER_CSS = path.join(APP_PATH, 'css', 'wrapper.css');
const SPLASH_HTML = `file://${path.join(APP_PATH, 'html', 'splash.html')}`;
const CERT_ERR_HTML = `file://${path.join(APP_PATH, 'html', 'certificate-error.html')}`;
const ABOUT_HTML = `file://${path.join(APP_PATH, 'html', 'about.html')}`;

// Configuration persistence
const init = require('./js/lib/init');
global.init = new init(INIT_JSON);

// Wrapper modules
const certutils = require('./js/certutils');
const download = require('./js/lib/download');
const googleAuth = require('./js/lib/googleAuth');
const locale = require('./locale/locale');
const systemMenu = require('./js/menu/system');
const developerMenu = require('./js/menu/developer');
const tray = require('./js/menu/tray');
const util = require('./js/util');
const windowManager = require('./js/window-manager');

// Config
const argv = minimist(process.argv.slice(1));
const config = require('./js/config');

// Web server
const HTTPServer = require('./js/lib/HTTPServer');
const WEB_SERVER_LISTEN = '127.0.0.1';
const WEB_SERVER_HOST = 'wire://prod.local';
const WEB_SERVER_FILES = path.join(USER_DATAS_PATH, 'app.wire.com.asar');
const WEB_SERVER_TOKEN_NAME = 'Local';

// Updater
//const WireUpdater = require('./js/lib/WireUpdater');

// Icon
const ICON = `wire.${((process.platform === 'win32') ? 'ico' : 'png')}`;
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
  }

  async run() {

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

    this.debug('misc init');
    this.misc();

    this.debug('runWebServer init');
    const {usedPort, accessToken} = await this.runWebServer();

    // URL for production is the local web server
    const PROD_URL = `http://${WEB_SERVER_LISTEN}:${usedPort}`;

    // Register the wire:// protocol
    this.debug('registerProtocols init');
    this.registerProtocols(PROD_URL);

    // Expose the accessToken and PROD_URL to the BrowserWindowInit class
    //this.debug('Token is %s', accessToken);
    app.once('ready', () => {

      if (!this.main) {
        this.debug('Unable to set datas in the BrowserWindowInit class, requests to the web server will likely fail!');
        return;
      }

      this.main.accessToken = accessToken;
      this.debug('Token has been set');

      this.main.PROD_URL = PROD_URL;
      this.debug('PROD_URL has been set');

      this.main.onBeforeSendHeaders();
      this.debug('onBeforeSendHeaders init');
    });

    // Register IPC events
    // (including the load-webapp event which is the event that will load the webapp)
    this.debug('ipcEvents init');
    this.ipcEvents();
  }

  // Used to forward wire:// requests
  getBaseUrl() {

    if (!argv.env && config.DEVELOPMENT) {
      switch (global.init.restore('env', config.INTERNAL)) {
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
    const openLinkInNewWindow = (event, _url) => {

      // Prevent default behavior
      event.preventDefault();

      // Ensure the link come from a whitelisted link
      if (!util.isMatchingEmbedOpenExternalWhitelist(event.sender.history[0], _url)) {
        webviewProtectionDebug('Tried to open a non-whitelisted window from a webview, aborting. URL: %s', _url);
        return;
      }

      webviewProtectionDebug('Opening an external window from a webview. URL: %s', _url);
      shell.openExternal(_url);
    };

    app.on('web-contents-created', (event, contents) => {

      // The following events should only be applied on webviews
      if (contents.getType() !== 'webview') {
        return;
      }

      // Open webview links outside of the app
      contents.on('new-window', (e, _url) => { openLinkInNewWindow(e, _url); });
      contents.on('will-navigate', (e, _url) => { openLinkInNewWindow(e, _url); });

      contents.on('will-attach-webview', (e, webPreferences, params) => {
        const _url = params.src;

        // Strip away preload scripts as they represent a security risk
        delete webPreferences.preload;
        delete webPreferences.preloadURL;
        params.preload = '';

        // Use secure defaults
        webPreferences.nodeIntegration = false;
        webPreferences.webSecurity = true;
        webPreferences.sandbox = true;
        webPreferences.contextIsolation = true;
        params.contextIsolation = true;
        webPreferences.allowRunningInsecureContent = false;
        params.plugins = false;
        params.autosize = false;

        // Let onBeforeSendHeaders manage the referrer
        params.httpreferrer = '';

        // IMPORTANT: Use an in-memory partition for the session (derived from the URL)
        // https://electron.atom.io/docs/api/webview-tag/#partition
        params.partition = new Buffer(_url).toString('base64');
        webviewProtectionDebug('Using partition %s', params.partition);

        // Verify the URL being loaded
        if (!util.isMatchingEmbed(_url)) {
          e.preventDefault();
          webviewProtectionDebug('Prevented to show an unauthorized <webview>. URL: %s', _url);
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
        const _url = request.url.substr(WEB_SERVER_HOST.length).replace(/\/$/, '').replace(/^\//, '');
        const redirectPath = `${baseURL}/${_url}`;

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
    //const miscDebug = debug('ElectronWrapperInit:misc');

    // Raygun settings
    this.raygunClient = new raygun.Client().init({apiKey: config.RAYGUN_API_KEY});
    this.raygunClient.onBeforeSend((payload) => {
      delete payload.details.machineName;
      return payload;
    });

    // Disable certificate verification in development env.
    /*miscDebug('Development mode? %s', config.DEVELOPMENT);
    if (config.DEVELOPMENT) {
      miscDebug('WARNING: Certificate errors are ignored!');
      app.commandLine.appendSwitch('ignore-certificate-errors', 'true');
    }*/
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

    ipcMain.on('google-auth-request', async (event) => {
      this.debug('google-auth-request fired');

      try {
        const code = await googleAuth.getAccessToken(config.GOOGLE_SCOPES, config.GOOGLE_CLIENT_ID, config.GOOGLE_CLIENT_SECRET);
        event.sender.send('google-auth-success', code.access_token);
      } catch (e) {
        event.sender.send('google-auth-error', error);
      }
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

      const baseURL = `${WEB_SERVER_HOST}/index.html?hl=${locale.getCurrent()}`;
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
      if (this.main) {
        this.main.quitting = true;
      }
    });
  }

  // System Menu & Tray Icon
  menus() {
    app.on('ready', () => {
      const appMenu = systemMenu.createMenu();

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

  // Archive old console.log
  cleanupLogFile() {
    const consoleLog = path.join(USER_DATAS_PATH, config.CONSOLE_LOG);

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

      autoHideMenuBar: !global.init.restore('showMenu', true),
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

        // Enable <webview>
        webviewTag: true,

        // Enforce allowRunningInsecureContent deactivation
        allowRunningInsecureContent: false,

        // Enable experimental features (so we can have worker-src until Electron use Chrome 59)
        experimentalFeatures: true,

        // Disable WebGL
        webgl: false,

        // Sandbox the renderer (broken due to webframe and desktopsharing dependencies)
        // Anyway, it's not very secure: https://github.com/electron/electron/issues/6712#issuecomment-299441941
        //sandbox: true,

        // Context isolation on main browser window (break <webview>)
        //contextIsolation: true,
      },
    });

    // Show the splash
    this.browserWindow.loadURL(SPLASH_HTML);

    // Restore previous window size
    if (global.init.restore('fullscreen', false)) {
      this.browserWindow.setFullScreen(true);
    } else {
      this.browserWindow.setBounds(global.init.restore('bounds', this.browserWindow.getBounds()));
    }

    // Set a fixed pinch-to-zoom level
    this.browserWindow.webContents.setVisualZoomLevelLimits(1, 1);

    // Session handling
    this.sessionPermissionsHandling();

    // Set certificate pinning verifications
    this.setCertificateVerification();

    // Fix CORS on backend
    this.fixCorsOnBackend();

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
        if (err) {
          reject(err);
          return;
        }
        resolve(data);
      });
    });
  }

  browserWindowListeners() {
    const browserWindowListenersDebug = debug('BrowserWindowInit:browserWindowListeners');

    this.browserWindow.webContents.on('will-navigate', (event, _url) => {
      browserWindowListenersDebug('will-navigate fired');

      // Resize the window for auth
      if (_url.startsWith(`${WEB_SERVER_HOST}/auth/`)) {
        browserWindowListenersDebug('Login page asked');
        util.resizeToSmall(this.browserWindow);
        return;
      }

      // Allow access in the same window to wire://
      if (_url.startsWith(`${WEB_SERVER_HOST}/`)) {
        browserWindowListenersDebug('Allowing access to wire://');

        // Resize the window if needed
        const size = this.browserWindow.getSize();
        if (size[0] < config.MIN_WIDTH_MAIN || size[1] < config.MIN_HEIGHT_MAIN) {
          browserWindowListenersDebug('Resize to big window');
          util.resizeToBig(this.browserWindow);
        }

        return;
      }

      // Prevent navigation inside the wrapper by default
      // Prevent Redirect for Drag and Drop on embeds or when no internet is present
      event.preventDefault();

      // Open links like www.wire.com in the browser instead
      if (util.openInExternalWindow(_url)) {
        shell.openExternal(_url);
        return;
      }
    });

    // Handle the new window event in the main Browser Window
    this.browserWindow.webContents.on('new-window', (event, _url) => {
      event.preventDefault();

      // Ensure the link does not come from a webview
      if (typeof event.sender.viewInstanceId !== 'undefined') {
        this.debug('New window did came from a webview, aborting.');
        return;
      }

      shell.openExternal(_url);
    });

    this.browserWindow.webContents.on('dom-ready', async () => {

      // Overwrite webapp styles
      try {
        const css = await this.getWrapperStyle();
        this.browserWindow.webContents.insertCSS(css);
        browserWindowListenersDebug('Successfully added wrapper CSS');
      } catch (err) {
        browserWindowListenersDebug('WARNING: Unable to add wrapper CSS into the webapp! Error: %o', err);
      };

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

    this.browserWindow.on('close', async (event) => {

      const isFullScreen = this.browserWindow.isFullScreen();

      global.init.save('fullscreen', isFullScreen);
      if (!isFullScreen) {
        global.init.save('bounds', this.browserWindow.getBounds());
      }

      if (!this.quitting) {
        event.preventDefault();
        this.browserWindow.hide();
      }

      // Save modifications to the file
      this.debug('Persisting user configuration file...');
      await global.init._saveToFile();
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
      const _url = webContents.getURL();

      // Enums: 'media', 'geolocation', 'notifications', 'midiSysex', 'pointerLock', 'fullscreen', 'openExternal'
      sessionPermissionsHandlingDebug('URL: %s, Permission: %s', _url, permission);

      if (
        (_url.startsWith(`${WEB_SERVER_HOST}/`))
        && (permission === 'notifications' || permission === 'media')
      ) {

        // Allow Wire to use notifications and camera/microphone
        sessionPermissionsHandlingDebug('Allowing Wire notifications or media access');

        return callback(true);

      } else if (
        (util.isMatchingEmbed(_url))
        && (permission === 'fullscreen')
      ) {

        // Allow fullscreen for embed content
        sessionPermissionsHandlingDebug('Allowing fullscreen for embed content');

        // Emit the event to browser
        this.browserWindow.webContents.send('ask-fullscreen', {
          viewInstanceId: webContents.viewInstanceId,
          link: _url,
        });

        return callback(true);
      }

      sessionPermissionsHandlingDebug('Permission denied');
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
        responseHeaders: details.responseHeaders,
      });
    });
  }

  // Must be executed only after this.PROD_URL is available
  onBeforeSendHeaders() {

    let filters = [
      // Local web server
      `${this.PROD_URL}/*`,
    ];

    // Add embed contents to the filter
    for (let i=0; i < config.EMBED_DOMAINS.length; i++) {
      if (!config.EMBED_DOMAINS[i].hostname) {
        continue;
      }
      for (let x=0; x < config.EMBED_DOMAINS[i].hostname.length; x++) {
        filters.push(`https://${config.EMBED_DOMAINS[i].hostname[x]}/*`);
      }
    }

    this.debug('Current filters for onBeforeSendHeaders: %o', filters);

    this.browserWindow.webContents.session.webRequest.onBeforeSendHeaders({urls: filters}, (details, callback) => {

      if (details.url.startsWith(`${this.PROD_URL}/`)) {
        // Append the Authorization header for build-in local server only
        details.requestHeaders['Authorization'] = `${WEB_SERVER_TOKEN_NAME} ${this.accessToken}`;
      } else if (util.isMatchingEmbed(details.url)) {
        // Set the right referer for embed content for webviews (like an <iframe> would do)
        this.debug('Embed match: %s', details.url);
        details.requestHeaders['Referer'] = details.url;
      }

      callback({
        cancel: false,
        requestHeaders: details.requestHeaders,
      });
    });
  }
};

(new ElectronWrapperInit()).run();
