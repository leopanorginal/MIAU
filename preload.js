// ── preload.js — contextIsolation=true ile güvenli IPC köprüsü ──

const { contextBridge, ipcRenderer } = require('electron')

// ── GÜVENLİK: Sadece izin verilen kanallar ──
const ALLOWED_SEND = new Set([
  'minimize', 'maximize', 'close',
  'toggle-fullscreen',
  'open-private-tab',
  'close-private-tab'
])

const ALLOWED_INVOKE = new Set([
  // Ekran görüntüsü & indirme
  'save-screenshot',
  'download-image',
  'download-file',
  // Self-destruct
  'self-destruct',
  // Fingerprint scripti
  'get-fp-script',
  // Güvenlik ayarları
  'get-security-settings',
  'set-security-settings',
  // Phishing kontrolü
  'check-phishing',
  // Session restore
  'save-session',
  'load-session',
  // DevTools
  'toggle-devtools',
  // Arama motorları
  'get-search-engines',
  'set-search-engine',
  'add-search-engine',
  'get-search-url',
  // Adblock
  'get-adblock-state',
  'set-adblock',
  'reset-adblock-stats',
  // Tracker map
  'get-tracker-map',
  'clear-tracker-map',
  // Yer imleri
  'get-bookmarks',
  'add-bookmark',
  'remove-bookmark',
  'update-bookmark',
  'check-bookmark',
  // Dark Reader
  'get-dark-reader',
  'set-dark-reader',
  'get-dark-reader-css',
  // Extensions
  'get-extensions',
  'get-extension-popup-url'
])

const ALLOWED_ON = new Set([
  'download-started',
  'download-progress',
  'download-done',
  'download-blocked',
  'fullscreen-changed',
  'open-in-new-tab',
  'self-destruct-done',
  'update-available',
  'update-downloaded',
  // İzin bildirimi
  'permission-denied',
  // Session kaydet isteği
  'save-session-request',
  // Live updates
  'tracker-update',
  'ram-update',
  'open-private-tab',
  'dark-reader-changed',
  // Webview context menu
  'webview-context-menu',
  // YouTube / HTML5 fullscreen
  'wv-enter-fullscreen',
  'wv-leave-fullscreen',
  // Webview ses durumu
  'wv-audio-changed'
])

contextBridge.exposeInMainWorld('electronAPI', {
  send: (channel, ...args) => {
    if (ALLOWED_SEND.has(channel)) ipcRenderer.send(channel, ...args)
  },
  invoke: (channel, ...args) => {
    if (ALLOWED_INVOKE.has(channel)) return ipcRenderer.invoke(channel, ...args)
    return Promise.reject(new Error('Kanal izni yok: ' + channel))
  },
  on: (channel, fn) => {
    if (!ALLOWED_ON.has(channel)) return () => {}
    const wrapped = (_, ...a) => fn(...a)
    ipcRenderer.on(channel, wrapped)
    return () => ipcRenderer.removeListener(channel, wrapped)
  }
})
