// ── preload-incognito.js — Gizli pencere için güvenli IPC köprüsü ──
const { contextBridge, ipcRenderer } = require('electron')

const ALLOWED_SEND = new Set([
  'inc-minimize', 'inc-maximize', 'inc-close', 'inc-fullscreen'
])

const ALLOWED_INVOKE = new Set([
  'get-fp-script',
  'download-image',
  'download-file'
])

const ALLOWED_ON = new Set([
  'download-started', 'download-progress', 'download-done',
  'download-blocked',
  'fullscreen-changed',
  'ram-update'
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
