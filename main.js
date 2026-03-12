const { app, BrowserWindow, ipcMain, session, Menu, dialog } = require('electron')
const path = require('path')
const fs   = require('fs')

// ── CACHE FIX ─────────────────────────────────────────────
;(function patchCachePaths() {
  try {
    const ud = app.getPath('userData')
    const dirs = [
      path.join(ud, 'Cache'), path.join(ud, 'GPUCache'),
      path.join(ud, 'Code Cache'), path.join(ud, 'Network'),
    ]
    for (const d of dirs) if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true })
  } catch (_) {}
})()

// ── SINGLE INSTANCE ───────────────────────────────────────
if (!app.requestSingleInstanceLock()) { app.quit(); process.exit(0) }

const { autoUpdater } = require('electron-updater')
const https  = require('https')
const http   = require('http')
const { URL } = require('url')
const crypto = require('crypto')

// ── electron-chrome-extensions ────────────────────────────
let ElectronChromeExtensions
try {
  ElectronChromeExtensions = require('electron-chrome-extensions').ElectronChromeExtensions
} catch (e) {
  console.warn('[MIAU] electron-chrome-extensions not found. Run: npm install electron-chrome-extensions')
  ElectronChromeExtensions = null
}

let mainWindow
const privateSessions = new Map()
const registeredHandlers = new Set()
let extensionEngine = null

// ══════════════════════════════════════════════
// LOGGING
// ══════════════════════════════════════════════
const SENSITIVE_KEYS = new Set(['password','token','cookie','auth','key','secret','credential'])
function maskSensitive(data) {
  if (!data || typeof data !== 'object') return data
  const out = {}
  for (const [k, v] of Object.entries(data)) out[k] = SENSITIVE_KEYS.has(k.toLowerCase()) ? '***' : v
  return out
}
const Logger = {
  _dir: null,
  init() {
    try { this._dir = path.join(app.getPath('userData'), 'logs'); if (!fs.existsSync(this._dir)) fs.mkdirSync(this._dir, { recursive: true }) } catch {}
  },
  _write(level, msg, data) {
    const ts = new Date().toISOString()
    const safeData = maskSensitive(data)
    const entry = JSON.stringify({ ts, level, msg, data: safeData }) + '\n'
    console.log(`[${ts}] ${level}: ${msg}`, safeData || '')
    if ((level === 'ERROR' || level === 'WARN') && this._dir) {
      try { fs.appendFileSync(path.join(this._dir, level.toLowerCase() + '.log'), entry) } catch {}
    }
  },
  error(m, d) { this._write('ERROR', m, d) },
  warn(m, d)  { this._write('WARN',  m, d) },
  info(m, d)  { this._write('INFO',  m, d) },
}

// ══════════════════════════════════════════════
// SECURITY HELPERS
// ══════════════════════════════════════════════
function isSafeUrl(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return false
  try { const u = new URL(urlStr); return ['http:', 'https:', 'file:'].includes(u.protocol) } catch { return false }
}
function isSafePath(p) {
  if (!p || typeof p !== 'string') return false
  return !['..', '<', '>', '|', '\0'].some(d => path.normalize(p).includes(d))
}
function sanitize(val, max = 500) {
  if (typeof val !== 'string') return ''
  return val.slice(0, max).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
}
const DANGEROUS_EXTS = new Set(['.exe','.msi','.bat','.cmd','.sh','.vbs','.ps1','.jar','.scr','.pif','.com','.reg'])

// ══════════════════════════════════════════════
// HTTPS-ONLY
// ══════════════════════════════════════════════
let httpsOnlyMode = true
function setupHttpsOnly(sess) {
  sess.webRequest.onBeforeRequest({ urls: ['http://*/*'] }, (details, callback) => {
    if (!httpsOnlyMode) return callback({})
    try { const u = new URL(details.url); if (['localhost','127.0.0.1','::1'].includes(u.hostname)) return callback({}) } catch {}
    callback({ redirectURL: details.url.replace(/^http:\/\//, 'https://') })
  })
}

// ══════════════════════════════════════════════
// TRACKER DOMAINS
// ══════════════════════════════════════════════
const TRACKER_DOMAINS = new Set([
  'google-analytics.com','googletagmanager.com','googletagservices.com',
  'doubleclick.net','googlesyndication.com','facebook.net','connect.facebook.net',
  'analytics.twitter.com','static.ads-twitter.com','scorecardresearch.com',
  'quantserve.com','adnxs.com','adsrvr.org','rubiconproject.com',
  'pubmatic.com','openx.net','criteo.com','hotjar.com','mixpanel.com',
  'segment.io','segment.com','amplitude.com','heap.io','fullstory.com',
  'newrelic.com','sentry.io','mc.yandex.ru','counter.ok.ru',
  'ad.doubleclick.net','stats.g.doubleclick.net','www.google-analytics.com',
  'ssl.google-analytics.com','pagead2.googlesyndication.com'
])
let trackingProtection = true
let thirdPartyCookieBlock = true
function isTracker(urlStr) {
  try {
    const host = new URL(urlStr).hostname.replace(/^www\./, '')
    return TRACKER_DOMAINS.has(host) || [...TRACKER_DOMAINS].some(t => host.endsWith('.' + t))
  } catch { return false }
}

// ══════════════════════════════════════════════
// ADBLOCK
// ══════════════════════════════════════════════
const AD_DOMAINS = new Set([
  // Google
  'doubleclick.net','googlesyndication.com','googleadservices.com',
  'adservice.google.com','pagead2.googlesyndication.com','ads.google.com',
  'adwords.google.com','googleads.g.doubleclick.net','stats.g.doubleclick.net',
  // Amazon
  'adsystem.amazon.com','aax.amazon-adsystem.com','amazon-adsystem.com',
  // Facebook/Meta
  'connect.facebook.net','an.facebook.com','facebook-web-clients.appspot.com',
  'graph.facebook.com','pixel.facebook.com',
  // Major ad networks
  'advertising.com','adblade.com','adcolony.com','addthis.com',
  'adform.net','adnxs.com','adroll.com','adsrvr.org','adtech.de',
  'adtechus.com','adtechjp.com','adthink.com','adtiger.de',
  'appnexus.com','bidswitch.net','casalemedia.com','contextweb.com',
  'criteo.com','criteo.net','demdex.net','doubleverify.com',
  'flashtalking.com','iasds01.com','imrworldwide.com',
  'lijit.com','liveramp.com','media.net','moatads.com',
  'openx.net','openx.com','outbrain.com','pubmatic.com',
  'quantserve.com','rfihub.com','rlcdn.com','rubiconproject.com',
  'scorecardresearch.com','sharethrough.com','sizmek.com',
  'spotxchange.com','taboola.com','tapad.com','teads.tv',
  'tremorhub.com','triplelift.com','undertone.com','unrulymedia.com',
  'xaxis.com','yieldmo.com','zemanta.com','zucks.net',
  // Pop/push ads
  'popads.net','popcash.net','propellerads.com','adcash.com',
  'hilltopads.net','trafficjunky.net','ero-advertising.com',
  'juicyads.com','plugrush.com','trafficfactory.biz',
  'exoclick.com','adspyglass.com','adsterra.com','mgid.com',
  'revcontent.com','contentad.net','zergnet.com',
  // Crypto miners
  'coinhive.com','coin-hive.com','crypto-loot.com','webminepool.com',
  'minero.cc','monerominer.rocks','cryptoloot.pro',
  // Analytics/tracking
  'hotjar.com','mixpanel.com','segment.io','segment.com',
  'amplitude.com','heap.io','fullstory.com','crazyegg.com',
  'mc.yandex.ru','counter.ok.ru','reklamstore.com','adgager.com',
  'chartbeat.com','chartbeat.net','newrelic.com','nr-data.net',
  'pingdom.net','loggly.com','bugsnag.com','raygun.io',
  // Turkish ad networks
  'admost.com','admost.io','admostnet.com','bugsense.com',
  'passive.pro','syndication.exoclick.com',
  // Additional EasyList domains
  'advertising.microsoft.com','bat.bing.com','clarity.ms',
  'ads.twitter.com','ads.linkedin.com','snap.licdn.com',
  'px.ads.linkedin.com','tr.snapchat.com','sc-static.net',
  'tiktok.com','analytics.tiktok.com','ads.tiktok.com',
  'branch.io','app.link','trk.email','sendgrid.net',
  '2mdn.net','360yield.com','33across.com','4dsply.com',
  'aatkit.com','adadvisor.net','adalliance.io','adamatic.com',
  'adap.tv','adboth.com','adbrn.com','adbutler.com',
  'adclickstats.net','adcombination.com','adconion.com',
  'addapptr.com','addeals.net','addshoppers.com',
  'adengage.com','adf.ly','adfalcon.com','adform.com',
  'adfrmd.com','adgage.net','adgear.com','adgridwork.com',
  'adhese.be','adhese.com','adhood.com','adikteev.com',
  'adition.com','adjug.com','adjuggler.net','adjuggler.com',
  'adkernel.com','adlegend.com','adlightning.com','adlucent.com',
  'admantx.com','admarvel.com','admedo.com','admelior.com',
  'admixer.net','admixer.com','adnetwork.net','adnologies.com',
  'adobedc.net','adobedtm.com','adocean.pl','adometry.com',
  'adperfect.com','adperium.com','adplugg.com','adpredictive.com',
  'adrime.com','adsafeprotected.com','adscale.de','adscend.com',
  'adservinginternational.com','adside.com','adskeeper.co.uk',
  'adsnative.com','adsonar.com','adspirit.de','adswizz.com',
  'adsymptotic.com','adtarget.com','adtarget.me','adtegrity.net',
  'adtoma.com','adtrade.net','adtrue.com','adultadworld.com',
  'adv.vi','advanced-ads.net','advancedwebranking.com',
  'adventori.com','adversal.com','adverticum.net','advertise.com',
  'affiliatefuture.com','affiliatewindow.com','affili.net',
  'agkn.com','aimatch.com','aldomedia.com','alenty.com',
  'aniview.com','answer.io','aolcloud.net',
])
let adblockEnabled = true
let adblockStats = { total: 0, byDomain: {} }
function isAd(urlStr) {
  try {
    const host = new URL(urlStr).hostname.replace(/^www\./, '')
    if (AD_DOMAINS.has(host)) return true
    const parts = host.split('.')
    for (let i = 1; i < parts.length - 1; i++)
      if (AD_DOMAINS.has(parts.slice(i).join('.'))) return true
    return false
  } catch { return false }
}

// ══════════════════════════════════════════════
// TRACKER COMPANY MAP
// ══════════════════════════════════════════════
const TRACKER_COMPANIES = {
  'Google':    ['google-analytics.com','googletagmanager.com','doubleclick.net','googlesyndication.com'],
  'Facebook':  ['facebook.net','connect.facebook.net','an.facebook.com'],
  'Twitter/X': ['analytics.twitter.com','static.ads-twitter.com'],
  'Amazon':    ['adsystem.amazon.com','aax.amazon-adsystem.com'],
  'Criteo':    ['criteo.com','criteo.net'],
  'AppNexus':  ['adnxs.com','appnexus.com'],
  'Taboola':   ['taboola.com'],
  'Outbrain':  ['outbrain.com'],
  'Hotjar':    ['hotjar.com'],
  'Mixpanel':  ['mixpanel.com'],
  'Segment':   ['segment.io','segment.com'],
}
const _domainToCompany = new Map()
for (const [co, doms] of Object.entries(TRACKER_COMPANIES))
  for (const d of doms) _domainToCompany.set(d, co)
function getTrackerCompany(urlStr) {
  try {
    const host = new URL(urlStr).hostname.replace(/^www\./, '')
    if (_domainToCompany.has(host)) return _domainToCompany.get(host)
    const parts = host.split('.')
    for (let i = 1; i < parts.length; i++) {
      const p = parts.slice(i).join('.')
      if (_domainToCompany.has(p)) return _domainToCompany.get(p)
    }
  } catch {}
  return null
}
const trackerMapData = new Map()

// ══════════════════════════════════════════════
// BİRLEŞİK BLOCKING HANDLER
// ══════════════════════════════════════════════
function setupBlockingRules(sess) {
  sess.webRequest.onBeforeRequest({ urls: ['*://*/*'] }, (details, callback) => {
    if (trackingProtection && isTracker(details.url)) {
      const company = getTrackerCompany(details.url)
      if (company) {
        const wc = details.webContentsId
        if (wc) {
          if (!trackerMapData.has(wc)) trackerMapData.set(wc, { total: 0, byCompany: {} })
          const d = trackerMapData.get(wc)
          d.total++
          d.byCompany[company] = (d.byCompany[company] || 0) + 1
          try { mainWindow?.webContents.send('tracker-update', { wc, data: d }) } catch {}
        }
      }
      return callback({ cancel: true })
    }
    if (adblockEnabled && isAdEnhanced(details.url)) {
      adblockStats.total++
      try {
        const host = new URL(details.url).hostname.replace(/^www\./, '')
        adblockStats.byDomain[host] = (adblockStats.byDomain[host] || 0) + 1
      } catch {}
      return callback({ cancel: true })
    }
    callback({})
  })
}

// ══════════════════════════════════════════════
// DNS-OVER-HTTPS
// ══════════════════════════════════════════════
function setupDoH() {
  app.configureHostResolver({
    secureDnsMode: 'secure',
    secureDnsServers: ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query']
  })
  Logger.info('DNS-over-HTTPS active')
}

// ══════════════════════════════════════════════
// FINGERPRINT SCRIPT
// ══════════════════════════════════════════════
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
]
function randomUA() { return USER_AGENTS[crypto.randomInt(USER_AGENTS.length)] }
function fingerprintScript() {
  const WIDTHS  = [1920,1366,1536,1440,1680,1280]
  const HEIGHTS = [1080,768,864,900,1050,800]
  const w = WIDTHS[crypto.randomInt(WIDTHS.length)]
  const h = HEIGHTS[crypto.randomInt(HEIGHTS.length)]
  return `(function(){
    try{
      Object.defineProperty(window,'screen',{get:()=>({width:${w},height:${h},availWidth:${w},availHeight:${h},colorDepth:24,pixelDepth:24}),configurable:false})
      Object.defineProperty(navigator,'languages',{get:()=>['tr-TR','he-IL','en-US'],configurable:false})
      const _gp=WebGLRenderingContext.prototype.getParameter
      WebGLRenderingContext.prototype.getParameter=function(p){if(p===37445)return 'Intel Inc.';if(p===37446)return 'Intel Iris OpenGL Engine';return _gp.call(this,p)}
      const _td=HTMLCanvasElement.prototype.toDataURL
      HTMLCanvasElement.prototype.toDataURL=function(t,...a){const ctx=this.getContext('2d');if(ctx){const img=ctx.getImageData(0,0,this.width,this.height);for(let i=0;i<img.data.length;i+=100)img.data[i]=img.data[i]^(Math.random()*3|0);ctx.putImageData(img,0,0)}return _td.call(this,t,...a)}
      const _RTC=window.RTCPeerConnection||window.webkitRTCPeerConnection
      if(_RTC){const S=function(c,o){if(c&&c.iceServers)c.iceServers=c.iceServers.filter(s=>{const u=Array.isArray(s.urls)?s.urls:[s.urls];return!u.some(u=>u&&u.startsWith('stun:'))});return new _RTC(c,o)};S.prototype=_RTC.prototype;window.RTCPeerConnection=S}
      if(navigator.mediaDevices)navigator.mediaDevices.enumerateDevices=()=>Promise.resolve([])
    }catch(e){}
  })()`
}

// ══════════════════════════════════════════════
// PHISHING
// ══════════════════════════════════════════════
const PHISHING_PATTERNS = [
  /paypal.*login.*verify/i,/bank.*account.*suspend/i,
  /verify.*identity.*urgent/i,/apple.*id.*locked/i,
  /microsoft.*account.*suspend/i,/amazon.*order.*verify/i,
  /netflix.*payment.*fail/i,/account.*suspended.*click/i
]
function checkPhishing(url) {
  try {
    const u = new URL(url)
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname)) return { risk:'medium', reason:'IP address URL — suspicious' }
    if (u.hostname.length > 60) return { risk:'medium', reason:'Abnormally long domain' }
    if (u.hostname.split('.').length > 6) return { risk:'medium', reason:'Excessive subdomains' }
    for (const p of PHISHING_PATTERNS) if (p.test(url)) return { risk:'high', reason:'Phishing pattern detected' }
    return null
  } catch { return null }
}

// ══════════════════════════════════════════════
// PERMISSIONS
// ══════════════════════════════════════════════
function setupPermissions(sess) {
  sess.setPermissionRequestHandler((webContents, permission, callback, details) => {
    const ALLOWED = ['clipboard-read','clipboard-sanitized-write','fullscreen','media']
    if (ALLOWED.includes(permission)) return callback(true)
    Logger.info('Permission denied', { permission, url: details?.requestingUrl?.slice(0,60) })
    mainWindow?.webContents.send('permission-denied', { permission, url: details?.requestingUrl })
    callback(false)
  })
  sess.setPermissionCheckHandler((webContents, permission) =>
    ['clipboard-read','clipboard-sanitized-write','fullscreen','media'].includes(permission))
}

// ══════════════════════════════════════════════
// SESSION SETUP
// ══════════════════════════════════════════════
function setupSession(sess) {
  setupHttpsOnly(sess)
  setupBlockingRules(sess)
  setupPermissions(sess)
  sess.webRequest.onBeforeSendHeaders((details, callback) => {
    const h = { ...details.requestHeaders }
    h['User-Agent'] = randomUA()
    h['DNT'] = '1'
    h['Sec-GPC'] = '1'
    callback({ requestHeaders: h })
  })
  sess.webRequest.onHeadersReceived((details, callback) => {
    const h = { ...details.responseHeaders }
    delete h['x-frame-options']; delete h['X-Frame-Options']
    h['X-Content-Type-Options'] = ['nosniff']
    h['Referrer-Policy'] = ['strict-origin-when-cross-origin']
    h['Permissions-Policy'] = ['geolocation=(), microphone=(), camera=(), payment=(), usb=(), bluetooth=()']
    h['X-XSS-Protection'] = ['1; mode=block']
    callback({ responseHeaders: h })
  })
  sess.on('will-download', (event, item) => {
    const filename = sanitize(item.getFilename(), 200)
    const ext = path.extname(filename).toLowerCase()
    if (DANGEROUS_EXTS.has(ext)) {
      event.preventDefault()
      Logger.warn('Dangerous file blocked', { filename })
      try { mainWindow?.webContents.send('download-blocked', { filename, reason:'Dangerous file type' }) } catch {}
      return
    }
    const id = Date.now()
    const win = BrowserWindow.fromWebContents(event.sender) || mainWindow
    if (win && !win.isDestroyed()) {
      win.webContents.send('download-started', { id, filename })
      item.on('updated', () => { if (!win.isDestroyed()) win.webContents.send('download-progress', { id, received:item.getReceivedBytes(), total:item.getTotalBytes() }) })
      item.on('done', (e, state) => { if (!win.isDestroyed()) { win.webContents.send('download-done', { id, filename, state }); Logger.info('Download complete', { filename, state }) } })
    }
  })
}

// ══════════════════════════════════════════════
// EXTENSION ENGINE
// ══════════════════════════════════════════════
const EXTENSIONS_DIR = path.join(__dirname, 'extensions')

async function loadBuiltinExtensions(sess) {
  if (!ElectronChromeExtensions) {
    Logger.warn('electron-chrome-extensions not available, skipping')
    return []
  }
  const loaded = []
  const extFolders = ['miau-adblock', 'miau-darkmode', 'miau-privacy']
  for (const folder of extFolders) {
    const extPath = path.join(EXTENSIONS_DIR, folder)
    if (!fs.existsSync(extPath)) { Logger.warn('Extension folder not found', { folder }); continue }
    try {
      const ext = await sess.loadExtension(extPath, { allowFileAccess: true })
      loaded.push({ id: ext.id, name: ext.name, path: extPath })
      Logger.info('Extension loaded', { name: ext.name, id: ext.id })
    } catch (e) {
      Logger.error('Extension load failed', { folder, error: e.message })
    }
  }
  return loaded
}

function setupExtensionEngine(win) {
  if (!ElectronChromeExtensions) return null
  try {
    const engine = new ElectronChromeExtensions({
      session: session.defaultSession,
      // Eklenti yeni sekme açmak istediğinde renderer'a yönlendir
      createTab: async (props) => {
        win.webContents.send('ext-open-tab', props)
        return [win.webContents, win]
      },
      selectTab: async (tab) => {
        win.webContents.send('ext-select-tab', { tabId: tab.id })
      },
      removeTab: async (tab) => {
        win.webContents.send('ext-close-tab', { tabId: tab.id })
      },
      // Eklenti pencere açmak isterse sekmeye çevir
      createWindow: async (props) => {
        win.webContents.send('ext-open-tab', { url: props.url })
        return win
      }
    })
    Logger.info('Extension engine initialized')
    return engine
  } catch (e) {
    Logger.error('Extension engine setup failed', { error: e.message })
    return null
  }
}

// ══════════════════════════════════════════════
// IPC HELPERS
// ══════════════════════════════════════════════
function safeHandle(ch, fn) {
  if (registeredHandlers.has(ch)) ipcMain.removeHandler(ch)
  registeredHandlers.add(ch)
  ipcMain.handle(ch, fn)
}

async function dlToFile(win, url, defName) {
  if (!isSafeUrl(url)) return { success:false, error:'Unsafe URL' }
  const ext = (() => { try { const m = new URL(url).pathname.match(/\.([a-zA-Z0-9]{1,5})(\?|$)/); return m ? m[1] : 'bin' } catch { return 'bin' } })()
  const name = sanitize(defName || ('miau-' + Date.now() + '.' + ext), 200)
  const { filePath } = await dialog.showSaveDialog(win, { defaultPath: path.join(app.getPath('downloads'), name) })
  if (!filePath || !isSafePath(filePath)) return { success:false, error:'Cancelled' }
  return new Promise(resolve => {
    const proto = url.startsWith('https') ? https : http
    const req = proto.get(url, { headers:{ 'User-Agent':randomUA() } }, res => {
      if ([301,302].includes(res.statusCode) && isSafeUrl(res.headers.location)) return dlToFile(win, res.headers.location, name).then(resolve)
      const f = fs.createWriteStream(filePath)
      res.pipe(f)
      f.on('finish', () => { f.close(); resolve({ success:true, path:filePath }) })
      f.on('error', e => { resolve({ success:false, error:e.message }) })
    })
    req.on('error', e => resolve({ success:false, error:e.message }))
    req.setTimeout(20000, () => { req.destroy(); resolve({ success:false, error:'Timeout' }) })
  })
}

// ══════════════════════════════════════════════
// SESSION RESTORE
// ══════════════════════════════════════════════
const SESSION_FILE = () => path.join(app.getPath('userData'), 'session.json')
function saveSession(tabs) {
  try { fs.writeFileSync(SESSION_FILE(), JSON.stringify({ tabs, savedAt:Date.now() }), 'utf8') } catch {}
}
function loadSession() {
  try {
    const data = JSON.parse(fs.readFileSync(SESSION_FILE(), 'utf8'))
    if (Date.now() - data.savedAt > 7 * 86400000) return null
    return data.tabs || null
  } catch { return null }
}

// ══════════════════════════════════════════════
// IPC HANDLERS
// ══════════════════════════════════════════════
safeHandle('self-destruct', async (e, opts) => {
  if (e.sender !== mainWindow?.webContents) return { success:false, error:'Unauthorized' }
  const { clearCookies, clearCache, timeDelay=0 } = opts || {}
  const doDestruct = async () => {
    try {
      const storages = []
      if (clearCookies) storages.push('cookies','localstorage','indexdb','shadercache','websql','serviceworkers','cachestorage')
      if (clearCache) storages.push('appcache','filesystem')
      if (storages.length) await session.defaultSession.clearStorageData({ storages })
      if (clearCache) await session.defaultSession.clearCache()
      mainWindow?.webContents.send('self-destruct-done')
    } catch (err) { Logger.error('Self-destruct error', err) }
  }
  if (timeDelay > 0) setTimeout(doDestruct, timeDelay * 60000)
  else await doDestruct()
  return { success:true }
})

safeHandle('get-security-settings', () => ({ httpsOnly:httpsOnlyMode, trackingProtection, thirdPartyCookieBlock }))
safeHandle('set-security-settings', (e, s) => {
  if (e.sender !== mainWindow?.webContents) return false
  if (typeof s.httpsOnly === 'boolean') httpsOnlyMode = s.httpsOnly
  if (typeof s.trackingProtection === 'boolean') trackingProtection = s.trackingProtection
  if (typeof s.thirdPartyCookieBlock === 'boolean') thirdPartyCookieBlock = s.thirdPartyCookieBlock
  return true
})
safeHandle('check-phishing', (e, url) => {
  if (!isSafeUrl(url)) return { risk:'high', reason:'Unsafe protocol' }
  return checkPhishing(url)
})
safeHandle('save-session', (e, tabs) => {
  if (e.sender !== mainWindow?.webContents) return false
  saveSession(tabs); return true
})
safeHandle('load-session', () => loadSession())
safeHandle('get-adblock-state', () => ({ enabled:adblockEnabled, stats:adblockStats }))
safeHandle('set-adblock', (e, enabled) => {
  if (e.sender !== mainWindow?.webContents) return false
  adblockEnabled = !!enabled; return true
})
safeHandle('reset-adblock-stats', (e) => {
  if (e.sender !== mainWindow?.webContents) return false
  adblockStats = { total:0, byDomain:{} }; return true
})
safeHandle('get-tracker-map', (e, wcId) => {
  if (wcId) return trackerMapData.get(wcId) || { total:0, byCompany:{} }
  return Object.fromEntries(trackerMapData)
})
safeHandle('clear-tracker-map', () => { trackerMapData.clear(); return true })

// ── Extension IPC ─────────────────────────────

// ══════════════════════════════════════════════
// YER İMLERİ
// ══════════════════════════════════════════════
const BOOKMARKS_FILE = () => path.join(app.getPath('userData'), 'bookmarks.json')

function loadBookmarks() {
  try {
    if (fs.existsSync(BOOKMARKS_FILE()))
      return JSON.parse(fs.readFileSync(BOOKMARKS_FILE(), 'utf8'))
  } catch {}
  return []
}

function saveBookmarks(bookmarks) {
  try { fs.writeFileSync(BOOKMARKS_FILE(), JSON.stringify(bookmarks, null, 2), 'utf8') } catch {}
}

safeHandle('get-bookmarks',    ()           => loadBookmarks())
safeHandle('add-bookmark',     (e, bm)      => { const b = loadBookmarks(); b.unshift({ ...bm, id: Date.now(), addedAt: Date.now() }); saveBookmarks(b); return b })
safeHandle('remove-bookmark',  (e, id)      => { const b = loadBookmarks().filter(x => x.id !== id); saveBookmarks(b); return b })
safeHandle('update-bookmark',  (e, id, upd) => { const b = loadBookmarks().map(x => x.id === id ? { ...x, ...upd } : x); saveBookmarks(b); return b })
safeHandle('check-bookmark',   (e, url)     => { return loadBookmarks().some(x => x.url === url) })

// ══════════════════════════════════════════════
// DARK READER — CSS injection sistemi
// ══════════════════════════════════════════════
let darkReaderEnabled = false

// Dark Reader CSS'i — tüm sitelere inject edilecek
const DARK_READER_CSS = `
  html { filter: invert(1) hue-rotate(180deg) !important; }
  img, video, canvas, iframe, embed, object,
  [style*="background-image"] {
    filter: invert(1) hue-rotate(180deg) !important;
  }
`

safeHandle('get-dark-reader',  ()          => darkReaderEnabled)
safeHandle('set-dark-reader',  (e, enable) => {
  darkReaderEnabled = !!enable
  // Tüm açık webview'lara uygula
  try {
    mainWindow?.webContents.send('dark-reader-changed', darkReaderEnabled)
  } catch {}
  return darkReaderEnabled
})
safeHandle('get-dark-reader-css', () => DARK_READER_CSS)

// ══════════════════════════════════════════════
// URL PATTERN ADBLOCK (EasyList tarzı)
// ══════════════════════════════════════════════
const AD_URL_PATTERNS = [
  /\/ads?\//i, /\/adserver/i, /\/adserving/i, /\/advert/i,
  /\/banner/i, /\/popup/i, /\/popunder/i, /\/track(ing|er)?\//i,
  /\/pixel\//i, /\/beacon\//i, /\/telemetry/i, /\/analytics/i,
  /\/sponsored/i, /\/promo(tion)?\//i, /\/(im|ad)pression/i,
  /googletag/i, /\.ads\./i, /\/adsense/i, /\/prebid/i,
  /\/header.?bid/i, /\/rtb\//i, /\/vast\.xml/i, /\/vast\?/i,
]

const _origIsAd = isAd
function isAdEnhanced(urlStr) {
  if (_origIsAd(urlStr)) return true
  try {
    const u = new URL(urlStr)
    const full = u.hostname + u.pathname
    for (const p of AD_URL_PATTERNS) if (p.test(full)) return true
  } catch {}
  return false
}

safeHandle('get-extensions', async (e) => {
  if (e.sender !== mainWindow?.webContents) return []
  try {
    const exts = session.defaultSession.getAllExtensions()
    return exts.map(ext => ({
      id:          ext.id,
      name:        ext.manifest?.name || ext.name || 'Unknown',
      version:     ext.manifest?.version || '?',
      description: ext.manifest?.description || '',
      hasPopup:    !!ext.manifest?.action?.default_popup,
      enabled:     true
    }))
  } catch { return [] }
})

safeHandle('get-extension-popup-url', async (e, extId) => {
  if (e.sender !== mainWindow?.webContents) return null
  try {
    const exts = session.defaultSession.getAllExtensions()
    const ext  = exts.find(x => x.id === extId)
    if (!ext) return null
    const popup = ext.manifest?.action?.default_popup
    if (!popup) return null
    return `chrome-extension://${ext.id}/${popup}`
  } catch { return null }
})

setInterval(() => {
  try {
    const mem = process.memoryUsage()
    mainWindow?.webContents.send('ram-update', {
      rss:       Math.round(mem.rss        / 1048576),
      heap:      Math.round(mem.heapUsed   / 1048576),
      heapTotal: Math.round(mem.heapTotal  / 1048576)
    })
  } catch {}
}, 2000)

// ── PASSWORD ENCRYPTION ───────────────────────
const PW_KEY_DIR  = () => path.join(app.getPath('userData'), '.miau_secure')
const PW_KEY_FILE = () => path.join(PW_KEY_DIR(), 'pk')
function ensurePwKeyDir() {
  const dir = PW_KEY_DIR()
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive:true })
    if (process.platform === 'win32') {
      try { require('child_process').execSync(`attrib +H +S "${dir}"`, { windowsHide:true }) } catch {}
    }
  }
}
function getPwKey() {
  try { ensurePwKeyDir(); if (fs.existsSync(PW_KEY_FILE())) return fs.readFileSync(PW_KEY_FILE()) } catch {}
  const key = crypto.randomBytes(32)
  try { ensurePwKeyDir(); fs.writeFileSync(PW_KEY_FILE(), key) } catch {}
  return key
}
function encryptPassword(p) {
  const key=getPwKey(), iv=crypto.randomBytes(12), cipher=crypto.createCipheriv('aes-256-gcm',key,iv)
  const enc=Buffer.concat([cipher.update(p,'utf8'),cipher.final()]), tag=cipher.getAuthTag()
  return Buffer.concat([iv,tag,enc]).toString('base64')
}
function decryptPassword(c) {
  const key=getPwKey(), buf=Buffer.from(c,'base64')
  const iv=buf.slice(0,12), tag=buf.slice(12,28), enc=buf.slice(28)
  const d=crypto.createDecipheriv('aes-256-gcm',key,iv); d.setAuthTag(tag)
  return Buffer.concat([d.update(enc),d.final()]).toString('utf8')
}
safeHandle('encrypt-password', (e, p) => {
  if (e.sender !== mainWindow?.webContents) return null
  if (typeof p !== 'string' || p.length > 500) return null
  try { return encryptPassword(p) } catch { return null }
})
safeHandle('decrypt-password', (e, c) => {
  if (e.sender !== mainWindow?.webContents) return null
  if (typeof c !== 'string') return null
  try { return decryptPassword(c) } catch { return null }
})

// ── SEARCH ENGINES ────────────────────────────
const DEFAULT_ENGINES = {
  duckduckgo:  'https://duckduckgo.com/?q={query}&kae=d&k1=-1&kp=-2',
  google:      'https://www.google.com/search?q={query}',
  brave:       'https://search.brave.com/search?q={query}',
  startpage:   'https://www.startpage.com/search?q={query}',
  bing:        'https://www.bing.com/search?q={query}',
  ecosia:      'https://www.ecosia.org/search?q={query}',
}
let searchEngines = { ...DEFAULT_ENGINES }
let activeEngine  = 'duckduckgo'
safeHandle('get-search-engines', () => ({ engines:searchEngines, active:activeEngine }))
safeHandle('set-search-engine', (e, key) => { if (searchEngines[key]) { activeEngine=key; return true }; return false })
safeHandle('add-search-engine', (e, { key, url }) => {
  if (!key || !url || !isSafeUrl(url.replace('{query}','test'))) return false
  searchEngines[sanitize(key,50)] = sanitize(url,300); return true
})
safeHandle('get-search-url', (e, query) =>
  (searchEngines[activeEngine] || searchEngines.duckduckgo).replace('{query}', encodeURIComponent(query)))

// ══════════════════════════════════════════════
// MAIN WINDOW
// ══════════════════════════════════════════════
function createWindow() {
  mainWindow = new BrowserWindow({
    width:1400, height:900, minWidth:900, minHeight:600,
    frame:false, backgroundColor:'#000000',
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: {
      nodeIntegration:false, contextIsolation:true,
      webviewTag:true, webSecurity:true,
      preload: path.join(__dirname, 'preload.js'),
      sandbox:false, devTools:false
    }
  })

  mainWindow.loadFile('index.html')
  Menu.setApplicationMenu(null)
  Logger.info('Main window created')

  // Ana pencere için yeni pencere engelle
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isSafeUrl(url)) mainWindow?.webContents.send('open-in-new-tab', url)
    return { action:'deny' }
  })

  // Webview'lar attach edildiğinde onların new-window olayını da yakala
  // (Startpage, Bing, Ecosia gibi siteler target="_blank" ile açıyor)
  mainWindow.webContents.on('did-attach-webview', (event, webviewContents) => {
    webviewContents.setWindowOpenHandler(({ url }) => {
      if (isSafeUrl(url)) mainWindow?.webContents.send('open-in-new-tab', url)
      return { action: 'deny' }
    })

    // Webview içinde sağ tık → renderer'a context-menu bilgisini gönder
    webviewContents.on('context-menu', (ev, params) => {
      mainWindow?.webContents.send('webview-context-menu', {
        x: params.x,
        y: params.y,
        linkURL:   params.linkURL   || '',
        srcURL:    params.srcURL    || '',
        mediaType: params.mediaType || 'none',
        selectionText: params.selectionText || '',
        pageURL:   params.pageURL   || '',
      })
    })

    // YouTube / HTML5 video tam ekran desteği
    webviewContents.on('enter-html-full-screen', () => {
      mainWindow?.webContents.send('wv-enter-fullscreen')
    })
    webviewContents.on('leave-html-full-screen', () => {
      mainWindow?.webContents.send('wv-leave-fullscreen')
    })

    // Ses durumu değişince renderer'a bildir
    webviewContents.on('audio-state-changed', ({ audible }) => {
      mainWindow?.webContents.send('wv-audio-changed', {
        wcId: webviewContents.id,
        audible
      })
    })
  })

  // Extension engine başlat
  extensionEngine = setupExtensionEngine(mainWindow)

  mainWindow.on('close', () => {
    try { mainWindow?.webContents.send('save-session-request') } catch {}
  })

  const onMain = (ch, fn) => ipcMain.on(ch, (e, ...a) => { if (e.sender === mainWindow?.webContents) fn(...a) })
  onMain('minimize',          () => mainWindow?.minimize())
  onMain('maximize',          () => mainWindow?.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize())
  onMain('close',             () => mainWindow?.close())
  onMain('toggle-fullscreen', () => {
    mainWindow?.setFullScreen(!mainWindow.isFullScreen())
    mainWindow?.webContents.send('fullscreen-changed', mainWindow.isFullScreen())
  })
  onMain('open-private-tab', () => {
    const tabId     = 'priv-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex')
    const partition = 'private-' + tabId
    const privSess  = session.fromPartition(partition, { cache:false })
    setupSession(privSess)
    privSess.setPermissionRequestHandler((wc, perm, cb) => cb(false))
    privSess.setPermissionCheckHandler(() => false)
    privSess.webRequest.onBeforeRequest({ urls:['file://*/*'] }, (_,cb) => cb({ cancel:true }))
    privateSessions.set(tabId, privSess)
    mainWindow?.webContents.send('open-private-tab', { tabId, partition })
    Logger.info('Private tab created', { tabId })
  })
  onMain('close-private-tab', async (tabId) => {
    const sess = privateSessions.get(tabId)
    if (!sess) return
    try {
      await sess.clearStorageData({ storages:['cookies','localstorage','indexdb','shadercache','websql','serviceworkers','cachestorage'] })
      await sess.clearCache()
    } catch {}
    privateSessions.delete(tabId)
    Logger.info('Private tab session wiped', { tabId })
  })

  safeHandle('toggle-devtools', (e) => {
    if (e.sender !== mainWindow?.webContents) return
    if (mainWindow?.webContents.isDevToolsOpened()) mainWindow.webContents.closeDevTools()
    else mainWindow?.webContents.openDevTools({ mode:'detach' })
  })
  safeHandle('save-screenshot', async (e, dataUrl) => {
    if (e.sender !== mainWindow?.webContents) return null
    if (typeof dataUrl !== 'string' || !dataUrl.startsWith('data:image/png;base64,')) return null
    try {
      const { filePath } = await dialog.showSaveDialog(mainWindow, {
        defaultPath: path.join(app.getPath('pictures'), `miau-${Date.now()}.png`),
        filters:[{ name:'PNG', extensions:['png'] }]
      })
      if (!filePath || !isSafePath(filePath)) return null
      fs.writeFileSync(filePath, dataUrl.replace(/^data:image\/png;base64,/,''), 'base64')
      return filePath
    } catch (err) { Logger.error('Screenshot error', err); return null }
  })
  safeHandle('download-image', async (e, url, fn) => { if (!isSafeUrl(url)) return { success:false }; return dlToFile(mainWindow, url, fn) })
  safeHandle('download-file',  async (e, url, fn) => { if (!isSafeUrl(url)) return { success:false }; return dlToFile(mainWindow, url, fn) })
  safeHandle('get-fp-script',  () => fingerprintScript())

  mainWindow.on('closed', () => { mainWindow = null })

  if (app.isPackaged) {
    autoUpdater.checkForUpdatesAndNotify()
    autoUpdater.on('update-available',  () => mainWindow?.webContents.send('update-available'))
    autoUpdater.on('update-downloaded', () => mainWindow?.webContents.send('update-downloaded'))
    autoUpdater.on('error', err => Logger.error('Update error', { message:err.message }))
  }
}

// ══════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════
app.whenReady().then(async () => {
  app.setAppUserModelId('com.miau.browser')
  Logger.init()
  Logger.info('MIAU starting', { version:app.getVersion(), platform:process.platform })

  app.on('second-instance', () => {
    if (mainWindow) { if (mainWindow.isMinimized()) mainWindow.restore(); mainWindow.focus() }
  })

  try { setupDoH() } catch (e) { Logger.warn('DoH setup failed', { msg:e.message }) }
  setupSession(session.defaultSession)

  // Eklentileri pencere açılmadan önce yükle
  const loadedExts = await loadBuiltinExtensions(session.defaultSession)
  Logger.info('Extensions loaded', { count:loadedExts.length, names:loadedExts.map(e=>e.name) })

  createWindow()
  try { mainWindow?.setIcon(path.join(__dirname, 'icon.png')) } catch {}
})

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit() })
process.on('uncaughtException', err => {
  Logger.error('UncaughtException', { name:err.name, message:err.message })
  try { dialog.showErrorBox('MIAU — Error', err.message) } catch {}
})
process.on('unhandledRejection', reason => Logger.error('UnhandledRejection', { reason:String(reason) }))
