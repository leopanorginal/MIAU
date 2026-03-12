<div align="center">

# 🐱 MIAU Browser

**Privacy-focused, hacker-themed desktop browser for Windows**  
Built with Electron · v5.0.0 · by [@leopanorginal](https://github.com/leopanorginal)

[![Release](https://img.shields.io/badge/release-v5.0.0-brightgreen?style=flat-square)](https://github.com/leopanorginal/MIAU/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-blue?style=flat-square)](https://github.com/leopanorginal/MIAU/releases)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)

</div>

---

## 📥 Installation

1. Go to **[Releases](https://github.com/leopanorginal/MIAU/releases)**
2. Download **`MIAU Browser Setup 5.0.0.exe`**
3. Run the installer
4. Choose your install directory
5. Click install and enjoy! 🚀

---

## ✨ Features

### 🛡️ Privacy & Security
- **HTTPS-Only mode** — Automatically upgrades HTTP requests to HTTPS (localhost excluded)
- **DNS-over-HTTPS (DoH)** — Encrypted DNS via Cloudflare and Google
- **Fingerprint protection** — Screen resolution, WebGL renderer, Canvas output and User-Agent are randomized per session
- **WebRTC IP leak prevention** — STUN servers are filtered so your real IP stays hidden
- **Phishing detection** — URLs are analyzed against known patterns; suspicious sites are flagged with a warning
- **Permission manager** — Location, microphone, camera and USB permissions are denied by default
- **Security headers** — `DNT`, `Sec-GPC`, `Referrer-Policy`, `Permissions-Policy` and more are injected into every request

### 🚫 Ad & Tracker Blocking
- **Built-in AdBlock** — Blocks 200+ ad domains (Google, Amazon, Facebook, Taboola, Criteo and more)
- **Tracker protection** — Blocks analytics and tracking scripts from Google, Facebook, Twitter/X, Hotjar, Mixpanel, Segment and more
- **Crypto miner blocker** — CoinHive, Crypto-Loot and similar scripts are automatically blocked
- **Tracker map** — See in real time which companies are making requests and how many
- **Ad statistics** — Total blocked requests with per-domain breakdown

### 🪟 Private Tabs
- Each private tab runs in its own fully isolated session
- On close, all cookies, localStorage, IndexedDB and cache are completely wiped
- All permissions automatically denied inside private tabs

### 🎨 Themes
- **50+ built-in themes** — Dark, light, cute, hacker, space and many more
- Switch themes instantly from the settings panel

### 🌐 Multilingual
- **Hebrew language support** included
- More languages coming soon

### 💣 Self-Destruct Mode
- Instantly wipe all browsing data with a single action
- Clears cookies, cache, history and local storage

### 🧩 Extension Support
- Chrome extension loading via `electron-chrome-extensions`
- Built-in extensions: **MIAU AdBlock**, **MIAU Dark Mode**, **MIAU Privacy**
- Manifest V3 compatible `declarativeNetRequest`-based ad blocker

### 🔎 Search Engines
- Default: **DuckDuckGo**
- Built-in: Google, Brave, Startpage, Bing, Ecosia
- Add your own custom search engine

### 📄 Built-in PDF Viewer
- View PDF files directly in the browser — no external app needed

### 🌙 More
- **Cute chibi girl animation** 🥺
- **Dark Reader** support
- **Bookmarks** — add, remove, update
- **History** tracking
- **Session save & restore** — pick up where you left off
- **Screenshot** capture
- **Auto-update** via GitHub Releases
- **RAM usage** live monitoring
- **YouTube HTML5 fullscreen** support
- Right-click **context menu** (links, images, text selection)
- **Download manager** — dangerous file extensions blocked automatically

---

## 🔒 Security Architecture

```
Renderer (index.html)
       │
       │  contextBridge (allowlist enforced)
       ▼
  preload.js
       │
       │  IPC (registered channels only)
       ▼
   main.js
  ├─ Session → HTTPS-only, header injection, permission manager
  ├─ webRequest → AdBlock + tracker blocking
  ├─ DoH → Encrypted DNS (Cloudflare + Google)
  └─ Fingerprint → Random UA, Canvas, WebGL, screen size
```

- `contextIsolation: true` — Main process and renderer are fully isolated
- `nodeIntegration: false` — No direct Node.js access from renderer
- All IPC channels protected by strict allowlist

---

## 🗂️ Project Structure

```
miau-browser/
├── main.js                  # Main Electron process
├── preload.js               # Secure IPC bridge for the main window
├── preload-incognito.js     # Isolated IPC bridge for private tabs
├── index.html               # Main browser UI
├── incognito.html           # Private tab UI
├── extensions/
│   ├── miau-adblock/        # Built-in ad blocker (Manifest V3)
│   ├── miau-darkmode/
│   └── miau-privacy/
└── package.json
```

---

## 🛠️ Build from Source

### Requirements
- [Node.js](https://nodejs.org/) v18+
- npm

```bash
git clone https://github.com/leopanorginal/MIAU.git
cd MIAU
npm install
npm start
```

### Build Windows installer
```bash
npm run build:win
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
  Made with 🐱 by <a href="https://github.com/leopanorginal">leopanorginal</a>
</div>
