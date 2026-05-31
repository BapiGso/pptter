(function () {
  "use strict";

  const PROTOCOL = "X25519-HKDF-A256GCM+Ed25519";
  const PROTOCOL_VERSION = 2;
  const HKDF_INFO = "pptter-msg-v2";
  const PAD_BUCKET = 256;
  const MAX_TEXT_BYTES = 4096;
  const MAX_RELAY_BYTES = 1.5 * 1024 * 1024;
  const RTC_CHUNK = 16 * 1024;
  const REPLAY_WINDOW_MS = 5 * 60 * 1000;
  const DEFAULT_ROOM = "lobby";
  const GROUP = "group";
  const MAX_NICK_LEN = 24;
  const MAX_MESSAGES_PER_THREAD = 200;
  const AVATAR_GRID = 6;
  const roomPattern = /[^A-Za-z0-9_-]/g;
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  const TONES = {
    soft: [{ f: 660, t: "triangle", d: 0.22, g: 0.12 }],
    ding: [{ f: 880, t: "sine", d: 0.12, g: 0.12 }, { f: 1320, t: "sine", d: 0.2, g: 0.1, at: 0.1 }],
    pop: [{ f: 420, t: "square", d: 0.09, g: 0.1 }],
    chime: [{ f: 784, t: "sine", d: 0.16, g: 0.1 }, { f: 988, t: "sine", d: 0.16, g: 0.09, at: 0.12 }, { f: 1175, t: "sine", d: 0.24, g: 0.09, at: 0.24 }],
    blip: [{ f: 300, t: "sawtooth", d: 0.06, g: 0.08 }, { f: 620, t: "sawtooth", d: 0.08, g: 0.08, at: 0.07 }],
  };
  const THEMES = ["pptter", "pptter-dark", "pptter-grape", "pptter-ocean", "pptter-sunset", "pptter-mid"];

  async function deriveSharedKey(privateKey, peerPublicKey, saltBytes) {
    const sharedBits = await crypto.subtle.deriveBits({ name: "X25519", public: peerPublicKey }, privateKey, 256);
    const sharedBytes = new Uint8Array(sharedBits);
    try {
      const hkdfKey = await crypto.subtle.importKey("raw", sharedBytes, "HKDF", false, ["deriveKey"]);
      return await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: saltBytes, info: textEncoder.encode(HKDF_INFO) },
        hkdfKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    } finally {
      wipeBytes(sharedBytes);
    }
  }

  function signedView(envelope, dest) {
    const canonical = [
      "v" + PROTOCOL_VERSION, envelope.scope, dest,
      String(envelope.ctr), String(envelope.ts), envelope.salt, envelope.iv, envelope.ct,
    ].join("|");
    return textEncoder.encode(canonical);
  }

  function padPlaintext(plaintextBytes) {
    const total = 4 + plaintextBytes.length;
    const padded = new Uint8Array(Math.ceil(total / PAD_BUCKET) * PAD_BUCKET);
    padded[0] = (plaintextBytes.length >>> 24) & 0xff;
    padded[1] = (plaintextBytes.length >>> 16) & 0xff;
    padded[2] = (plaintextBytes.length >>> 8) & 0xff;
    padded[3] = plaintextBytes.length & 0xff;
    padded.set(plaintextBytes, 4);
    return padded;
  }

  function unpadPlaintext(paddedBytes) {
    if (paddedBytes.length < 4) {
      throw new Error("padding 长度不足");
    }
    const length = (paddedBytes[0] * 0x1000000) + (paddedBytes[1] << 16) + (paddedBytes[2] << 8) + paddedBytes[3];
    if (length < 0 || length > paddedBytes.length - 4) {
      throw new Error("padding 长度非法");
    }
    return textDecoder.decode(paddedBytes.subarray(4, 4 + length));
  }

  function initialRoom() {
    const fromHash = normalizeRoom(decodeURIComponent((location.hash || "").replace(/^#/, "")));
    return fromHash || DEFAULT_ROOM;
  }

  function normalizeRoom(value) {
    return String(value || "").trim().replace(roomPattern, "-").replace(/-+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
  }

  function websocketURL(room) {
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    return protocol + "//" + location.host + "/ws/" + encodeURIComponent(room);
  }

  function bytesToBase64(bytes) {
    let binary = "";
    const chunkSize = 0x8000;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      binary += String.fromCharCode.apply(null, bytes.subarray(offset, offset + chunkSize));
    }
    return btoa(binary);
  }

  function base64ToBytes(base64) {
    const binary = atob(String(base64 || ""));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function wipeBytes(bytes) {
    if (bytes && typeof bytes.fill === "function") {
      bytes.fill(0);
    }
  }

  function shortID(id) {
    if (!id) {
      return "未知";
    }
    return id.length <= 12 ? id : id.slice(0, 6) + "…" + id.slice(-4);
  }

  function avatarIndex(id) {
    let hash = 0;
    for (let i = 0; i < id.length; i += 1) {
      hash = (hash * 131 + id.charCodeAt(i)) >>> 0;
    }
    return hash % (AVATAR_GRID * AVATAR_GRID);
  }

  function formatTime(date) {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function safeError(error) {
    return error && error.message ? String(error.message).slice(0, 120) : "未知错误";
  }

  function humanSize(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) {
      return n + " B";
    }
    if (n < 1024 * 1024) {
      return (n / 1024).toFixed(1) + " KB";
    }
    return (n / 1024 / 1024).toFixed(1) + " MB";
  }

  function isDarkTheme(theme) {
    return theme === "pptter-dark" || theme === "pptter-mid";
  }

  function stunURL(host, port) {
    const cleanHost = String(host || "").trim();
    const cleanPort = String(port || "").trim();
    if (!cleanHost || !cleanPort) {
      return "";
    }
    const urlHost = cleanHost.includes(":") && cleanHost[0] !== "[" ? "[" + cleanHost + "]" : cleanHost;
    return "stun:" + urlHost + ":" + cleanPort;
  }

  window.PPTTERCore = {
    PROTOCOL,
    PROTOCOL_VERSION,
    MAX_TEXT_BYTES,
    MAX_RELAY_BYTES,
    RTC_CHUNK,
    REPLAY_WINDOW_MS,
    GROUP,
    MAX_NICK_LEN,
    MAX_MESSAGES_PER_THREAD,
    TONES,
    THEMES,
    textEncoder,
    deriveSharedKey,
    signedView,
    padPlaintext,
    unpadPlaintext,
    initialRoom,
    websocketURL,
    bytesToBase64,
    base64ToBytes,
    wipeBytes,
    shortID,
    avatarIndex,
    formatTime,
    safeError,
    humanSize,
    isDarkTheme,
    stunURL,
  };
})();
