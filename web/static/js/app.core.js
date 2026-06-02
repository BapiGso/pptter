(function () {
  "use strict";

  const PROTOCOL = "X25519-HKDF-A256GCM+Ed25519";
  const PROTOCOL_VERSION = 2;
  const HKDF_INFO = "pptter-msg-v2";
  // 留言（离线消息）：不走每对成员的临时 ECDH（那条路有前向保密、对方重连即换密钥，
  // 留言必然解不开），而是用房间预共享密钥（URL #片段）派生对称密钥，服务端只暂存密文。
  // 这天然比实时端到端更弱：无前向保密、服务端持有密文、拿到链接者皆可读——前端会以醒目样式区分。
  const NOTE_VERSION = 1;
  const NOTE_ALG = "ROOMKEY-HKDF-A256GCM+Ed25519";
  const NOTE_HKDF_INFO = "pptter-note-v1";
  const PAD_BUCKET = 256;
  const MAX_TEXT_BYTES = 4096;
  const MAX_RELAY_BYTES = 1.5 * 1024 * 1024;
  // P2P 直传接收上限：接收端把所有分片缓存在内存里再合成 Blob，
  // 若不设上限，对端可声明超大文件或持续发送把浏览器内存撑爆。
  const MAX_P2P_FILE_BYTES = 512 * 1024 * 1024;
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
  const THEMES = ["pptter", "pptter-dark", "cupcake", "synthwave", "retro", "dracula"];
  const DARK_THEMES = new Set(["pptter-dark", "synthwave", "dracula"]);

  // deriveSharedKey 把一次 X25519 ECDH 的共享密钥经 HKDF 派生成一次性 AES-256-GCM 密钥。
  //   - dh：本端会话密钥提供方（WebCrypto 或 nacl 回退），deriveSecret(peerRaw) 返回 32 字节原始共享点；
  //     WebCrypto deriveBits 与 nacl.scalarMult 输出一致，两种实现可互通。
  //   - roomKeyBytes：可选的房间预共享密钥（来自 URL #fragment），混入 HKDF info 作为额外口令层，
  //     不知道房间密钥的人即便拿到密文也派生不出相同的 AES 密钥。HKDF/AES-GCM 始终走 WebCrypto。
  async function deriveSharedKey(dh, peerDhRaw, saltBytes, roomKeyBytes) {
    const sharedBytes = await dh.deriveSecret(peerDhRaw);
    try {
      const hkdfKey = await crypto.subtle.importKey("raw", sharedBytes, "HKDF", false, ["deriveKey"]);
      return await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: saltBytes, info: hkdfInfoBytes(roomKeyBytes) },
        hkdfKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    } finally {
      wipeBytes(sharedBytes);
    }
  }

  function hkdfInfoBytes(roomKeyBytes) {
    const base = textEncoder.encode(HKDF_INFO);
    if (!roomKeyBytes || roomKeyBytes.length === 0) {
      return base;
    }
    const info = new Uint8Array(base.length + 1 + roomKeyBytes.length);
    info.set(base, 0);
    info[base.length] = 0x1f; // 分隔符，避免 info 拼接歧义。
    info.set(roomKeyBytes, base.length + 1);
    return info;
  }

  // noteKeyIKM 决定留言对称密钥的输入密钥材料（IKM）：
  //   - 私密房间（有 #密钥）：用房间预共享密钥字节——服务端不知道，无法解密；
  //   - 公共 lobby（无密钥）：退化为由公开房间名派生——服务端也能算出，因此留言对服务端可读，最不安全。
  function noteKeyIKM(room, roomKeyBytes) {
    if (roomKeyBytes && roomKeyBytes.length > 0) {
      return roomKeyBytes;
    }
    return textEncoder.encode("pptter-public-note|" + String(room || ""));
  }

  // deriveNoteKey 由留言 IKM + 每条随机 salt 派生一次性 AES-256-GCM 密钥（始终走 WebCrypto）。
  async function deriveNoteKey(ikmBytes, saltBytes) {
    const hkdfKey = await crypto.subtle.importKey("raw", ikmBytes, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: saltBytes, info: textEncoder.encode(NOTE_HKDF_INFO) },
      hkdfKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  // noteSignedView 返回留言签名所覆盖的规范字节（不含 sig 本身），作者用 Ed25519 身份私钥签名，
  // 任何拿到房间密钥的人都能验签作者身份并发现密文被篡改（公共房间尤其重要：服务端能算出密钥）。
  function noteSignedView(envelope) {
    const canonical = [
      "note-v" + NOTE_VERSION, String(envelope.ts), envelope.idKey, envelope.salt, envelope.iv, envelope.ct,
    ].join("|");
    return textEncoder.encode(canonical);
  }

  // createCrypto 在页面加载时探测 WebCrypto 是否实现 Ed25519 / X25519；
  // 任一缺失时（部分移动端浏览器报 "Unrecognized name"）回退到本地内置的 tweetnacl，
  // 只替换签名与 ECDH 这两条曲线，对称层（HKDF/AES-GCM）仍走所有浏览器都支持的 WebCrypto。
  async function createCrypto() {
    const subtle = window.crypto && window.crypto.subtle;
    if (!subtle) {
      throw new Error("浏览器不支持 Web Crypto（AES-GCM/HKDF）");
    }
    const edNative = await probeAlgo({ name: "Ed25519" }, ["sign", "verify"]);
    const dhNative = await probeAlgo({ name: "X25519" }, ["deriveBits"]);
    const nacl = window.nacl;
    if ((!edNative || !dhNative) && !nacl) {
      throw new Error("浏览器缺少 Ed25519/X25519，且未能加载本地回退库");
    }
    return {
      edNative,
      dhNative,
      usingFallback: !edNative || !dhNative,
      makeIdentity: edNative ? makeNativeIdentity : () => makeNaclIdentity(nacl),
      importVerifier: edNative ? makeNativeVerifier : (raw) => makeNaclVerifier(nacl, raw),
      makeDH: dhNative ? makeNativeDH : () => makeNaclDH(nacl),
    };
  }

  async function probeAlgo(algo, usages) {
    try {
      await crypto.subtle.generateKey(algo, false, usages);
      return true;
    } catch {
      return false;
    }
  }

  async function makeNativeIdentity() {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    return {
      publicRaw,
      sign: async (bytes) => new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, bytes)),
    };
  }

  async function makeNativeVerifier(raw) {
    const key = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, true, ["verify"]);
    return {
      verify: (sig, bytes) => crypto.subtle.verify({ name: "Ed25519" }, key, sig, bytes),
    };
  }

  async function makeNativeDH() {
    const pair = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    return {
      publicRaw,
      deriveSecret: async (peerRaw) => {
        const peerKey = await crypto.subtle.importKey("raw", peerRaw, { name: "X25519" }, true, []);
        const bits = await crypto.subtle.deriveBits({ name: "X25519", public: peerKey }, pair.privateKey, 256);
        return new Uint8Array(bits);
      },
    };
  }

  function makeNaclIdentity(nacl) {
    const pair = nacl.sign.keyPair();
    return {
      publicRaw: pair.publicKey,
      sign: async (bytes) => nacl.sign.detached(bytes, pair.secretKey),
    };
  }

  function makeNaclVerifier(nacl, raw) {
    return {
      verify: async (sig, bytes) => nacl.sign.detached.verify(bytes, sig, raw),
    };
  }

  function makeNaclDH(nacl) {
    const pair = nacl.box.keyPair();
    return {
      publicRaw: pair.publicKey,
      deriveSecret: async (peerRaw) => nacl.scalarMult(pair.secretKey, peerRaw),
    };
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
    const fromPath = roomFromPath(location.pathname);
    if (fromPath) {
      return fromPath;
    }
    const fromHash = normalizeRoom(decodeURIComponent((location.hash || "").replace(/^#/, "")));
    return fromHash || DEFAULT_ROOM;
  }

  // roomFromPath 从 /r/<room> 路径里取房间名（房间名体现在 GET 请求里），
  // 服务端把这个路径当作 SPA 入口返回，不记录、不解析房间名。
  function roomFromPath(pathname) {
    const match = /^\/r\/([^/]+)/.exec(String(pathname || ""));
    if (!match) {
      return "";
    }
    try {
      return normalizeRoom(decodeURIComponent(match[1]));
    } catch {
      return "";
    }
  }

  function roomURL(room) {
    return location.origin + "/r/" + encodeURIComponent(normalizeRoom(room) || DEFAULT_ROOM);
  }

  // randomRoomName 生成一个只含房间名合法字符的随机短名，用于「新建房间」。
  function randomRoomName() {
    const bytes = new Uint8Array(6);
    crypto.getRandomValues(bytes);
    const suffix = bytesToBase64(bytes).replace(/[^A-Za-z0-9]/g, "").slice(0, 8).toLowerCase();
    return normalizeRoom("room-" + (suffix || Date.now().toString(36)));
  }

  function normalizeRoom(value) {
    return String(value || "").trim().replace(roomPattern, "-").replace(/-+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
  }

  // ---- 房间预共享密钥（URL #fragment） ----
  // 密钥放在 URL 的 # 片段里：浏览器永远不会把 # 后的内容发给服务器，所以服务端无从得知；
  // 它会被混入 HKDF info，作为房间的一层预共享口令——没有完整分享链接的人即便混进房间，
  // 派生出的 AES 密钥也不同，无法解密。注意：同一房间内所有人必须共享同一份密钥。

  // roomKeyFromHash 从 #k=<token> 取房间密钥，找不到返回空串。
  function roomKeyFromHash() {
    const hash = String(location.hash || "").replace(/^#/, "");
    const match = /(?:^|&)k=([^&]+)/.exec(hash);
    if (!match) {
      return "";
    }
    try {
      return normalizeRoomKey(decodeURIComponent(match[1]));
    } catch {
      return "";
    }
  }

  // normalizeRoomKey 只保留 URL 安全字符，限定长度，避免畸形片段。
  function normalizeRoomKey(value) {
    return String(value || "").trim().replace(/[^A-Za-z0-9_-]/g, "").slice(0, 64);
  }

  // randomRoomKey 为新建的私密房间生成一个高熵预共享密钥。
  function randomRoomKey() {
    const bytes = new Uint8Array(18);
    crypto.getRandomValues(bytes);
    return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "").slice(0, 24);
  }

  // roomKeyToBytes 把密钥 token 转成混入 HKDF 的字节；空密钥返回 null（即公共房间不加这层）。
  function roomKeyToBytes(token) {
    const clean = normalizeRoomKey(token);
    return clean ? textEncoder.encode(clean) : null;
  }

  // shareURL 生成可分享链接：房间名在路径里，房间密钥（若有）放在 # 片段里。
  function shareURL(room, keyToken) {
    const base = location.origin + "/r/" + encodeURIComponent(normalizeRoom(room) || DEFAULT_ROOM);
    const key = normalizeRoomKey(keyToken);
    return key ? base + "#k=" + encodeURIComponent(key) : base;
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
    return DARK_THEMES.has(theme);
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
    NOTE_VERSION,
    NOTE_ALG,
    DEFAULT_ROOM,
    MAX_TEXT_BYTES,
    MAX_RELAY_BYTES,
    MAX_P2P_FILE_BYTES,
    RTC_CHUNK,
    REPLAY_WINDOW_MS,
    GROUP,
    MAX_NICK_LEN,
    MAX_MESSAGES_PER_THREAD,
    TONES,
    THEMES,
    textEncoder,
    createCrypto,
    deriveSharedKey,
    noteKeyIKM,
    deriveNoteKey,
    noteSignedView,
    signedView,
    padPlaintext,
    unpadPlaintext,
    initialRoom,
    roomFromPath,
    normalizeRoom,
    roomKeyFromHash,
    normalizeRoomKey,
    randomRoomKey,
    roomKeyToBytes,
    shareURL,
    roomURL,
    randomRoomName,
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
