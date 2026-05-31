(function () {
  "use strict";

  // 端到端加密的零信任群聊/私聊。UI 使用 Alpine.js CSP 构建，
  // 兼容严格 CSP（script-src 'self'，无 unsafe-eval）。
  //
  // 协议 v2：
  //   - 身份密钥 Ed25519：派生匿名 ID，并对每条消息签名（发送者认证）。
  //   - 会话密钥 X25519（每次连接重新生成）：ECDH + HKDF 派生一次性 AES-256-GCM 密钥；
  //     身份密钥只签名、永不解密，会话结束丢弃即获前向保密。dhSig 把会话公钥绑定到身份，
  //     使服务器无法替换某成员的会话公钥而不被发现。
  //   - 防重放：信封内含单调计数器 ctr + 时间戳 ts，并纳入签名。
  //   - 抗长度分析：明文按 256 字节档位 padding。
  //   - scope：group=群聊（加密给所有人）/ dm=私聊（只加密给一人），纳入签名。
  //   - 明文内容是一段 JSON：{k:"t",t:文本} 或 {k:"i",m:mime,d:图片Base64}，
  //     因此文字和图片都端到端加密，服务器只转发不可解密的密文。

  const core = window.PPTTERCore;
  if (!core) {
    throw new Error("PPTTERCore 未加载");
  }
  const {
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
  } = core;

  const state = {
    room: initialRoom(),
    self: null,
    peers: [],
    threads: { group: [] },
    unread: {},
    active: GROUP,
    search: "",
    muted: false,
    nick: "",
    tone: "soft",
    stun: "",
    backgroundImage: "",
    iceServers: null,
    p2pPick: false,
    socket: null,
    identityKeyPair: null,
    dhKeyPair: null,
    idKeyB64: "",
    dhKeyB64: "",
    dhSigB64: "",
    sendCounter: 0,
    nextMessageID: 1,
    statusText: "初始化",
    statusTone: "warn",
    reconnecting: false,
  };

  // 单条活动的 WebRTC 直连（仅用于私聊大文件）。
  const P2P_IDLE_KEEPALIVE_MS = 2 * 60 * 1000;
  // 握手超时：连接态（请求/打洞/响应）超过该时长仍未建立即放弃，给出明确提示并复位，
  // 避免对方不在该会话时本端永远卡在「打洞中」。对方打开会话后由其重新发起即可自动重连。
  const P2P_HANDSHAKE_TIMEOUT_MS = 15 * 1000;
  const rtc = {
    pc: null,
    channel: null,
    peerId: null,
    state: "idle",
    ready: false,
    connecting: false,
    loadingLabel: "",
    loadingFrame: "/",
    loadingIndex: 0,
    loadingTimer: 0,
    idleTimer: 0,
    handshakeTimer: 0,
    recv: null,
    queue: [],
    sending: null,
    sentFiles: new Map(),
    polite: false,
    makingOffer: false,
    localShare: null,
    shareSenders: null,
    remoteStream: null,
    localVoice: null,
    voiceSenders: null,
    micMuted: false,
    remoteVoiceStream: null,
  };
  const P2P_LOADING_FRAMES = ["/", "-", "\\", "|"];
  const P2P_STATE = {
    IDLE: "idle",
    REQUESTING: "requesting",
    OFFERING: "offering",
    ANSWERING: "answering",
    CONNECTED: "connected",
    FAILED: "failed",
    CLOSED: "closed",
  };
  const TRANSFER_STATUS = {
    QUEUED: "queued",
    SENDING: "sending",
    RECEIVING: "receiving",
    DONE: "done",
    FAILED: "failed",
    CANCELED: "canceled",
  };

  let toastTimer = 0;
  let audioCtx = null;
  let booted = false;
  let ui = null;

  function boot() {
    if (booted) {
      return;
    }
    booted = true;
    start();
  }

  function alpineActions() {
    return {
      bind(instance) {
        ui = instance;
      },
      boot,
      sync: syncUI,
      searchChanged(value) {
        state.search = String(value || "");
        renderConversations();
      },
      sendText: () => { void sendText(); },
      select: (key) => selectConversation(key),
      reconnect: () => { void reconnect(); },
      pickFile: () => chooseFile(false),
      p2pClick: () => { void p2pButtonClick(); },
      toggleScreenShare: () => { void toggleScreenShare(); },
      fullscreenRemote: () => {
        const video = ui && ui.$refs ? ui.$refs.remoteVideo : null;
        if (video && typeof video.requestFullscreen === "function") {
          void video.requestFullscreen().catch(() => {});
        }
      },
      pipRemote: () => {
        const video = ui && ui.$refs ? ui.$refs.remoteVideo : null;
        if (!video) {
          return;
        }
        if (document.pictureInPictureElement) {
          void document.exitPictureInPicture().catch(() => {});
        } else if (typeof video.requestPictureInPicture === "function") {
          void video.requestPictureInPicture().catch(() => {});
        }
      },
      toggleVoice: () => { void toggleVoice(); },
      toggleMute: () => toggleMute(),
      hangupVoice: () => {
        // 挂断 = 彻底离开通话：停掉自己的麦克风，并停止接收对方音频、收起浮条。
        stopVoice();
        detachRemoteVoice();
      },
      onFileInput: (event) => handlePickedFile(event.target),
      dropFile: (event) => {
        const files = event.dataTransfer && event.dataTransfer.files;
        if (files && files[0]) {
          void handleFile(files[0]);
        }
      },
      pasteFile: (event) => {
        const files = event.clipboardData && event.clipboardData.files;
        if (files && files[0]) {
          void handleFile(files[0]);
        }
      },
      saveSound: () => {
        state.muted = !(ui && ui.soundOn);
        saveSetting("muted", state.muted ? "1" : "0");
      },
      onBgFile: (event) => {
        const input = event.target;
        if (input.files && input.files[0]) {
          void handleBgFile(input.files[0]);
        }
        input.value = "";
      },
      resetBackground: () => applyBackground(null),
      saveNick: () => setNick(ui ? ui.nick : ""),
      applyTheme: (theme) => applyTheme(theme),
      saveTone: () => {
        state.tone = (ui && TONES[ui.tone]) ? ui.tone : "soft";
        saveSetting("tone", state.tone);
      },
      testTone: () => {
        ensureAudio();
        playTone(ui ? ui.tone : state.tone);
      },
      saveStun: () => {
        const raw = ui ? String(ui.stun || "").trim() : "";
        const stun = normalizeStunSetting(raw);
        if (raw && !stun) {
          state.stun = "";
          removeSetting("stun");
          if (ui) {
            ui.stun = "";
          }
          showToast("STUN 地址格式无效，已忽略");
          return;
        }
        state.stun = stun;
        if (ui) {
          ui.stun = stun;
        }
        if (stun) {
          saveSetting("stun", stun);
        } else {
          removeSetting("stun");
        }
      },
      fingerprint: () => fingerprint(),
      toggleTheme: (event) => toggleTheme(event),
      ensureAudio: () => ensureAudio(),
      cancelTransfer: (messageId) => cancelTransfer(messageId),
      retryTransfer: (messageId) => retryTransfer(messageId),
    };
  }

  document.addEventListener("alpine:init", () => {
    registerAlpineComponent();
  });

  window.addEventListener("pagehide", () => {
    closeRtcObjects();
    closeSocket();
  });

  window.addEventListener("pageshow", (event) => {
    if (event.persisted && booted) {
      void reconnect();
    }
  });

  registerAlpineComponent();

  function registerAlpineComponent() {
    if (!window.Alpine || window.__pptterChatRegistered) {
      return;
    }
    window.__pptterChatRegistered = true;
    window.Alpine.data("chat", window.PPTTERUI.createChatComponent(alpineActions()));
    if (document.body && document.body.hasAttribute("x-data") && !document.body._x_dataStack && typeof window.Alpine.initTree === "function") {
      window.Alpine.initTree(document.body);
    }
  }

  function start() {
    initSettings();
    void loadRtcConfig();
    renderConversations();
    syncHeaderUI();
    void init();
  }

  function chooseFile(p2pOnly) {
    if (!canSend()) {
      return;
    }
    state.p2pPick = !!p2pOnly;
    const input = ui && ui.$refs ? ui.$refs.fileInput : null;
    if (input) {
      input.click();
    }
  }

  function handlePickedFile(input) {
    if (!input || !input.files || !input.files[0]) {
      state.p2pPick = false;
      return;
    }
    const file = input.files[0];
    if (state.p2pPick) {
      void sendFileP2P(file);
    } else {
      void handleFile(file);
    }
    state.p2pPick = false;
    input.value = "";
  }

  async function init() {
    if (!window.crypto || !window.crypto.subtle) {
      setStatus("浏览器不支持加密", "bad");
      addSystemMessage("需要支持 Web Crypto（Ed25519/X25519）的现代浏览器，建议 HTTPS 或 localhost。");
      return;
    }
    try {
      setStatus("生成密钥", "warn");
      await generateIdentity();
      addSystemMessage("已生成端到端加密身份，私钥只在本页内存，永不上传服务器。");
      await connect();
    } catch (error) {
      setStatus("初始化失败", "bad");
      addSystemMessage("初始化失败：" + safeError(error));
    }
  }

  async function generateIdentity() {
    state.identityKeyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    state.dhKeyPair = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    const idRaw = new Uint8Array(await crypto.subtle.exportKey("raw", state.identityKeyPair.publicKey));
    const dhRaw = new Uint8Array(await crypto.subtle.exportKey("raw", state.dhKeyPair.publicKey));
    state.idKeyB64 = bytesToBase64(idRaw);
    state.dhKeyB64 = bytesToBase64(dhRaw);
    const dhSig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, state.identityKeyPair.privateKey, dhRaw));
    state.dhSigB64 = bytesToBase64(dhSig);
  }

  async function connect() {
    state.peers = [];
    state.threads = { group: [] };
    state.unread = {};
    state.active = GROUP;
    state.self = null;
    rtcReset();
    closeSocket();
    setStatus("连接中", "warn");
    renderConversations();
    syncHeaderUI();
    renderMessages();

    const socket = new WebSocket(websocketURL(state.room));
    state.socket = socket;

    socket.addEventListener("open", () => {
      socket.send(JSON.stringify({ type: "hello", idKey: state.idKeyB64, dhKey: state.dhKeyB64, dhSig: state.dhSigB64 }));
    });
    socket.addEventListener("message", (event) => {
      void handleServerFrame(event.data);
    });
    socket.addEventListener("close", () => {
      if (state.socket === socket) {
        setStatus("已断开", "bad");
        addSystemMessage("连接已断开，聊天记录已保留，可点左下角重新连接。");
      }
    });
    socket.addEventListener("error", () => {
      if (state.socket === socket) {
        setStatus("连接错误", "bad");
      }
    });
  }

  async function reconnect() {
    if (state.reconnecting) {
      return;
    }
    state.reconnecting = true;
    try {
      await generateIdentity();
      await connect();
    } finally {
      state.reconnecting = false;
    }
  }

  function closeSocket() {
    if (!state.socket) {
      return;
    }
    const current = state.socket;
    state.socket = null;
    current.onopen = current.onmessage = current.onclose = current.onerror = null;
    if (current.readyState === WebSocket.OPEN || current.readyState === WebSocket.CONNECTING) {
      current.close(1000, "bye");
    }
  }

  async function handleServerFrame(rawData) {
    if (typeof rawData !== "string") {
      return;
    }
    let frame;
    try {
      frame = JSON.parse(rawData);
    } catch {
      return;
    }
    switch (frame.type) {
      case "welcome": await handleWelcome(frame); break;
      case "peer_joined": await addPeer(frame.peer, true); break;
      case "peer_left": handlePeerLeft(frame.id); break;
      case "ciphertext": await handleCiphertext(frame); break;
    }
  }

  async function handleWelcome(frame) {
    state.self = frame.self;
    renderSelfAvatar();
    state.peers = [];
    const peers = Array.isArray(frame.peers) ? frame.peers : [];
    for (const peer of peers) {
      await addPeer(peer, false);
    }
    setStatus("已连接", "ok");
    addSystemMessage("已进入群聊「" + state.room + "」，当前 " + memberCountText() + " 人在线。");
    if (state.nick && state.peers.length > 0) {
      void sendContent({ k: "p" }, { broadcast: true, silent: true });
    }
    renderConversations();
  }

  function handlePeerLeft(peerID) {
    state.peers = state.peers.filter((p) => p.id !== peerID);
    addSystemMessage("成员 " + shortID(peerID) + " 已离开。");
    if (rtc.peerId === peerID) {
      rtcReset();
    }
    if (state.active === peerID) {
      state.active = GROUP;
      syncHeaderUI();
      renderMessages();
    }
    renderConversations();
  }

  async function handleCiphertext(frame) {
    let envelope;
    try {
      envelope = JSON.parse(frame.payload);
    } catch {
      return;
    }
    await routeEnvelope(envelope);
  }

  // routeEnvelope 尝试用每个已知成员的密钥验证并解密一个信封；中转和 P2P 直连共用。
  async function routeEnvelope(envelope) {
    for (const peer of state.peers) {
      try {
        if (await tryOpenFromPeer(peer, envelope)) {
          return;
        }
      } catch {
        // 换下一个候选成员继续验证。
      }
    }
  }

  async function tryOpenFromPeer(peer, envelope) {
    if (!peer.idVerifyKey || !peer.dhPublicKey || envelope.v !== PROTOCOL_VERSION) {
      return false;
    }
    const selfID = state.self ? state.self.id : "";
    const sigOK = await crypto.subtle.verify(
      { name: "Ed25519" }, peer.idVerifyKey, base64ToBytes(envelope.sig), signedView(envelope, selfID));
    if (!sigOK) {
      return false;
    }
    const ctr = Number(envelope.ctr);
    const ts = Number(envelope.ts);
    if (!Number.isFinite(ctr) || !Number.isFinite(ts)) {
      return false;
    }
    if (ctr <= peer.lastCounter) {
      return true;
    }
    if (Math.abs(Date.now() - ts) > REPLAY_WINDOW_MS) {
      return true;
    }
    const json = await decryptFromPeer(peer, envelope);
    peer.lastCounter = ctr;
    let content;
    try {
      content = JSON.parse(json);
    } catch {
      return true;
    }
    if (content && typeof content.n === "string") {
      setPeerName(peer, content.n);
    }
    if (content && content.k === "p") {
      renderConversations();
      syncHeaderUI();
      return true;
    }
    if (content && content.k === "rtc") {
      if (envelope.scope !== "dm") {
        return true;
      }
      await handleRtcSignal(peer, content);
      return true;
    }
    const message = contentToMessage(content, peer.id, peerName(peer.id), false);
    if (message) {
      const convoKey = envelope.scope === "dm" ? peer.id : GROUP;
      addChatMessage(convoKey, message);
      maybeBeep();
    }
    return true;
  }

  async function decryptFromPeer(peer, envelope) {
    const aesKey = await deriveSharedKey(state.dhKeyPair.privateKey, peer.dhPublicKey, base64ToBytes(envelope.salt));
    const ivBytes = base64ToBytes(envelope.iv);
    const ciphertextBytes = base64ToBytes(envelope.ct);
    const paddedBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, aesKey, ciphertextBytes);
    const paddedBytes = new Uint8Array(paddedBuffer);
    try {
      return unpadPlaintext(paddedBytes);
    } finally {
      wipeBytes(paddedBytes);
    }
  }

  async function addPeer(peer, announce) {
    if (!peer || !peer.id || !peer.idKey || !peer.dhKey || !peer.dhSig) {
      return;
    }
    if (state.self && peer.id === state.self.id) {
      return;
    }
    if (state.peers.some((p) => p.id === peer.id)) {
      return;
    }
    try {
      const idRaw = base64ToBytes(peer.idKey);
      const dhRaw = base64ToBytes(peer.dhKey);
      const idVerifyKey = await crypto.subtle.importKey("raw", idRaw, { name: "Ed25519" }, true, ["verify"]);
      const dhSigOK = await crypto.subtle.verify({ name: "Ed25519" }, idVerifyKey, base64ToBytes(peer.dhSig), dhRaw);
      if (!dhSigOK) {
        addSystemMessage("成员 " + shortID(peer.id) + " 的会话公钥签名异常，已拒绝（疑似中间人）。");
        return;
      }
      const dhPublicKey = await crypto.subtle.importKey("raw", dhRaw, { name: "X25519" }, true, []);
      state.peers.push({ id: peer.id, idVerifyKey, dhPublicKey, lastCounter: 0, name: "" });
      if (!state.threads[peer.id]) {
        state.threads[peer.id] = [];
      }
      if (announce) {
        addSystemMessage("成员 " + shortID(peer.id) + " 加入了群聊。");
        if (state.nick) {
          void sendContent({ k: "p" }, { toPeerId: peer.id, scope: "group", silent: true });
        }
      }
      renderConversations();
    } catch (error) {
      addSystemMessage("无法导入成员密钥：" + safeError(error));
    }
  }

  // ---- 发送 ----

  async function sendText() {
    const text = (ui ? ui.draft : "").trim();
    if (!text || !canSend()) {
      return;
    }
    if (textEncoder.encode(text).length > MAX_TEXT_BYTES) {
      addSystemMessage("消息过长，未发送。");
      return;
    }
    const ok = await sendContent({ k: "t", t: text });
    if (ok) {
      if (ui) {
        ui.draft = "";
      }
    }
  }

  async function handleFile(file) {
    if (!canSend()) {
      return;
    }
    const isImage = !!file.type && file.type.startsWith("image/");
    if (file.size <= MAX_RELAY_BYTES) {
      try {
        const buffer = await file.arrayBuffer();
        const base64 = bytesToBase64(new Uint8Array(buffer));
        if (isImage) {
          await sendContent({ k: "i", m: file.type, d: base64 });
        } else {
          await sendContent({ k: "f", m: file.type || "application/octet-stream", fn: file.name || "file", sz: file.size, d: base64 });
        }
      } catch (error) {
        addSystemMessage("文件发送失败：" + safeError(error));
      }
      return;
    }
    // 大文件：群聊无法直连，提示改用私聊 P2P；私聊则走 WebRTC 数据通道。
    if (state.active === GROUP) {
      showToast("大文件请进入私聊，使用 P2P 直连发送");
      return;
    }
    await sendFileP2P(file);
  }

  // sendContent 把一段内容（文本/图片/文件/资料/信令）加密分发给目标成员。
  // opts.toPeerId 指定单一收件人；opts.broadcast 发给所有成员；否则按当前会话推断。
  // opts.silent 时不在本地回显（用于资料广播、WebRTC 信令等控制消息）。
  // 私聊且 P2P 数据通道就绪时，普通消息改走直连通道，不再经服务器中转。
  async function sendContent(content, opts) {
    opts = opts || {};
    let targets;
    let scope;
    if (opts.toPeerId) {
      targets = state.peers.filter((p) => p.id === opts.toPeerId);
      scope = opts.scope || "dm";
    } else if (opts.broadcast) {
      targets = state.peers;
      scope = GROUP;
    } else if (state.active === GROUP) {
      targets = state.peers;
      scope = GROUP;
    } else {
      targets = state.peers.filter((p) => p.id === state.active);
      scope = "dm";
    }
    if (targets.length === 0) {
      if (!opts.silent) {
        addSystemMessage(scope === GROUP ? "群里暂时没有其他人，消息未发送。" : "对方已离线，消息未发送。");
      }
      return false;
    }

    if (state.nick && content.k !== "rtc" && content.k !== "p") {
      content = Object.assign({}, content, { n: state.nick });
    } else if (content.k === "p") {
      content = { k: "p", n: state.nick };
    }

    const ctr = ++state.sendCounter;
    const ts = Date.now();
    const bytes = textEncoder.encode(JSON.stringify(content));
    const padded = padPlaintext(bytes);
    try {
      for (const peer of targets) {
        const envelope = await sealForPeer(peer, padded, ctr, ts, scope);
        if (scope === "dm" && content.k !== "rtc" && rtcConnected(peer.id)) {
          rtc.channel.send(JSON.stringify({ t: "msg", e: envelope }));
        } else {
          state.socket.send(JSON.stringify({ type: "send", messages: [{ dest: peer.id, payload: envelope }] }));
        }
      }
    } finally {
      wipeBytes(bytes);
      wipeBytes(padded);
    }

    if (!opts.silent) {
      const selfID = state.self ? state.self.id : "self";
      const own = contentToMessage(content, selfID, selfName(), true);
      if (own) {
        addChatMessage(opts.toPeerId || state.active, own);
      }
    }
    return true;
  }

  async function sealForPeer(peer, paddedBytes, ctr, ts, scope) {
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const ivBytes = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await deriveSharedKey(state.dhKeyPair.privateKey, peer.dhPublicKey, saltBytes);
    const ciphertextBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivBytes }, aesKey, paddedBytes);
    const envelope = {
      v: PROTOCOL_VERSION,
      alg: PROTOCOL,
      scope: scope,
      ctr: ctr,
      ts: ts,
      salt: bytesToBase64(saltBytes),
      iv: bytesToBase64(ivBytes),
      ct: bytesToBase64(new Uint8Array(ciphertextBuffer)),
    };
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, state.identityKeyPair.privateKey, signedView(envelope, peer.id)));
    envelope.sig = bytesToBase64(sig);
    return JSON.stringify(envelope);
  }

  // contentToMessage 把解密出的内容对象转成可渲染的消息对象，并做基本校验。
  function contentToMessage(content, from, author, fromSelf) {
    if (!content || typeof content !== "object") {
      return null;
    }
    const base = { id: 0, system: false, fromSelf, from, author, time: formatTime(new Date()) };
    if (content.k === "t" && typeof content.t === "string") {
      return Object.assign(base, { kind: "text", text: content.t });
    }
    if (content.k === "i" && typeof content.m === "string" && /^image\//.test(content.m) && typeof content.d === "string") {
      return Object.assign(base, { kind: "image", mime: content.m, data: content.d });
    }
    if (content.k === "f" && typeof content.m === "string" && typeof content.fn === "string" && typeof content.d === "string") {
      return Object.assign(base, { kind: "file", mime: content.m, name: content.fn, size: Number(content.sz) || 0, data: content.d });
    }
    return null;
  }

  // ---- 会话与状态 ----

  function selectConversation(key) {
    state.active = key;
    state.unread[key] = 0;
    if (key === GROUP) {
      scheduleRtcIdleClose();
    } else if (rtc.peerId && rtc.peerId !== key) {
      rtcReset();
    } else {
      cancelRtcIdleClose();
    }
    renderConversations();
    syncHeaderUI();
    renderMessages();
    maybeAutoUpgrade(key);
  }

  // maybeAutoUpgrade 进入私聊时自动尝试把会话升级为 P2P 直连：
  // ID 较大的一方主动发起，较小的一方发请求让对方发起（避免双方同时 offer）。
  function maybeAutoUpgrade(key) {
    if (key === GROUP || !canSend()) {
      return;
    }
    if (rtcClosedFor(key)) {
      rtcReset();
    }
    if ((rtc.state === P2P_STATE.CONNECTED || rtc.connecting || rtc.pc) && rtc.peerId === key) {
      return;
    }
    const peer = state.peers.find((p) => p.id === key);
    if (!peer) {
      return;
    }
    const selfID = state.self ? state.self.id : "";
    if (selfID > key) {
      void startP2P(key);
    } else {
      void requestP2P(key);
    }
  }

  function conversationTitle() {
    return state.active === GROUP ? "群聊「" + state.room + "」" : peerName(state.active) + " · 私聊";
  }

  // peerName 返回成员的显示名：优先对方设置的昵称，否则回退匿名短 ID。
  function peerName(id) {
    if (id === GROUP) {
      return "群聊";
    }
    const peer = state.peers.find((p) => p.id === id);
    return (peer && peer.name) ? peer.name : shortID(id);
  }

  function selfName() {
    return state.nick || "我";
  }

  function setPeerName(peer, raw) {
    const name = String(raw || "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, MAX_NICK_LEN);
    if (peer.name !== name) {
      peer.name = name;
      renderConversations();
      syncHeaderUI();
    }
  }

  function filteredPeers() {
    const q = state.search.trim().toLowerCase();
    if (!q) {
      return state.peers;
    }
    return state.peers.filter((p) => peerName(p.id).toLowerCase().includes(q) || shortID(p.id).toLowerCase().includes(q));
  }

  function threadPreview(key) {
    const list = state.threads[key] || [];
    for (let i = list.length - 1; i >= 0; i -= 1) {
      const m = list[i];
      if (!m.system) {
        const body = m.kind === "image" ? "[图片]" : m.kind === "file" ? "[文件] " + (m.name || "") : m.text;
        return (m.fromSelf ? "我: " : "") + body;
      }
    }
    return "暂无消息";
  }

  function addChatMessage(convoKey, message) {
    if (!state.threads[convoKey]) {
      state.threads[convoKey] = [];
    }
    message.id = state.nextMessageID++;
    state.threads[convoKey].push(message);
    trimThread(convoKey);
    if (convoKey === state.active) {
      renderMessages();
    } else if (!message.fromSelf) {
      state.unread[convoKey] = (state.unread[convoKey] || 0) + 1;
    }
    renderConversations();
    return message;
  }

  function addSystemMessage(text, convoKey) {
    const key = convoKey || GROUP;
    if (!state.threads[key]) {
      state.threads[key] = [];
    }
    state.threads[key].push({
      id: state.nextMessageID++, system: true, fromSelf: false,
      from: "system", author: "系统", kind: "text", text: text, time: formatTime(new Date()),
    });
    trimThread(key);
    if (state.active === key) {
      renderMessages();
    }
    renderConversations();
  }

  function trimThread(key) {
    const list = state.threads[key];
    if (list && list.length > MAX_MESSAGES_PER_THREAD) {
      list.splice(0, list.length - MAX_MESSAGES_PER_THREAD);
    }
  }

  function canSend() {
    return state.socket && state.socket.readyState === WebSocket.OPEN && state.statusTone === "ok";
  }

  function memberCountText() {
    return String(state.peers.length + (state.self ? 1 : 0));
  }

  function syncUI() {
    syncSettingsUI();
    renderSelfAvatar();
    renderConversations();
    syncHeaderUI();
    renderMessages();
  }

  function syncSettingsUI() {
    if (!ui) {
      return;
    }
    ui.nick = state.nick;
    ui.soundOn = !state.muted;
    ui.tone = state.tone;
    ui.stun = state.stun;
    ui.theme = document.documentElement.dataset.theme || "pptter";
    ui.isDark = isDarkTheme(ui.theme);
    ui.backgroundImage = state.backgroundImage;
  }

  function syncHeaderUI() {
    if (!ui) {
      return;
    }
    const inDM = state.active !== GROUP;
    const connected = inDM && rtcConnected(state.active);
    const connecting = inDM && rtc.connecting && rtc.peerId === state.active;
    ui.active = state.active;
    ui.convoTitle = conversationTitle();
    ui.statusText = statusDisplayText();
    ui.statusDotClass = connecting ? "bg-warning" : state.statusTone === "ok" ? "bg-success" : state.statusTone === "bad" ? "bg-error" : "bg-warning";
    ui.sendDisabled = !canSend();
    ui.inputPlaceholder = state.active === GROUP ? "群聊消息，本地加密后发送" : "私聊消息，仅对方可解密";
    ui.p2pHidden = !inDM;
    ui.p2pConnected = connected;
    ui.p2pTitle = connected ? "P2P 直连已建立，点击发送大文件" : connecting ? "P2P 打洞中…" : "建立 P2P 直连（大文件）";
    ui.shareHidden = !inDM;
    ui.screenSharing = !!rtc.localShare;
    ui.shareTitle = rtc.localShare ? "停止共享屏幕" : "共享屏幕（仅对方可见）";
    ui.inCall = !!rtc.localVoice;
    ui.micMuted = rtc.micMuted;
    ui.callTitle = rtc.localVoice ? "退出语音通话" : "发起语音通话";
    ui.micTitle = rtc.micMuted ? "取消静音" : "静音";
  }

  function statusDisplayText() {
    if (state.statusTone !== "ok") {
      return state.statusText;
    }
    if (state.active === GROUP) {
      return "群聊 · 端到端加密 (X25519·Ed25519)";
    }
    if (rtcConnected(state.active)) {
      return "P2P 直连 · 端到端加密";
    }
    if (rtc.connecting && rtc.peerId === state.active) {
      return (rtc.loadingLabel || "P2P 打洞中") + " " + (rtc.loadingFrame || "/");
    }
    if (rtc.state === P2P_STATE.FAILED && rtc.peerId === state.active) {
      return "P2P 直连失败 · 私聊端到端加密";
    }
    if (rtc.state === P2P_STATE.CLOSED && rtc.peerId === state.active) {
      return "P2P 已断开 · 私聊端到端加密";
    }
    return "私聊 · 端到端加密 (X25519·Ed25519)";
  }

  function conversationViews() {
    const list = [{
      key: GROUP,
      isGroup: true,
      title: "群聊 (" + memberCountText() + ")",
      preview: threadPreview(GROUP),
      unread: state.unread[GROUP] || 0,
    }];

    for (const peer of filteredPeers()) {
      const avatar = avatarModel(peer.id, shortID(peer.id).slice(0, 2));
      list.push({
        key: peer.id,
        isGroup: false,
        title: peerName(peer.id),
        preview: threadPreview(peer.id),
        unread: state.unread[peer.id] || 0,
        text: avatar.text,
        avatarClass: avatar.avatarClass,
      });
    }

    return list;
  }

  function messageView(message) {
    if (message.system) {
      return { id: message.id, system: true, text: message.text };
    }

    const avatar = avatarModel(message.from, shortID(message.from).slice(0, 2));
    const isImage = message.kind === "image";
    const isFile = message.kind === "file";
    const transfer = message.transfer || null;
    const href = isFile ? (message.url || ("data:" + message.mime + ";base64," + message.data)) : "";
    const src = isImage ? (message.url || ("data:" + message.mime + ";base64," + message.data)) : "";
    const canDownload = isFile && !!href && (!transfer || transfer.status === TRANSFER_STATUS.DONE);
    return {
      id: message.id,
      system: false,
      chatClass: "chat " + (message.fromSelf ? "chat-end" : "chat-start"),
      avatarClass: avatar.avatarClass,
      avatarText: avatar.text,
      author: message.author,
      timeText: message.time,
      bubbleClass: "chat-bubble" + (message.fromSelf ? " chat-bubble-accent" : "") + (isImage || isFile ? " is-media" : ""),
      isText: message.kind === "text",
      isImage: isImage,
      isFile: isFile,
      isTransfer: !!transfer,
      text: message.text || "",
      src: src,
      href: href,
      name: message.name || "文件",
      meta: isFile ? fileMeta(message) : "",
      downloadTitle: isFile ? "下载 " + (message.name || "") : "",
      canDownload: canDownload,
      progress: transfer ? transfer.percent : 0,
      progressText: transfer ? transfer.label : "",
      canCancel: !!(transfer && transfer.canCancel),
      canRetry: !!(transfer && transfer.canRetry),
    };
  }

  function fileMeta(message) {
    const base = humanSize(message.size) + (message.p2p ? " · P2P 直传" : "");
    if (message.transfer && message.transfer.label) {
      return base + " · " + message.transfer.label;
    }
    return base + " · 点击下载";
  }

  function avatarModel(id, fallbackText) {
    const avatarNumber = avatarIndex(id || "");
    return {
      text: "",
      avatarClass: "avatar-sprite avatar-pos-" + avatarNumber,
      fallbackText: fallbackText,
    };
  }

  // ---- 渲染 ----

  function setStatus(text, tone) {
    state.statusText = text;
    state.statusTone = tone;
    syncHeaderUI();
  }

  function renderConversations() {
    if (ui) {
      ui.conversations = conversationViews();
      ui.hasPeers = state.peers.length > 0;
      ui.active = state.active;
    }
  }

  function renderMessages() {
    const list = state.threads[state.active] || [];
    if (ui) {
      ui.messages = list.map(messageView);
    }
  }

  function showToast(text) {
    if (ui) {
      ui.toastText = text;
      ui.toastShown = true;
      window.clearTimeout(toastTimer);
      toastTimer = window.setTimeout(() => { if (ui) ui.toastShown = false; }, 1800);
    }
  }

  // ---- 设置 / 深色模式 / 灯箱 / 提示音 ----

  function lsGet(key) {
    try {
      return localStorage.getItem("pptter." + key);
    } catch {
      return null;
    }
  }

  function saveSetting(key, value) {
    try {
      localStorage.setItem("pptter." + key, value);
    } catch {
      // localStorage 不可用（隐私模式等）时忽略。
    }
  }

  function removeSetting(key) {
    try {
      localStorage.removeItem("pptter." + key);
    } catch {
      // localStorage 不可用（隐私模式等）时忽略。
    }
  }

  function initSettings() {
    const stored = lsGet("theme");
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(THEMES.includes(stored) ? stored : (prefersDark ? "pptter-dark" : "pptter"));

    state.muted = lsGet("muted") === "1";

    state.nick = (lsGet("nick") || "").slice(0, MAX_NICK_LEN);

    const tone = lsGet("tone");
    state.tone = (tone && TONES[tone]) ? tone : "soft";

    const storedStun = lsGet("stun");
    state.stun = normalizeStunSetting(storedStun || "");
    if (storedStun && !state.stun) {
      removeSetting("stun");
    }
    syncSettingsUI();

    const bg = lsGet("bg");
    if (bg) {
      applyBackground(bg, true);
    }
  }

  function normalizeStunSetting(raw) {
    const value = String(raw || "").trim();
    if (!value) {
      return "";
    }
    const withScheme = value.match(/^(stun|stuns):(.+)$/i);
    if (withScheme && validStunHostPort(withScheme[2])) {
      return value;
    }
    if (validStunHostPort(value)) {
      return "stun:" + value;
    }
    return "";
  }

  function validStunHostPort(value) {
    const match = String(value || "").match(/^(\[[^\]]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})$/);
    if (!match) {
      return false;
    }
    const port = Number(match[2]);
    return Number.isInteger(port) && port > 0 && port <= 65535;
  }

  // setNick 更新本地昵称并向所有在线成员广播一次加密的资料帧。
  function setNick(raw) {
    const name = String(raw || "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, MAX_NICK_LEN);
    state.nick = name;
    saveSetting("nick", name);
    if (ui) {
      ui.nick = name;
    }
    renderSelfAvatar();
    renderConversations();
    if (canSend() && state.peers.length > 0) {
      void sendContent({ k: "p" }, { broadcast: true, silent: true });
    }
    showToast(name ? "昵称已更新" : "已清除昵称");
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    saveSetting("theme", theme);
    if (ui) {
      ui.theme = theme;
      ui.isDark = isDarkTheme(theme);
    }
  }

  // toggleTheme：用 View Transitions API 从按钮位置以圆形遮罩扩散到整页。
  function toggleTheme(event) {
    const currentTheme = document.documentElement.dataset.theme || "pptter";
    const current = isDarkTheme(currentTheme) ? "pptter-dark" : "pptter";
    const next = current === "pptter-dark" ? "pptter" : "pptter-dark";
    const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!document.startViewTransition || reduced) {
      applyTheme(next);
      return;
    }
    const x = event && Number.isFinite(event.clientX) ? event.clientX : Math.round(innerWidth / 2);
    const y = event && Number.isFinite(event.clientY) ? event.clientY : Math.round(innerHeight / 2);
    const endRadius = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
    const transition = document.startViewTransition(() => applyTheme(next));
    transition.ready.then(() => {
      document.documentElement.animate(
        { clipPath: ["circle(0px at " + x + "px " + y + "px)", "circle(" + endRadius + "px at " + x + "px " + y + "px)"] },
        { duration: 450, easing: "ease-in-out", pseudoElement: "::view-transition-new(root)" });
    });
  }

  // fingerprint 返回本机身份公钥的短指纹，供成员带外核对、防中间人。
  async function fingerprint() {
    if (!state.idKeyB64 || !window.crypto || !window.crypto.subtle) {
      return "—";
    }
    try {
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", base64ToBytes(state.idKeyB64)));
      const hex = Array.from(digest.slice(0, 16)).map((b) => b.toString(16).padStart(2, "0")).join("");
      return hex.replace(/(.{4})/g, "$1 ").trim();
    } catch {
      return "—";
    }
  }

  // ---- WebRTC P2P：仅当前私聊，用于大文件直传与消息直连，信令走既有端到端加密通道。 ----

  function rtcConfig() {
    const servers = [];
    if (Array.isArray(state.iceServers)) {
      servers.push(...state.iceServers);
    }
    if (state.stun) {
      servers.push({ urls: state.stun });
    }
    return { iceServers: servers };
  }

  // loadRtcConfig 向后端拉取自建 STUN 服务信息，构造 ICE 配置。
  // 后端返回 {enabled, stunPort, stunHost?}；STUN 地址默认用当前主机名 + 该端口，
  // 因此跨网络也能尝试反射地址，而不引入任何第三方服务。
  async function loadRtcConfig() {
    try {
      const res = await fetch("/webrtc-config", { cache: "no-store" });
      if (!res.ok) {
        state.iceServers = [];
        return;
      }
      const cfg = await res.json();
      if (cfg && cfg.enabled && cfg.stunPort) {
        const host = (cfg.stunHost && String(cfg.stunHost)) || location.hostname;
        const url = stunURL(host, cfg.stunPort);
        state.iceServers = url ? [{ urls: url }] : [];
      } else {
        state.iceServers = [];
      }
    } catch {
      state.iceServers = [];
    }
  }

  function setRtcState(nextState, peerId, label) {
    cancelRtcIdleClose();
    cancelHandshakeTimeout();
    if (peerId) {
      rtc.peerId = peerId;
    }
    rtc.state = nextState;
    rtc.ready = nextState === P2P_STATE.CONNECTED;
    rtc.connecting = nextState === P2P_STATE.REQUESTING || nextState === P2P_STATE.OFFERING || nextState === P2P_STATE.ANSWERING;
    if (rtc.connecting) {
      startP2PLoading(rtc.peerId, label || p2pStateLabel(nextState));
      scheduleHandshakeTimeout(rtc.peerId);
    } else {
      stopP2PLoading(false);
    }
    if (state.active === GROUP && (nextState === P2P_STATE.CONNECTED || rtc.connecting)) {
      scheduleRtcIdleClose();
    }
    syncHeaderUI();
  }

  function p2pStateLabel(nextState) {
    if (nextState === P2P_STATE.REQUESTING) {
      return "等待对方发起 P2P";
    }
    if (nextState === P2P_STATE.ANSWERING) {
      return "正在响应 P2P";
    }
    return "P2P 打洞中";
  }

  function startP2PLoading(peerId, label) {
    if (!peerId || peerId === GROUP) {
      return;
    }
    rtc.peerId = peerId;
    rtc.connecting = true;
    rtc.loadingLabel = label || rtc.loadingLabel || "P2P 打洞中";
    rtc.loadingIndex = 0;
    rtc.loadingFrame = P2P_LOADING_FRAMES[0];
    if (!rtc.loadingTimer) {
      rtc.loadingTimer = window.setInterval(() => {
        if (!rtc.connecting) {
          stopP2PLoading();
          return;
        }
        rtc.loadingIndex = (rtc.loadingIndex + 1) % P2P_LOADING_FRAMES.length;
        rtc.loadingFrame = P2P_LOADING_FRAMES[rtc.loadingIndex];
        syncHeaderUI();
      }, 180);
    }
    syncHeaderUI();
  }

  function stopP2PLoading(sync) {
    if (rtc.loadingTimer) {
      window.clearInterval(rtc.loadingTimer);
      rtc.loadingTimer = 0;
    }
    rtc.connecting = false;
    rtc.loadingLabel = "";
    rtc.loadingIndex = 0;
    rtc.loadingFrame = P2P_LOADING_FRAMES[0];
    if (sync !== false) {
      syncHeaderUI();
    }
  }

  function rtcConnected(peerId) {
    return rtc.state === P2P_STATE.CONNECTED && rtc.ready && rtc.peerId === peerId && rtc.channel && rtc.channel.readyState === "open";
  }

  function rtcClosedFor(peerId) {
    return rtc.peerId === peerId && (
      rtc.state === P2P_STATE.FAILED ||
      rtc.state === P2P_STATE.CLOSED ||
      (rtc.pc && rtc.pc.connectionState === "closed")
    );
  }

  function cancelRtcIdleClose() {
    if (rtc.idleTimer) {
      window.clearTimeout(rtc.idleTimer);
      rtc.idleTimer = 0;
    }
  }

  function cancelHandshakeTimeout() {
    if (rtc.handshakeTimer) {
      window.clearTimeout(rtc.handshakeTimer);
      rtc.handshakeTimer = 0;
    }
  }

  function scheduleHandshakeTimeout(peerId) {
    cancelHandshakeTimeout();
    if (!peerId || peerId === GROUP) {
      return;
    }
    rtc.handshakeTimer = window.setTimeout(() => {
      rtc.handshakeTimer = 0;
      if (rtc.peerId !== peerId || !rtc.connecting) {
        return;
      }
      addSystemMessage("P2P 未建立：请确认对方也已打开本会话；对方打开后会自动重连。", peerId);
      rtcReset();
    }, P2P_HANDSHAKE_TIMEOUT_MS);
  }

  function scheduleRtcIdleClose() {
    cancelRtcIdleClose();
    if (!rtc.peerId || rtc.state === P2P_STATE.IDLE || rtc.state === P2P_STATE.CLOSED || rtc.state === P2P_STATE.FAILED) {
      return;
    }
    rtc.idleTimer = window.setTimeout(() => {
      if (state.active === GROUP && rtc.peerId) {
        addSystemMessage("P2P 直连已空闲回收。", rtc.peerId);
        rtcReset();
      }
    }, P2P_IDLE_KEEPALIVE_MS);
  }

  function closeRtcObjects() {
    failActiveTransfers("连接断开");
    if (rtc.localShare) {
      rtc.localShare.getTracks().forEach((track) => { try { track.stop(); } catch { /* 忽略 */ } });
    }
    rtc.localShare = null;
    rtc.shareSenders = null;
    hideRemoteShare();
    if (rtc.localVoice) {
      rtc.localVoice.getTracks().forEach((track) => { try { track.stop(); } catch { /* 忽略 */ } });
    }
    rtc.localVoice = null;
    rtc.voiceSenders = null;
    rtc.micMuted = false;
    detachRemoteVoice();
    if (ui) {
      ui.screenSharing = false;
      ui.inCall = false;
      ui.micMuted = false;
    }
    if (rtc.channel) {
      try { rtc.channel.close(); } catch { /* 忽略 */ }
    }
    if (rtc.pc) {
      try { rtc.pc.close(); } catch { /* 忽略 */ }
    }
    rtc.pc = null;
    rtc.channel = null;
    rtc.ready = false;
    rtc.recv = null;
    rtc.sending = null;
    rtc.makingOffer = false;
  }

  function failActiveTransfers(reason) {
    if (rtc.sending && rtc.sending.message) {
      updateTransfer(rtc.sending.message, { status: TRANSFER_STATUS.FAILED, error: reason || "连接断开" });
    }
    if (rtc.recv && rtc.recv.message) {
      updateTransfer(rtc.recv.message, { status: TRANSFER_STATUS.FAILED, error: reason || "连接断开" });
    }
  }

  function rtcReset() {
    cancelRtcIdleClose();
    cancelHandshakeTimeout();
    stopP2PLoading(false);
    closeRtcObjects();
    rtc.peerId = null;
    rtc.state = P2P_STATE.IDLE;
    rtc.connecting = false;
    for (const item of rtc.queue) {
      if (item.message) {
        updateTransfer(item.message, { status: TRANSFER_STATUS.FAILED, error: "连接已切换" });
      }
    }
    rtc.queue = [];
    updateP2pButton();
    syncHeaderUI();
  }

  async function announceP2PConnected(peerId, channel) {
    const details = await safeP2PConnectionDetails(peerId, channel);
    logP2PEvent("connected", details);
  }

  async function safeP2PConnectionDetails(peerId, channel) {
    const pc = rtc.pc && rtc.peerId === peerId ? rtc.pc : null;
    const details = {
      peer: shortID(peerId),
      dataChannelState: channel ? channel.readyState : "unknown",
      connectionState: pc ? pc.connectionState : "unknown",
      iceConnectionState: pc ? pc.iceConnectionState : "unknown",
      iceGatheringState: pc ? pc.iceGatheringState : "unknown",
      signalingState: pc ? pc.signalingState : "unknown",
    };
    if (!pc || typeof pc.getStats !== "function") {
      return details;
    }
    try {
      const report = await pc.getStats();
      let selectedPair = null;
      report.forEach((stat) => {
        if (stat.type === "candidate-pair" && stat.state === "succeeded" && (stat.selected || stat.nominated)) {
          selectedPair = stat;
        }
      });
      if (!selectedPair) {
        return details;
      }
      const local = selectedPair.localCandidateId ? report.get(selectedPair.localCandidateId) : null;
      const remote = selectedPair.remoteCandidateId ? report.get(selectedPair.remoteCandidateId) : null;
      if (local && local.candidateType) {
        details.localCandidateType = local.candidateType;
      }
      if (remote && remote.candidateType) {
        details.remoteCandidateType = remote.candidateType;
      }
      if (local && local.protocol) {
        details.protocol = local.protocol;
      }
      if (Number.isFinite(selectedPair.currentRoundTripTime)) {
        details.rttMs = Math.round(selectedPair.currentRoundTripTime * 1000);
      }
    } catch {
      // 统计信息不可用时仍保留连接状态日志。
    }
    return details;
  }

  function logP2PEvent(event, details) {
    if (window.console && typeof window.console.info === "function") {
      window.console.info("[pptter:p2p]", Object.assign({ event: event }, details));
    }
  }

  function ensurePeerConnection(peerId, initiator) {
    if (rtc.pc && rtc.peerId !== peerId) {
      rtcReset();
    }
    if (rtc.pc) {
      return rtc.pc;
    }
    rtc.peerId = peerId;
    // 完美协商（perfect negotiation）的礼貌方判定：ID 较小者为礼貌方，
    // 较大者为发起/不礼貌方（与既有「ID 大者发起」一致），用于消解重协商时的 offer 碰撞。
    const selfID = state.self ? state.self.id : "";
    rtc.polite = selfID < peerId;
    rtc.makingOffer = false;
    const pc = new RTCPeerConnection(rtcConfig());
    rtc.pc = pc;
    pc.onicecandidate = (event) => {
      if (event.candidate) {
        void sendContent({ k: "rtc", s: "ice", c: JSON.stringify(event.candidate) }, { toPeerId: peerId, silent: true });
      }
    };
    pc.oniceconnectionstatechange = () => {
      logP2PEvent("ice", { peer: shortID(peerId), iceConnectionState: pc.iceConnectionState });
    };
    pc.onconnectionstatechange = () => {
      const s = pc.connectionState;
      logP2PEvent("pcstate", { peer: shortID(peerId), connectionState: s, iceConnectionState: pc.iceConnectionState });
      // 只把 failed/closed 当作致命；disconnected 多为重协商或瞬时丢包导致，通常会自行恢复，
      // 若此时贸然 close 会把正常连接（含已建立的屏幕共享/语音）一并打断。
      if ((s === "failed" || s === "closed") && rtc.peerId === peerId) {
        const nextState = s === "failed" ? P2P_STATE.FAILED : P2P_STATE.CLOSED;
        setRtcState(nextState, peerId);
        addSystemMessage("P2P 直连已断开。", peerId);
        logP2PEvent("closed", {
          peer: shortID(peerId),
          connectionState: pc.connectionState,
          iceConnectionState: pc.iceConnectionState,
        });
        closeRtcObjects();
      }
      updateP2pButton();
    };
    pc.ondatachannel = (event) => setupChannel(event.channel, peerId);
    // 接收对方媒体：视频轨=屏幕共享面板；音频轨=语音通话播放。媒体均走 DTLS-SRTP。
    pc.ontrack = (event) => {
      if (rtc.peerId !== peerId) {
        return;
      }
      const track = event.track;
      const stream = (event.streams && event.streams[0]) ? event.streams[0] : new MediaStream([track]);
      if (track.kind === "video") {
        showRemoteShare(peerId, stream);
        track.addEventListener("ended", () => {
          if (rtc.peerId === peerId) {
            hideRemoteShare();
          }
        });
        if (event.streams && event.streams[0]) {
          event.streams[0].addEventListener("removetrack", () => {
            if (rtc.peerId === peerId && event.streams[0].getVideoTracks().length === 0) {
              hideRemoteShare();
            }
          });
        }
      } else if (track.kind === "audio") {
        attachRemoteVoice(peerId, stream);
        // 对方移除麦克风轨时，接收端按规范触发 mute（而非 ended），两者都收下以可靠收起浮条。
        const drop = () => {
          if (rtc.peerId === peerId) {
            detachRemoteVoice();
          }
        };
        track.addEventListener("ended", drop);
        track.addEventListener("mute", drop);
        track.addEventListener("unmute", () => {
          if (rtc.peerId === peerId) {
            attachRemoteVoice(peerId, stream);
          }
        });
      }
    };
    if (initiator) {
      setupChannel(pc.createDataChannel("p2p", { ordered: true }), peerId);
    }
    return pc;
  }

  function setupChannel(channel, peerId) {
    rtc.channel = channel;
    channel.binaryType = "arraybuffer";
    channel.bufferedAmountLowThreshold = 1 << 20;
    channel.onopen = () => {
      if (rtc.peerId !== peerId) {
        return;
      }
      setRtcState(P2P_STATE.CONNECTED, peerId);
      void announceP2PConnected(peerId, channel);
      updateP2pButton();
      syncHeaderUI();
      flushQueue();
    };
    channel.onclose = () => {
      if (rtc.peerId !== peerId) {
        return;
      }
      setRtcState(P2P_STATE.CLOSED, peerId);
      updateP2pButton();
      syncHeaderUI();
    };
    channel.onmessage = (event) => {
      if (rtc.peerId === peerId) {
        handleChannelData(event.data);
      }
    };
  }

  async function startP2P(peerId) {
    if (!peerId || peerId === GROUP) {
      return;
    }
    if (rtcConnected(peerId) || (rtc.pc && rtc.peerId === peerId && rtc.state !== P2P_STATE.FAILED && rtc.state !== P2P_STATE.CLOSED)) {
      return;
    }
    if (rtc.pc && rtc.peerId !== peerId) {
      rtcReset();
    }
    if (rtc.pc && rtc.peerId === peerId) {
      rtcReset();
    }
    ensureAudio();
    try {
      setRtcState(P2P_STATE.OFFERING, peerId, "P2P 打洞中");
      const pc = ensurePeerConnection(peerId, true);
      rtc.makingOffer = true;
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await sendContent({ k: "rtc", s: "offer", sdp: pc.localDescription.sdp }, { toPeerId: peerId, silent: true });
    } catch (error) {
      setRtcState(P2P_STATE.FAILED, peerId);
      addSystemMessage("发起 P2P 失败：" + safeError(error), peerId);
      closeRtcObjects();
    } finally {
      rtc.makingOffer = false;
    }
  }

  async function requestP2P(peerId) {
    if (!peerId || peerId === GROUP || rtcConnected(peerId)) {
      return;
    }
    if (rtcClosedFor(peerId)) {
      rtcReset();
    }
    const selfID = state.self ? state.self.id : "";
    if (selfID > peerId) {
      await startP2P(peerId);
      return;
    }
    if ((rtc.connecting || rtc.pc) && rtc.peerId === peerId) {
      return;
    }
    setRtcState(P2P_STATE.REQUESTING, peerId, "等待对方发起 P2P");
    await sendContent({ k: "rtc", s: "req" }, { toPeerId: peerId, silent: true });
  }

  async function handleRtcSignal(peer, content) {
    const peerId = peer.id;
    // 双向意图：仅在「正在查看该会话」或「已与该 peer 建立/协商中的连接」时处理信令。
    // P2P 需双方都进入该私聊才建立，避免被动暴露 ICE 反射地址给未交谈的成员。
    // 代价：对端刷新后需有一方重新打开会话才能重连——这是有意的安全取舍。
    if (state.active !== peerId && rtc.peerId !== peerId) {
      return;
    }
    try {
      if (content.s === "req") {
        // 对方请求建立直连：由 ID 较大的一方发起，避免双方同时发 offer 造成 glare。
        const selfID = state.self ? state.self.id : "";
        if (selfID > peerId) {
          if (rtc.peerId && rtc.peerId !== peerId) {
            rtcReset();
          } else if (rtcClosedFor(peerId)) {
            rtcReset();
          }
          if (!rtcConnected(peerId) && !(rtc.pc && rtc.peerId === peerId)) {
            await startP2P(peerId);
          }
        }
        return;
      }
      if (content.s === "ice") {
        if (rtc.pc && rtc.peerId === peerId && content.c) {
          try { await rtc.pc.addIceCandidate(JSON.parse(content.c)); } catch { /* 候选迟到或回滚期忽略 */ }
        }
        return;
      }
      if (content.s === "offer") {
        if (rtc.peerId && rtc.peerId !== peerId) {
          rtcReset();
        } else if (rtcClosedFor(peerId)) {
          rtcReset();
        }
        const fresh = !rtc.pc || rtc.peerId !== peerId;
        if (rtc.pc && rtc.peerId !== peerId) {
          rtcReset();
        }
        if (fresh) {
          setRtcState(P2P_STATE.ANSWERING, peerId, "正在响应 P2P");
        }
        const pc = ensurePeerConnection(peerId, false);
        // 完美协商：检测 offer 碰撞（我方正发 offer，或信令状态非 stable）。
        const collision = rtc.makingOffer || pc.signalingState !== "stable";
        logP2PEvent("offer-recv", { peer: shortID(peerId), polite: rtc.polite, collision: collision, signalingState: pc.signalingState });
        if (collision && !rtc.polite) {
          return; // 不礼貌方忽略碰撞 offer；礼貌方继续（setRemoteDescription 隐式回滚）。
        }
        await pc.setRemoteDescription({ type: "offer", sdp: content.sdp });
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        await sendContent({ k: "rtc", s: "answer", sdp: pc.localDescription.sdp }, { toPeerId: peerId, silent: true });
        return;
      }
      if (content.s === "answer") {
        logP2PEvent("answer-recv", { peer: shortID(peerId), signalingState: rtc.pc ? rtc.pc.signalingState : "no-pc" });
        if (rtc.pc && rtc.peerId === peerId && rtc.pc.signalingState === "have-local-offer") {
          await rtc.pc.setRemoteDescription({ type: "answer", sdp: content.sdp });
        }
        return;
      }
    } catch (error) {
      addSystemMessage("P2P 协商失败：" + safeError(error), peerId);
    }
  }

  // renegotiate 在已建立的连接上增删媒体轨（如屏幕共享）后重新发起协商。
  async function renegotiate(peerId) {
    const pc = rtc.pc;
    if (!pc || rtc.peerId !== peerId) {
      return;
    }
    try {
      rtc.makingOffer = true;
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await sendContent({ k: "rtc", s: "offer", sdp: pc.localDescription.sdp }, { toPeerId: peerId, silent: true });
    } catch (error) {
      addSystemMessage("屏幕共享协商失败：" + safeError(error), peerId);
    } finally {
      rtc.makingOffer = false;
    }
  }

  // ---- 屏幕共享：复用当前私聊的 PeerConnection，媒体走 DTLS-SRTP 端到端加密，服务器看不到。 ----

  async function toggleScreenShare() {
    if (rtc.localShare) {
      stopScreenShare();
      return;
    }
    await startScreenShare();
  }

  async function startScreenShare() {
    if (state.active === GROUP || !canSend()) {
      showToast("屏幕共享仅用于私聊");
      return;
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
      showToast("当前环境不支持屏幕共享（需 HTTPS / localhost）");
      return;
    }
    const peerId = state.active;
    let stream;
    try {
      stream = await navigator.mediaDevices.getDisplayMedia({
        video: { displaySurface: "monitor" },
        audio: false,
        selfBrowserSurface: "exclude",
        systemAudio: "exclude",
      });
    } catch (error) {
      if (error && (error.name === "NotAllowedError" || error.name === "AbortError")) {
        return; // 用户在系统选择器里取消，不报错。
      }
      showToast("无法开始屏幕共享：" + safeError(error));
      return;
    }
    ensureAudio();
    // 主动发起共享的一方负责 offer；若尚无连接则顺带建数据通道，保证消息/文件 P2P 也可用。
    const pc = ensurePeerConnection(peerId, true);
    rtc.localShare = stream;
    rtc.shareSenders = stream.getTracks().map((track) => pc.addTrack(track, stream));
    // 用户通过浏览器原生「停止共享」按钮结束时，同步收尾。
    stream.getVideoTracks().forEach((track) => {
      track.addEventListener("ended", () => stopScreenShare());
    });
    if (ui) {
      ui.screenSharing = true;
    }
    syncHeaderUI();
    addSystemMessage("已开始向对方共享屏幕。", peerId);
    await renegotiate(peerId);
  }

  function stopScreenShare() {
    const peerId = rtc.peerId;
    const wasSharing = !!rtc.localShare;
    if (rtc.localShare) {
      rtc.localShare.getTracks().forEach((track) => { try { track.stop(); } catch { /* 忽略 */ } });
    }
    if (rtc.shareSenders && rtc.pc) {
      rtc.shareSenders.forEach((sender) => { try { rtc.pc.removeTrack(sender); } catch { /* 忽略 */ } });
    }
    rtc.localShare = null;
    rtc.shareSenders = null;
    if (ui) {
      ui.screenSharing = false;
    }
    syncHeaderUI();
    if (wasSharing && rtc.pc && peerId) {
      addSystemMessage("已停止屏幕共享。", peerId);
      void renegotiate(peerId);
    }
  }

  function showRemoteShare(peerId, stream) {
    rtc.remoteStream = stream;
    if (ui) {
      ui.remoteSharing = true;
      ui.shareMinimized = false;
      if (ui.$refs && ui.$refs.remoteVideo) {
        ui.$refs.remoteVideo.srcObject = stream;
      }
    }
    addSystemMessage("对方开始共享屏幕。", peerId);
  }

  function hideRemoteShare() {
    if (!rtc.remoteStream && !(ui && ui.remoteSharing)) {
      return;
    }
    rtc.remoteStream = null;
    if (ui) {
      ui.remoteSharing = false;
      if (ui.$refs && ui.$refs.remoteVideo) {
        ui.$refs.remoteVideo.srcObject = null;
      }
    }
  }

  // ---- 语音通话：把麦克风轨推入同一条 P2P，双方各自开麦即成两人会议室。 ----

  async function toggleVoice() {
    if (rtc.localVoice) {
      stopVoice();
      return;
    }
    await startVoice();
  }

  async function startVoice() {
    if (state.active === GROUP || !canSend()) {
      showToast("语音通话仅用于私聊");
      return;
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      showToast("当前环境不支持语音（需 HTTPS / localhost）");
      return;
    }
    const peerId = state.active;
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
        video: false,
      });
    } catch (error) {
      if (error && (error.name === "NotAllowedError" || error.name === "AbortError")) {
        showToast("已拒绝麦克风权限");
        return;
      }
      showToast("无法开启语音：" + safeError(error));
      return;
    }
    ensureAudio();
    const pc = ensurePeerConnection(peerId, true);
    rtc.localVoice = stream;
    rtc.micMuted = false;
    rtc.voiceSenders = stream.getTracks().map((track) => pc.addTrack(track, stream));
    if (ui) {
      ui.inCall = true;
      ui.micMuted = false;
    }
    syncHeaderUI();
    addSystemMessage("已加入语音通话。", peerId);
    await renegotiate(peerId);
  }

  function stopVoice() {
    const peerId = rtc.peerId;
    const wasInCall = !!rtc.localVoice;
    if (rtc.localVoice) {
      rtc.localVoice.getTracks().forEach((track) => { try { track.stop(); } catch { /* 忽略 */ } });
    }
    if (rtc.voiceSenders && rtc.pc) {
      rtc.voiceSenders.forEach((sender) => { try { rtc.pc.removeTrack(sender); } catch { /* 忽略 */ } });
    }
    rtc.localVoice = null;
    rtc.voiceSenders = null;
    rtc.micMuted = false;
    if (ui) {
      ui.inCall = false;
      ui.micMuted = false;
    }
    syncHeaderUI();
    if (wasInCall && rtc.pc && peerId) {
      addSystemMessage("已退出语音通话。", peerId);
      void renegotiate(peerId);
    }
  }

  function toggleMute() {
    if (!rtc.localVoice) {
      return;
    }
    rtc.micMuted = !rtc.micMuted;
    rtc.localVoice.getAudioTracks().forEach((track) => { track.enabled = !rtc.micMuted; });
    if (ui) {
      ui.micMuted = rtc.micMuted;
    }
    syncHeaderUI();
  }

  function attachRemoteVoice(peerId, stream) {
    const wasActive = !!(ui && ui.remoteVoice);
    rtc.remoteVoiceStream = stream;
    if (ui) {
      ui.remoteVoice = true;
      if (ui.$refs && ui.$refs.remoteAudio) {
        ui.$refs.remoteAudio.srcObject = stream;
        void ui.$refs.remoteAudio.play().catch(() => {});
      }
    }
    if (!wasActive) {
      addSystemMessage("对方已接入语音。", peerId);
    }
  }

  function detachRemoteVoice() {
    if (!rtc.remoteVoiceStream && !(ui && ui.remoteVoice)) {
      return;
    }
    rtc.remoteVoiceStream = null;
    if (ui) {
      ui.remoteVoice = false;
      if (ui.$refs && ui.$refs.remoteAudio) {
        ui.$refs.remoteAudio.srcObject = null;
      }
    }
  }

  async function p2pButtonClick() {
    if (state.active === GROUP || !canSend()) {
      return;
    }
    if (rtcConnected(state.active)) {
      chooseFile(true);
    } else {
      await requestP2P(state.active);
    }
  }

  function updateP2pButton() {
    syncHeaderUI();
  }

  // ---- P2P 数据通道：传文件与转发端到端加密信封。 ----

  function transferID() {
    if (crypto.randomUUID) {
      return crypto.randomUUID();
    }
    const bytes = crypto.getRandomValues(new Uint8Array(12));
    return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function checksumStart() {
    return 0x811c9dc5;
  }

  function checksumUpdate(hash, bytes) {
    let next = hash >>> 0;
    for (let index = 0; index < bytes.length; index += 1) {
      next ^= bytes[index];
      next = Math.imul(next, 0x01000193) >>> 0;
    }
    return next;
  }

  function checksumHex(hash) {
    return (hash >>> 0).toString(16).padStart(8, "0");
  }

  function transferLabel(transfer) {
    const percent = Math.max(0, Math.min(100, transfer.percent || 0));
    if (transfer.status === TRANSFER_STATUS.QUEUED) {
      return "等待 P2P 连接";
    }
    if (transfer.status === TRANSFER_STATUS.SENDING) {
      return "发送中 " + percent + "%";
    }
    if (transfer.status === TRANSFER_STATUS.RECEIVING) {
      return "接收中 " + percent + "%";
    }
    if (transfer.status === TRANSFER_STATUS.DONE) {
      return transfer.checksum ? "已完成 · 校验 " + transfer.checksum : "已完成";
    }
    if (transfer.status === TRANSFER_STATUS.CANCELED) {
      return "已取消";
    }
    return transfer.error ? "失败 · " + transfer.error : "失败";
  }

  function createTransfer(direction, total, status) {
    const transfer = {
      id: transferID(),
      direction,
      status,
      loaded: 0,
      total: Number(total) || 0,
      percent: 0,
      label: "",
      checksum: "",
      error: "",
      canCancel: status === TRANSFER_STATUS.QUEUED || status === TRANSFER_STATUS.SENDING || status === TRANSFER_STATUS.RECEIVING,
      canRetry: false,
    };
    transfer.label = transferLabel(transfer);
    return transfer;
  }

  function updateTransfer(message, patch) {
    if (!message || !message.transfer) {
      return;
    }
    Object.assign(message.transfer, patch || {});
    const total = message.transfer.total || message.size || 0;
    message.transfer.percent = total > 0 ? Math.floor((message.transfer.loaded || 0) * 100 / total) : 0;
    message.transfer.canCancel = message.transfer.status === TRANSFER_STATUS.QUEUED ||
      message.transfer.status === TRANSFER_STATUS.SENDING ||
      message.transfer.status === TRANSFER_STATUS.RECEIVING;
    message.transfer.canRetry = message.transfer.status === TRANSFER_STATUS.FAILED ||
      (message.transfer.status === TRANSFER_STATUS.CANCELED && message.transfer.direction === "send");
    message.transfer.label = transferLabel(message.transfer);
    renderMessages();
    renderConversations();
  }

  function createSendTransferMessage(peerId, file) {
    const transfer = createTransfer("send", file.size, TRANSFER_STATUS.QUEUED);
    const message = addChatMessage(peerId, {
      id: 0, system: false, fromSelf: true, from: state.self ? state.self.id : "self",
      author: selfName(), time: formatTime(new Date()),
      kind: "file", mime: file.type || "application/octet-stream", name: file.name || "file",
      size: file.size, url: "", p2p: true, file, transfer,
    });
    return message;
  }

  function findTransferMessage(messageId) {
    for (const [convoKey, list] of Object.entries(state.threads)) {
      const message = list.find((item) => item.id === messageId && item.transfer);
      if (message) {
        return { convoKey, message };
      }
    }
    return null;
  }

  function findTransferByID(peerId, transferId) {
    const list = state.threads[peerId] || [];
    return list.find((message) => message.transfer && message.transfer.id === transferId) || null;
  }

  function cancelTransfer(messageId) {
    const found = findTransferMessage(messageId);
    if (!found) {
      return;
    }
    const { message } = found;
    const transfer = message.transfer;
    if (transfer.status !== TRANSFER_STATUS.QUEUED && transfer.status !== TRANSFER_STATUS.SENDING && transfer.status !== TRANSFER_STATUS.RECEIVING) {
      return;
    }
    updateTransfer(message, { status: TRANSFER_STATUS.CANCELED, error: "" });
    rtc.queue = rtc.queue.filter((item) => item.message !== message);
    if (rtc.sending && rtc.sending.message === message) {
      rtc.sending.canceled = true;
    }
    if (rtc.recv && rtc.recv.message === message) {
      rtc.recv = null;
    }
    if (rtc.channel && rtc.channel.readyState === "open") {
      try { rtc.channel.send(JSON.stringify({ t: "cancel", id: transfer.id })); } catch { /* 忽略 */ }
    }
  }

  function retryTransfer(messageId) {
    const found = findTransferMessage(messageId);
    if (!found) {
      return;
    }
    const { message } = found;
    const transfer = message.transfer;
    if (transfer.direction === "send" && message.file) {
      updateTransfer(message, { status: TRANSFER_STATUS.QUEUED, loaded: 0, error: "", checksum: "" });
      void sendFileP2P(message.file, { message });
      return;
    }
    if (transfer.direction === "recv" && rtc.channel && rtc.channel.readyState === "open") {
      updateTransfer(message, { status: TRANSFER_STATUS.RECEIVING, loaded: 0, error: "", checksum: "" });
      try { rtc.channel.send(JSON.stringify({ t: "retry", id: transfer.id })); } catch { /* 忽略 */ }
    }
  }

  async function sendFileP2P(file, opts) {
    opts = opts || {};
    const peerId = state.active;
    if (peerId === GROUP) {
      showToast("P2P 仅用于私聊");
      return;
    }
    if (!canSend()) {
      return;
    }
    const message = opts.message || createSendTransferMessage(peerId, file);
    if (!rtcConnected(peerId)) {
      updateTransfer(message, { status: TRANSFER_STATUS.QUEUED, loaded: 0, error: "" });
      rtc.queue.push({ file, message });
      await requestP2P(peerId);
      return;
    }
    await pushFile(file, message, opts.transferId || (message.transfer && message.transfer.id));
  }

  function flushQueue() {
    const pending = rtc.queue.slice();
    rtc.queue = [];
    void (async () => {
      for (const item of pending) {
        await pushFile(item.file, item.message, item.message && item.message.transfer ? item.message.transfer.id : "");
      }
    })();
  }

  function waitDrain(channel) {
    return new Promise((resolve) => {
      channel.onbufferedamountlow = () => {
        channel.onbufferedamountlow = null;
        resolve();
      };
    });
  }

  async function pushFile(file, message, explicitTransferId) {
    const channel = rtc.channel;
    if (!channel || channel.readyState !== "open") {
      return;
    }
    const peerId = rtc.peerId;
    const mime = file.type || "application/octet-stream";
    message = message || createSendTransferMessage(peerId, file);
    if (!message.transfer) {
      message.transfer = createTransfer("send", file.size, TRANSFER_STATUS.SENDING);
    }
    if (explicitTransferId) {
      message.transfer.id = explicitTransferId;
    }
    const transferId = message.transfer.id;
    rtc.sentFiles.set(transferId, file);
    rtc.sending = { id: transferId, message, canceled: false };
    updateTransfer(message, { status: TRANSFER_STATUS.SENDING, loaded: 0, total: file.size, error: "", checksum: "" });
    channel.send(JSON.stringify({ t: "meta", id: transferId, name: file.name || "file", size: file.size, mime }));
    try {
      let offset = 0;
      let checksum = checksumStart();
      while (offset < file.size) {
        if (rtc.sending && rtc.sending.id === transferId && rtc.sending.canceled) {
          channel.send(JSON.stringify({ t: "cancel", id: transferId }));
          updateTransfer(message, { status: TRANSFER_STATUS.CANCELED });
          return;
        }
        if (channel.bufferedAmount > 8 * RTC_CHUNK) {
          await waitDrain(channel);
        }
        if (channel.readyState !== "open") {
          updateTransfer(message, { status: TRANSFER_STATUS.FAILED, error: "通道关闭" });
          return;
        }
        const chunk = await file.slice(offset, offset + RTC_CHUNK).arrayBuffer();
        checksum = checksumUpdate(checksum, new Uint8Array(chunk));
        channel.send(chunk);
        offset += chunk.byteLength;
        updateTransfer(message, { status: TRANSFER_STATUS.SENDING, loaded: offset });
      }
      const finalChecksum = checksumHex(checksum);
      channel.send(JSON.stringify({ t: "done", id: transferId, checksum: finalChecksum }));
      message.url = URL.createObjectURL(file);
      updateTransfer(message, { status: TRANSFER_STATUS.DONE, loaded: file.size, checksum: finalChecksum });
    } catch (error) {
      updateTransfer(message, { status: TRANSFER_STATUS.FAILED, error: safeError(error) });
    } finally {
      if (rtc.sending && rtc.sending.id === transferId) {
        rtc.sending = null;
      }
    }
  }

  function handleChannelData(data) {
    if (typeof data === "string") {
      let msg;
      try { msg = JSON.parse(data); } catch { return; }
      if (msg.t === "meta") {
        const transferId = msg.id || transferID();
        let message = findTransferByID(rtc.peerId, transferId);
        if (!message) {
          message = addChatMessage(rtc.peerId, {
            id: 0, system: false, fromSelf: false, from: rtc.peerId,
            author: peerName(rtc.peerId), time: formatTime(new Date()),
            kind: "file", mime: msg.mime || "application/octet-stream", name: msg.name || "file",
            size: Number(msg.size) || 0, url: "", p2p: true,
            transfer: createTransfer("recv", Number(msg.size) || 0, TRANSFER_STATUS.RECEIVING),
          });
          message.transfer.id = transferId;
        } else {
          updateTransfer(message, { status: TRANSFER_STATUS.RECEIVING, loaded: 0, total: Number(msg.size) || 0, error: "", checksum: "" });
        }
        rtc.recv = {
          id: transferId,
          name: msg.name,
          size: Number(msg.size) || 0,
          mime: msg.mime || "application/octet-stream",
          chunks: [],
          received: 0,
          checksum: checksumStart(),
          message,
        };
      } else if (msg.t === "done") {
        finishRecv(msg.id || "", msg.checksum || "");
      } else if (msg.t === "cancel") {
        handleTransferCancel(msg.id || "");
      } else if (msg.t === "retry") {
        handleTransferRetry(msg.id || "");
      } else if (msg.t === "msg" && typeof msg.e === "string") {
        let envelope;
        try { envelope = JSON.parse(msg.e); } catch { return; }
        void routeEnvelope(envelope);
      }
      return;
    }
    if (rtc.recv && data instanceof ArrayBuffer) {
      rtc.recv.chunks.push(data);
      rtc.recv.received += data.byteLength;
      rtc.recv.checksum = checksumUpdate(rtc.recv.checksum, new Uint8Array(data));
      updateTransfer(rtc.recv.message, { status: TRANSFER_STATUS.RECEIVING, loaded: rtc.recv.received });
    }
  }

  function handleTransferCancel(transferId) {
    if (rtc.recv && (!transferId || rtc.recv.id === transferId)) {
      updateTransfer(rtc.recv.message, { status: TRANSFER_STATUS.CANCELED });
      rtc.recv = null;
      return;
    }
    if (rtc.sending && (!transferId || rtc.sending.id === transferId)) {
      rtc.sending.canceled = true;
      updateTransfer(rtc.sending.message, { status: TRANSFER_STATUS.CANCELED });
    }
  }

  function handleTransferRetry(transferId) {
    const file = rtc.sentFiles.get(transferId);
    if (!file || !rtcConnected(rtc.peerId)) {
      return;
    }
    void pushFile(file, null, transferId);
  }

  function finishRecv(transferId, expectedChecksum) {
    const received = rtc.recv;
    rtc.recv = null;
    if (!received) {
      return;
    }
    if (transferId && received.id !== transferId) {
      updateTransfer(received.message, { status: TRANSFER_STATUS.FAILED, error: "传输编号不匹配" });
      return;
    }
    const actualChecksum = checksumHex(received.checksum);
    if (received.received !== received.size) {
      updateTransfer(received.message, { status: TRANSFER_STATUS.FAILED, error: "大小不匹配" });
      return;
    }
    if (expectedChecksum && actualChecksum !== expectedChecksum) {
      updateTransfer(received.message, { status: TRANSFER_STATUS.FAILED, error: "校验失败" });
      return;
    }
    const blob = new Blob(received.chunks, { type: received.mime });
    const url = URL.createObjectURL(blob);
    const peerId = rtc.peerId;
    received.message.url = url;
    received.message.size = received.size || blob.size;
    updateTransfer(received.message, { status: TRANSFER_STATUS.DONE, loaded: received.message.size, checksum: actualChecksum });
    maybeBeep();
  }

  function applyBackground(dataURL, skipSave) {
    state.backgroundImage = dataURL || "";
    if (ui) {
      ui.backgroundImage = state.backgroundImage;
    }
    if (dataURL) {
      if (!skipSave) {
        saveSetting("bg", dataURL);
      }
    } else {
      try {
        localStorage.removeItem("pptter.bg");
      } catch {
        // 忽略。
      }
    }
  }

  async function handleBgFile(file) {
    if (!file.type || !file.type.startsWith("image/")) {
      showToast("请选择图片文件");
      return;
    }
    if (file.size > 3 * 1024 * 1024) {
      showToast("背景图请控制在 3MB 以内");
      return;
    }
    const buffer = await file.arrayBuffer();
    applyBackground("data:" + file.type + ";base64," + bytesToBase64(new Uint8Array(buffer)));
  }

  function ensureAudio() {
    if (!audioCtx) {
      try {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      } catch {
        audioCtx = null;
      }
    }
    if (audioCtx && audioCtx.state === "suspended") {
      void audioCtx.resume();
    }
  }

  function maybeBeep() {
    if (state.muted) {
      return;
    }
    playTone(state.tone);
  }

  // playTone 按预设依次合成几段振荡器音符，纯本地、无音频资源文件。
  function playTone(name) {
    ensureAudio();
    if (!audioCtx) {
      return;
    }
    const sequence = TONES[name] || TONES.soft;
    const base = audioCtx.currentTime;
    try {
      for (const note of sequence) {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = note.t;
        osc.frequency.value = note.f;
        const start = base + (note.at || 0);
        gain.gain.setValueAtTime(0.0001, start);
        gain.gain.exponentialRampToValueAtTime(note.g, start + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.0001, start + note.d);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start(start);
        osc.stop(start + note.d + 0.02);
      }
    } catch {
      // 忽略音频错误。
    }
  }

  function renderSelfAvatar() {
    if (!ui) {
      return;
    }
    const id = state.self ? state.self.id : "";
    const avatar = avatarModel(id, id ? shortID(id).slice(0, 2) : "我");
    ui.selfAvatarText = avatar.text || (id ? "" : "我");
    ui.selfAvatarClass = avatar.avatarClass;
  }

  function fallbackBoot() {
    setTimeout(boot, 0);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", fallbackBoot);
  } else {
    fallbackBoot();
  }
})();
