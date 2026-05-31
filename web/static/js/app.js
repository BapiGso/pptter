(function () {
  "use strict";

  // 端到端加密的零信任群聊/私聊。不使用任何会触发 eval 的框架，兼容严格 CSP
  // （script-src 'self'，无 unsafe-eval）。UI 用原生 DOM 渲染。
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

  const PROTOCOL = "X25519-HKDF-A256GCM+Ed25519";
  const PROTOCOL_VERSION = 2;
  const HKDF_INFO = "pptter-msg-v2";
  const PAD_BUCKET = 256;
  const MAX_TEXT_BYTES = 4096;
  const MAX_IMAGE_BYTES = 1.5 * 1024 * 1024;
  const REPLAY_WINDOW_MS = 5 * 60 * 1000;
  const DEFAULT_ROOM = "lobby";
  const GROUP = "group";
  const MAX_MESSAGES_PER_THREAD = 200;
  const roomPattern = /[^A-Za-z0-9_-]/g;
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  const state = {
    room: initialRoom(),
    self: null,
    peers: [],
    threads: { group: [] },
    unread: {},
    active: GROUP,
    search: "",
    muted: false,
    socket: null,
    identityKeyPair: null,
    dhKeyPair: null,
    idKeyB64: "",
    dhKeyB64: "",
    dhSigB64: "",
    sendCounter: 0,
    nextMessageID: 1,
    statusTone: "warn",
    reconnecting: false,
  };

  const dom = {};
  let toastTimer = 0;
  let audioCtx = null;

  function start() {
    dom.convoList = document.getElementById("convo-list");
    dom.search = document.getElementById("search");
    dom.convoTitle = document.getElementById("convo-title");
    dom.statusDot = document.getElementById("status-dot");
    dom.statusText = document.getElementById("status-text");
    dom.messages = document.getElementById("messages");
    dom.form = document.getElementById("msg-form");
    dom.input = document.getElementById("msg-input");
    dom.sendBtn = document.getElementById("send-btn");
    dom.reconnect = document.getElementById("btn-reconnect");
    dom.fileInput = document.getElementById("file-input");
    dom.btnImage = document.getElementById("btn-image");
    dom.toast = document.getElementById("toast");
    dom.toastText = document.getElementById("toast-text");
    dom.btnProfile = document.getElementById("btn-profile");
    dom.selfAvatar = document.getElementById("self-avatar");
    dom.btnTheme = document.getElementById("btn-theme");
    dom.themeIcon = document.getElementById("theme-icon");
    dom.settings = document.getElementById("settings");
    dom.settingsClose = document.getElementById("settings-close");
    dom.setSound = document.getElementById("set-sound");
    dom.setBg = document.getElementById("set-bg");
    dom.bgReset = document.getElementById("bg-reset");
    dom.lightbox = document.getElementById("lightbox");
    dom.lightboxImg = document.getElementById("lightbox-img");

    dom.form.addEventListener("submit", (e) => { e.preventDefault(); void sendText(); });
    dom.search.addEventListener("input", () => { state.search = dom.search.value; renderConversations(); });
    dom.reconnect.addEventListener("click", () => { void reconnect(); });
    dom.btnImage.addEventListener("click", () => { if (canSend()) dom.fileInput.click(); });
    dom.fileInput.addEventListener("change", () => {
      if (dom.fileInput.files && dom.fileInput.files[0]) {
        void handleFile(dom.fileInput.files[0]);
      }
      dom.fileInput.value = "";
    });

    // 拖拽与粘贴图片。
    dom.messages.addEventListener("dragover", (e) => e.preventDefault());
    dom.messages.addEventListener("drop", (e) => {
      e.preventDefault();
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
        void handleFile(e.dataTransfer.files[0]);
      }
    });
    document.addEventListener("paste", (e) => {
      const files = e.clipboardData && e.clipboardData.files;
      if (files && files[0]) {
        void handleFile(files[0]);
      }
    });

    // 设置 / 深色模式 / 灯箱。
    dom.btnProfile.addEventListener("click", openSettings);
    dom.settingsClose.addEventListener("click", closeSettings);
    dom.settings.addEventListener("click", (e) => { if (e.target === dom.settings) closeSettings(); });
    dom.setSound.addEventListener("change", () => { state.muted = !dom.setSound.checked; saveSetting("muted", state.muted ? "1" : "0"); });
    dom.setBg.addEventListener("change", () => {
      if (dom.setBg.files && dom.setBg.files[0]) {
        void handleBgFile(dom.setBg.files[0]);
      }
      dom.setBg.value = "";
    });
    dom.bgReset.addEventListener("click", () => applyBackground(null));
    dom.btnTheme.addEventListener("click", toggleTheme);
    dom.lightbox.addEventListener("click", closeLightbox);

    initSettings();
    renderConversations();
    renderHeader();
    void init();
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
    closeSocket();
    setStatus("连接中", "warn");
    renderConversations();
    renderHeader();
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
    renderConversations();
  }

  function handlePeerLeft(peerID) {
    state.peers = state.peers.filter((p) => p.id !== peerID);
    addSystemMessage("成员 " + shortID(peerID) + " 已离开。");
    if (state.active === peerID) {
      state.active = GROUP;
      renderHeader();
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
    const message = contentToMessage(json, peer.id, shortID(peer.id), false);
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
      state.peers.push({ id: peer.id, idVerifyKey, dhPublicKey, lastCounter: 0 });
      if (!state.threads[peer.id]) {
        state.threads[peer.id] = [];
      }
      if (announce) {
        addSystemMessage("成员 " + shortID(peer.id) + " 加入了群聊。");
      }
      renderConversations();
    } catch (error) {
      addSystemMessage("无法导入成员密钥：" + safeError(error));
    }
  }

  // ---- 发送 ----

  async function sendText() {
    const text = dom.input.value.trim();
    if (!text || !canSend()) {
      return;
    }
    if (textEncoder.encode(text).length > MAX_TEXT_BYTES) {
      addSystemMessage("消息过长，未发送。");
      return;
    }
    const ok = await sendContent({ k: "t", t: text });
    if (ok) {
      dom.input.value = "";
    }
  }

  async function handleFile(file) {
    if (!canSend()) {
      return;
    }
    if (!file.type || !file.type.startsWith("image/")) {
      showToast("目前只支持发送图片");
      return;
    }
    if (file.size > MAX_IMAGE_BYTES) {
      showToast("图片太大，请控制在 1.5MB 以内");
      return;
    }
    try {
      const buffer = await file.arrayBuffer();
      const base64 = bytesToBase64(new Uint8Array(buffer));
      await sendContent({ k: "i", m: file.type, d: base64 });
    } catch (error) {
      addSystemMessage("图片发送失败：" + safeError(error));
    }
  }

  async function sendContent(content) {
    const isGroup = state.active === GROUP;
    const targets = isGroup ? state.peers : state.peers.filter((p) => p.id === state.active);
    if (targets.length === 0) {
      addSystemMessage(isGroup ? "群里暂时没有其他人，消息未发送。" : "对方已离线，私聊消息未发送。");
      return false;
    }

    const scope = isGroup ? GROUP : "dm";
    const ctr = ++state.sendCounter;
    const ts = Date.now();
    const bytes = textEncoder.encode(JSON.stringify(content));
    const padded = padPlaintext(bytes);
    try {
      if (content.k === "i") {
        // 图片密文较大，按收件人拆成单独的帧，避免单帧超过服务端大小上限。
        for (const peer of targets) {
          const envelope = await sealForPeer(peer, padded, ctr, ts, scope);
          state.socket.send(JSON.stringify({ type: "send", messages: [{ dest: peer.id, payload: envelope }] }));
        }
      } else {
        const messages = [];
        for (const peer of targets) {
          messages.push({ dest: peer.id, payload: await sealForPeer(peer, padded, ctr, ts, scope) });
        }
        state.socket.send(JSON.stringify({ type: "send", messages }));
      }
    } finally {
      wipeBytes(bytes);
      wipeBytes(padded);
    }

    const selfID = state.self ? state.self.id : "self";
    const own = contentToMessage(JSON.stringify(content), selfID, "我", true);
    if (own) {
      addChatMessage(state.active, own);
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

  // contentToMessage 把解密出的 JSON 内容转成可渲染的消息对象，并做基本校验。
  function contentToMessage(json, from, author, fromSelf) {
    let content;
    try {
      content = JSON.parse(json);
    } catch {
      return null;
    }
    const base = { id: 0, system: false, fromSelf, from, author, time: formatTime(new Date()) };
    if (content.k === "t" && typeof content.t === "string") {
      return Object.assign(base, { kind: "text", text: content.t });
    }
    if (content.k === "i" && typeof content.m === "string" && /^image\//.test(content.m) && typeof content.d === "string") {
      return Object.assign(base, { kind: "image", mime: content.m, data: content.d });
    }
    return null;
  }

  // ---- 会话与状态 ----

  function selectConversation(key) {
    state.active = key;
    state.unread[key] = 0;
    renderConversations();
    renderHeader();
    renderMessages();
  }

  function conversationTitle() {
    return state.active === GROUP ? "群聊「" + state.room + "」" : shortID(state.active) + " · 私聊";
  }

  function filteredPeers() {
    const q = state.search.trim().toLowerCase();
    if (!q) {
      return state.peers;
    }
    return state.peers.filter((p) => shortID(p.id).toLowerCase().includes(q));
  }

  function threadPreview(key) {
    const list = state.threads[key] || [];
    for (let i = list.length - 1; i >= 0; i -= 1) {
      const m = list[i];
      if (!m.system) {
        const body = m.kind === "image" ? "[图片]" : m.text;
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
  }

  function addSystemMessage(text) {
    state.threads[GROUP].push({
      id: state.nextMessageID++, system: true, fromSelf: false,
      from: "system", author: "系统", kind: "text", text: text, time: formatTime(new Date()),
    });
    trimThread(GROUP);
    if (state.active === GROUP) {
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

  // ---- 渲染 ----

  function setStatus(text, tone) {
    state.statusTone = tone;
    if (dom.statusText) {
      dom.statusText.textContent = text;
    }
    if (dom.statusDot) {
      dom.statusDot.className = "inline-block size-2 rounded-full " +
        (tone === "ok" ? "bg-success" : tone === "bad" ? "bg-error" : "bg-warning");
    }
    updateSendable();
  }

  function updateSendable() {
    const ok = canSend();
    if (dom.input) {
      dom.input.disabled = !ok;
      dom.input.placeholder = state.active === GROUP ? "群聊消息，本地加密后发送" : "私聊消息，仅对方可解密";
    }
    if (dom.sendBtn) {
      dom.sendBtn.disabled = !ok;
    }
    if (dom.btnImage) {
      dom.btnImage.disabled = !ok;
    }
  }

  function renderHeader() {
    if (dom.convoTitle) {
      dom.convoTitle.textContent = conversationTitle();
    }
    updateSendable();
  }

  function avatarEl(id, initials, big) {
    const el = document.createElement("span");
    el.className = (big ? "size-11" : "size-9") +
      " grid shrink-0 place-items-center rounded-full text-xs font-extrabold uppercase text-white select-none";
    el.textContent = initials;
    const hue = colorHue(id || "");
    el.style.background = "linear-gradient(135deg, hsl(" + hue + " 70% 38%), hsl(" + ((hue + 36) % 360) + " 78% 50%))";
    return el;
  }

  function convoButton(opts) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "flex items-center gap-3 px-3.5 py-2.5 text-left text-white shrink-0 w-60 md:w-auto hover:bg-white/10" +
      (opts.active ? " bg-white/20" : "");
    btn.addEventListener("click", opts.onClick);

    if (opts.groupBadge) {
      const g = document.createElement("span");
      g.className = "size-11 grid shrink-0 place-items-center rounded-full bg-white/25 text-white font-extrabold";
      g.textContent = "群";
      btn.appendChild(g);
    } else {
      btn.appendChild(avatarEl(opts.id, opts.initials, true));
    }

    const body = document.createElement("span");
    body.className = "min-w-0 flex-1";
    const top = document.createElement("span");
    top.className = "flex items-center justify-between gap-2";
    const name = document.createElement("strong");
    name.className = "text-sm truncate";
    name.textContent = opts.title;
    top.appendChild(name);
    if (opts.unread > 0) {
      const badge = document.createElement("span");
      badge.className = "badge badge-xs badge-error";
      badge.textContent = String(opts.unread);
      top.appendChild(badge);
    }
    const preview = document.createElement("small");
    preview.className = "block text-xs text-white/60 truncate";
    preview.textContent = opts.preview;
    body.appendChild(top);
    body.appendChild(preview);
    btn.appendChild(body);
    return btn;
  }

  function renderConversations() {
    if (!dom.convoList) {
      return;
    }
    dom.convoList.replaceChildren();

    dom.convoList.appendChild(convoButton({
      groupBadge: true,
      title: "群聊 (" + memberCountText() + ")",
      preview: threadPreview(GROUP),
      unread: state.unread[GROUP] || 0,
      active: state.active === GROUP,
      onClick: () => selectConversation(GROUP),
    }));

    for (const peer of filteredPeers()) {
      dom.convoList.appendChild(convoButton({
        id: peer.id,
        initials: shortID(peer.id).slice(0, 2),
        title: shortID(peer.id),
        preview: threadPreview(peer.id),
        unread: state.unread[peer.id] || 0,
        active: state.active === peer.id,
        onClick: () => selectConversation(peer.id),
      }));
    }

    if (state.peers.length === 0) {
      const empty = document.createElement("div");
      empty.className = "px-3.5 py-2 text-xs text-white/70 shrink-0";
      empty.textContent = "还没有其他成员在线";
      dom.convoList.appendChild(empty);
    }
  }

  function messageEl(message) {
    const wrap = document.createElement("div");
    if (message.system) {
      const center = document.createElement("div");
      center.className = "flex justify-center my-2";
      const badge = document.createElement("span");
      badge.className = "badge badge-ghost badge-sm max-w-[85%] h-auto py-1 whitespace-normal text-center text-base-content/70";
      badge.textContent = message.text;
      center.appendChild(badge);
      wrap.appendChild(center);
      return wrap;
    }

    const chat = document.createElement("div");
    chat.className = "chat " + (message.fromSelf ? "chat-end" : "chat-start");

    const image = document.createElement("div");
    image.className = "chat-image";
    image.appendChild(avatarEl(message.from, shortID(message.from).slice(0, 2), false));

    const head = document.createElement("div");
    head.className = "chat-header text-xs opacity-80 gap-1";
    const author = document.createElement("span");
    author.textContent = message.author;
    const time = document.createElement("time");
    time.className = "opacity-60";
    time.textContent = " " + message.time;
    head.appendChild(author);
    head.appendChild(time);

    const bubble = document.createElement("div");
    bubble.className = "chat-bubble" + (message.fromSelf ? " chat-bubble-accent" : "");
    if (message.kind === "image") {
      const img = document.createElement("img");
      img.className = "rounded-lg max-w-[min(70vw,18rem)] max-h-[18rem] h-auto w-auto cursor-zoom-in";
      img.alt = "图片";
      img.loading = "lazy";
      const src = "data:" + message.mime + ";base64," + message.data;
      img.src = src;
      img.addEventListener("click", () => openLightbox(src));
      bubble.classList.add("p-1", "max-w-full");
      bubble.appendChild(img);
    } else {
      bubble.textContent = message.text;
    }

    chat.appendChild(image);
    chat.appendChild(head);
    chat.appendChild(bubble);
    wrap.appendChild(chat);
    return wrap;
  }

  function renderMessages() {
    if (!dom.messages) {
      return;
    }
    const list = state.threads[state.active] || [];
    dom.messages.replaceChildren();
    for (const message of list) {
      dom.messages.appendChild(messageEl(message));
    }
    requestAnimationFrame(() => {
      dom.messages.scrollTop = dom.messages.scrollHeight;
    });
  }

  function showToast(text) {
    if (!dom.toast) {
      return;
    }
    dom.toastText.textContent = text;
    dom.toast.classList.remove("hidden");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => dom.toast.classList.add("hidden"), 1800);
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

  function initSettings() {
    const stored = lsGet("theme");
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(stored || (prefersDark ? "pptter-dark" : "pptter"));

    state.muted = lsGet("muted") === "1";
    if (dom.setSound) {
      dom.setSound.checked = !state.muted;
    }

    const bg = lsGet("bg");
    if (bg) {
      applyBackground(bg, true);
    }

    // 浏览器自动播放策略：首次用户交互后才允许音频。
    document.addEventListener("pointerdown", ensureAudio, { once: true });
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    saveSetting("theme", theme);
    setThemeIcon(theme);
  }

  function setThemeIcon(theme) {
    if (!dom.themeIcon) {
      return;
    }
    dom.themeIcon.innerHTML = theme === "pptter-dark"
      ? '<circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path>'
      : '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"></path>';
  }

  // toggleTheme：用 View Transitions API 从按钮位置以圆形遮罩扩散到整页。
  function toggleTheme(event) {
    const current = document.documentElement.dataset.theme === "pptter-dark" ? "pptter-dark" : "pptter";
    const next = current === "pptter-dark" ? "pptter" : "pptter-dark";
    const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!document.startViewTransition || reduced) {
      applyTheme(next);
      return;
    }
    const x = event.clientX;
    const y = event.clientY;
    const endRadius = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
    const transition = document.startViewTransition(() => applyTheme(next));
    transition.ready.then(() => {
      document.documentElement.animate(
        { clipPath: ["circle(0px at " + x + "px " + y + "px)", "circle(" + endRadius + "px at " + x + "px " + y + "px)"] },
        { duration: 450, easing: "ease-in-out", pseudoElement: "::view-transition-new(root)" });
    });
  }

  function openSettings() {
    if (dom.settings) {
      dom.settings.classList.remove("hidden");
    }
  }

  function closeSettings() {
    if (dom.settings) {
      dom.settings.classList.add("hidden");
    }
  }

  function applyBackground(dataURL, skipSave) {
    if (dataURL) {
      document.body.style.backgroundImage = "url(" + dataURL + ")";
      document.body.classList.add("has-bg");
      if (!skipSave) {
        saveSetting("bg", dataURL);
      }
    } else {
      document.body.style.backgroundImage = "";
      document.body.classList.remove("has-bg");
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
    ensureAudio();
    if (!audioCtx) {
      return;
    }
    try {
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = "triangle";
      osc.frequency.value = 660;
      gain.gain.setValueAtTime(0.0001, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.12, audioCtx.currentTime + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.22);
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.24);
    } catch {
      // 忽略音频错误。
    }
  }

  function openLightbox(src) {
    if (!dom.lightbox) {
      return;
    }
    dom.lightboxImg.src = src;
    dom.lightbox.classList.remove("hidden");
  }

  function closeLightbox() {
    if (!dom.lightbox) {
      return;
    }
    dom.lightbox.classList.add("hidden");
    dom.lightboxImg.src = "";
  }

  function renderSelfAvatar() {
    if (!dom.selfAvatar || !state.self) {
      return;
    }
    dom.selfAvatar.textContent = shortID(state.self.id).slice(0, 2);
    const hue = colorHue(state.self.id);
    dom.selfAvatar.style.background = "linear-gradient(135deg, hsl(" + hue + " 70% 38%), hsl(" + ((hue + 36) % 360) + " 78% 50%))";
  }

  // ---- 加密原语 ----

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

  function colorHue(id) {
    let hash = 0;
    for (let i = 0; i < id.length; i += 1) {
      hash = (hash * 31 + id.charCodeAt(i)) >>> 0;
    }
    return hash % 360;
  }

  function formatTime(date) {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function safeError(error) {
    return error && error.message ? String(error.message).slice(0, 120) : "未知错误";
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
