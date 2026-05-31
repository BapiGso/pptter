(function () {
  "use strict";

  function createChatComponent(actions) {
    return function chat() {
      return {
        active: "group",
        search: "",
        conversations: [],
        hasPeers: false,
        messages: [],
        convoTitle: "群聊",
        statusText: "初始化",
        statusDotClass: "bg-warning",
        p2pHidden: true,
        p2pConnected: false,
        p2pTitle: "建立 P2P 直连（大文件）",
        sendDisabled: true,
        inputPlaceholder: "群聊消息，本地加密后发送",
        draft: "",
        settingsOpen: false,
        aboutOpen: false,
        menuOpen: false,
        lightboxOpen: false,
        lightboxSrc: "",
        toastShown: false,
        toastText: "",
        nick: "",
        theme: "pptter",
        soundOn: true,
        tone: "soft",
        stun: "",
        fingerprint: "—",
        selfAvatarText: "我",
        selfAvatarClass: "avatar-sprite avatar-pos-0",
        isDark: false,
        backgroundImage: "",

        init() {
          actions.bind(this);
          this.$watch("search", (value) => actions.searchChanged(value));
          actions.boot();
          actions.sync();
        },
        sendText: actions.sendText,
        select(key) {
          this.menuOpen = false;
          actions.select(key);
        },
        reconnect() {
          this.menuOpen = false;
          actions.reconnect();
        },
        pickFile: actions.pickFile,
        p2pClick: actions.p2pClick,
        onFileInput: actions.onFileInput,
        dropFile: actions.dropFile,
        pasteFile: actions.pasteFile,
        openSettings() {
          this.settingsOpen = true;
          this.menuOpen = false;
        },
        saveSound: actions.saveSound,
        onBgFile: actions.onBgFile,
        resetBackground: actions.resetBackground,
        saveNick: actions.saveNick,
        applyTheme: actions.applyTheme,
        saveTone: actions.saveTone,
        testTone: actions.testTone,
        saveStun: actions.saveStun,
        openAbout() {
          this.aboutOpen = true;
          this.menuOpen = false;
          void actions.fingerprint().then((fingerprint) => { this.fingerprint = fingerprint; });
        },
        toggleTheme: actions.toggleTheme,
        ensureAudio: actions.ensureAudio,
        showImage(src) {
          this.lightboxSrc = src;
          this.lightboxOpen = true;
        },
        cancelTransfer: actions.cancelTransfer,
        retryTransfer: actions.retryTransfer,
        scrollLatest() {
          // 读取 messages 让 x-effect 追踪它：每次新消息（数组替换/增减）都重新滚到底部。
          const tracked = this.messages.length;
          void tracked;
          this.$nextTick(() => {
            const messages = this.$refs.messages;
            if (messages) {
              messages.scrollTop = messages.scrollHeight;
            }
          });
        },
      };
    };
  }

  window.PPTTERUI = {
    createChatComponent,
  };
})();
