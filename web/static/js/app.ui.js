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
        shareHidden: true,
        screenSharing: false,
        remoteSharing: false,
        shareMinimized: false,
        shareTitle: "共享屏幕（仅对方可见）",
        inCall: false,
        remoteVoice: false,
        micMuted: false,
        callTitle: "发起语音通话",
        micTitle: "静音",
        sendDisabled: true,
        noteHidden: false,
        composerMenuOpen: false,
        themeOptions: [],
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

        get callActive() {
          return this.inCall || this.remoteVoice;
        },

        init() {
          actions.bind(this);
          this.$watch("search", (value) => actions.searchChanged(value));
          actions.boot();
          actions.sync();
        },
        sendText: actions.sendText,
        sendNote: actions.sendNote,
        pickFromMenu() {
          this.composerMenuOpen = false;
          actions.pickFile();
        },
        noteFromMenu() {
          this.composerMenuOpen = false;
          actions.sendNote();
        },
        select(key) {
          this.menuOpen = false;
          actions.select(key);
        },
        reconnect() {
          this.menuOpen = false;
          actions.reconnect();
        },
        createRoom() {
          this.menuOpen = false;
          actions.createRoom();
        },
        shareRoom: actions.shareRoom,
        pickFile: actions.pickFile,
        p2pClick: actions.p2pClick,
        toggleScreenShare: actions.toggleScreenShare,
        fullscreenRemote: actions.fullscreenRemote,
        pipRemote: actions.pipRemote,
        toggleVoice: actions.toggleVoice,
        toggleMute: actions.toggleMute,
        hangupVoice: actions.hangupVoice,
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
