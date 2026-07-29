// Сквозное шифрование чата: ECDH P-256 + AES-256-GCM (Web Crypto API).
// Приватный ключ никогда не покидает браузер — на сервер уходит только публичный ключ и шифротекст.

const ChatCrypto = {
  b64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  },
  unb64(s) {
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
  },

  // Создать (или загрузить из localStorage) свою пару ключей
  async loadOrCreateKeyPair(storageKey) {
    const saved = localStorage.getItem(storageKey);
    if (saved) {
      try {
        const jwks = JSON.parse(saved);
        const priv = await crypto.subtle.importKey('jwk', jwks.priv,
          { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
        return { priv, pubJwk: jwks.pub };
      } catch (_) { /* повреждённый ключ — создаём новый */ }
    }
    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
    const privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
    const pubJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    localStorage.setItem(storageKey, JSON.stringify({ priv: privJwk, pub: pubJwk }));
    return { priv: kp.privateKey, pubJwk };
  },

  // Общий секретный ключ: мой приватный + публичный собеседника
  async deriveSharedKey(myPriv, theirPubJwk) {
    const theirPub = await crypto.subtle.importKey('jwk',
      { ...theirPubJwk, key_ops: [] },
      { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: theirPub }, myPriv,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  },

  async encrypt(sharedKey, text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sharedKey,
      new TextEncoder().encode(text));
    return { iv: this.b64(iv), ciphertext: this.b64(ct) };
  },

  async decrypt(sharedKey, ivB64, ctB64) {
    try {
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: this.unb64(ivB64) },
        sharedKey, this.unb64(ctB64));
      return new TextDecoder().decode(pt);
    } catch (_) {
      return null; // не расшифровалось (другой ключ / другое устройство)
    }
  },

  exportKeyBackup(storageKey) {
    return localStorage.getItem(storageKey);
  },

  importKeyBackup(storageKey, backup) {
    const jwks = JSON.parse(backup);
    if (!jwks.priv || !jwks.pub) throw new Error('Некорректная резервная копия ключа');
    localStorage.setItem(storageKey, backup);
  },
};
