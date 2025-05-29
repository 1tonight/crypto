'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // per-user connection state
    this.certs = {} // username -> certificate
    this.EGKeyPair = null // our own ECDH keypair
    this.username = null // our own username
    this.cert = null // our own certificate
  }

  async generateCertificate (username) {
    this.EGKeyPair = await generateEG()
    this.username = username
    this.cert = {
      username: username,
      pub: await cryptoKeyToJSON(this.EGKeyPair.pub)
    }
    return this.cert
  }

  async receiveCertificate (certificate, signature) {
    const certString = JSON.stringify(certificate)
    const valid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!valid) throw new Error('Invalid certificate signature')
    this.certs[certificate.username] = certificate
    if (!this.conns[certificate.username]) {
      this.conns[certificate.username] = {
        theirCert: certificate,
        theirPub: null,
        sending: null,
        receiving: null,
        sendCount: 0,
        recvCount: 0,
        recvIVs: new Set(),
        skipped: {}, // {pubKeyStr: {msgNum: mk}}
        lastRecvDH: null,
        lastSendDH: null,
        lastRecvHeader: null,
        lastSendHeader: null
      }
    }
    this.conns[certificate.username].theirPub = await this._importPubKey(certificate.pub)
  }

  async sendMessage (name, plaintext) {
    if (!this.conns[name]) throw new Error('No certificate for recipient')
    const conn = this.conns[name]
    if (!conn.sending) {
      conn.sending = await computeDH(this.EGKeyPair.sec, conn.theirPub)
      conn.sendCount = 0
      conn.lastSendDH = this.EGKeyPair.pub
    }
    const [nextSending, mk] = await HKDF(conn.sending, conn.sending, 'ratchet-str')
    conn.sending = nextSending
    conn.sendCount += 1
    const iv = genRandomSalt()
    const govEphemeral = await generateEG()
    const govDH = await computeDH(govEphemeral.sec, this.govPublicKey)
    const govAES = await HMACtoAESKey(govDH, govEncryptionDataStr)
    const mkBuf = await HMACtoAESKey(mk, 'msg-key', true)
    const ivGov = genRandomSalt()
    const cGov = await encryptWithGCM(govAES, mkBuf, ivGov)
    const header = {
      sender: this.username,
      receiver: name,
      senderPub: await cryptoKeyToJSON(this.EGKeyPair.pub),
      receiverPub: await cryptoKeyToJSON(conn.theirPub),
      senderIV: Array.from(iv),
      msgNum: conn.sendCount,
      vGov: await cryptoKeyToJSON(govEphemeral.pub),
      cGov: Array.from(new Uint8Array(cGov)),
      ivGov: Array.from(ivGov),
      receiverIV: null
    }
    const headerForAD = { ...header }
    delete headerForAD.receiverIV
    const ad = JSON.stringify(headerForAD)
    const ct = await encryptWithGCM(mk, plaintext, iv, ad)
    header.receiverIV = Array.from(iv)
    conn.lastSendHeader = header
    return [header, ct]
  }


  async receiveMessage (name, [header, ciphertext]) {
    if (header.receiver !== this.username) throw new Error('Not intended recipient')
    if (!this.conns[name]) throw new Error('No certificate for sender')
    const conn = this.conns[name]
    const ivKey = JSON.stringify(header.receiverIV)
    if (conn.recvIVs.has(ivKey)) throw new Error('Replay detected')
    conn.recvIVs.add(ivKey)
    const senderPub = await this._importPubKey(header.senderPub)
    const senderPubStr = JSON.stringify(header.senderPub)
    // Initialize skipped if needed
    if (!conn.skipped[senderPubStr]) conn.skipped[senderPubStr] = {}
    // DH ratchet step if new senderPub
    if (!conn.lastRecvDH || JSON.stringify(await cryptoKeyToJSON(conn.lastRecvDH)) !== senderPubStr) {
      conn.receiving = await computeDH(this.EGKeyPair.sec, senderPub)
      conn.recvCount = 0
      conn.lastRecvDH = senderPub
    }
    // Nếu đã có mk bị bỏ qua (out-of-order), dùng luôn
    if (conn.skipped[senderPubStr][header.msgNum]) {
      const mk = conn.skipped[senderPubStr][header.msgNum]
      delete conn.skipped[senderPubStr][header.msgNum]
      const headerForAD = { ...header }
      delete headerForAD.receiverIV
      const ad = JSON.stringify(headerForAD)
      let pt
      try {
        pt = await decryptWithGCM(mk, ciphertext, new Uint8Array(header.receiverIV), ad)
      } catch (e) {
        throw new Error('Decryption failed')
      }
      return bufferToString(pt)
    }
    // Nếu msgNum < recvCount, không có key thì lỗi
    if (header.msgNum <= conn.recvCount) {
      throw new Error('Message already processed or too old')
    }
    // Advance ratchet để đến đúng msgNum, lưu các mk bị bỏ qua
    let mk
    while (conn.recvCount < header.msgNum - 1) {
      const [nextReceiving, skippedMk] = await HKDF(conn.receiving, conn.receiving, 'ratchet-str')
      conn.receiving = nextReceiving
      conn.recvCount += 1
      conn.skipped[senderPubStr][conn.recvCount] = skippedMk
    }
    // Derive mk cho message hiện tại
    const [nextReceiving, thisMk] = await HKDF(conn.receiving, conn.receiving, 'ratchet-str')
    conn.receiving = nextReceiving
    conn.recvCount += 1
    mk = thisMk
    const headerForAD = { ...header }
    delete headerForAD.receiverIV
    const ad = JSON.stringify(headerForAD)
    let pt
    try {
      pt = await decryptWithGCM(mk, ciphertext, new Uint8Array(header.receiverIV), ad)
    } catch (e) {
      throw new Error('Decryption failed')
    }
    return bufferToString(pt)
  }


  async _importPubKey (jwk) {
    return await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    )
  }
}
module.exports = {
  MessengerClient
}