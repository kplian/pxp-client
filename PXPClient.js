/**
 * Pxp Rest client v2
 * Connect with pxp framework php 7 version
 * @author : Jaime Rivera, Favio Figueroa
 * @example
 * // create client:
 * const x = new PXPClient('3.101.135.201', 'kerp/pxp/lib/rest', 'cors');
 * @example
 * // authenticate
 * const prom = x.authenticate('admin', 'admin');
 * prom.then(data => {
 *   console.log('2:',data);
 * });
 * @example
 * // doRequest
 * fetch(x.request({
 *       url: 'seguridad/Usuario/listarUsuario',
 *       params: {
 *           start: 0,
 *           limit: 1000
 *       }
 *   }))
 *   .then(response => response.json())
 *   .then(data => console.log(data))
 *   .catch(err => console.log('error', err));
 *
 * @webSocket
 * the websocket is initialized when the login has been correct
 * for listening some event you need to import webSocketListener
 * @example
 * webSocketListener({event:'testWebsocket',idComponent:uuidv4(), handle: (e)=> {handleOnMessage(e)}});
 * for sending message for some event you need to import sendMessageWs
 * @example
 * sendMessageWs({
 *                 event: 'testWebsocket',
 *                 msg: 'test msg'
 *              });
 */

import md5 from 'crypto-js/md5';
import AES from 'crypto-js/aes';
import CryptoJS from 'crypto-js';
import Base64 from 'crypto-js/enc-base64';
import Utf8 from 'crypto-js/enc-utf8';
import Hex from 'crypto-js/enc-hex';
import { v4 as uuidv4 } from 'uuid';

class Encryption {
  /**
   * @var integer Return encrypt method or Cipher method number. (128, 192, 256)
   */
  get encryptMethodLength() {
    var encryptMethod = this.encryptMethod;
    // get only number from string.
    // @link https://stackoverflow.com/a/10003709/128761 Reference.
    var aesNumber = encryptMethod.match(/\d+/)[0];
    return parseInt(aesNumber);
  }// encryptMethodLength


  /**
   * @var integer Return cipher method divide by 8. example: AES number 256 will be 256/8 = 32.
   */
  get encryptKeySize() {
    var aesNumber = this.encryptMethodLength;
    return parseInt(aesNumber / 8);
  }// encryptKeySize


  /**
   * @link http://php.net/manual/en/function.openssl-get-cipher-methods.php Refer to available methods in PHP if we are working between JS & PHP encryption.
   * @var string Cipher method.
   *              Recommended AES-128-CBC, AES-192-CBC, AES-256-CBC
   *              due to there is no `openssl_cipher_iv_length()` function in JavaScript
   *              and all of these methods are known as 16 in iv_length.
   */
  get encryptMethod() {
    return 'AES-256-CBC';
  }// encryptMethod


  /**
   * Decrypt string.
   *
   * @link https://stackoverflow.com/questions/41222162/encrypt-in-php-openssl-and-decrypt-in-javascript-cryptojs Reference.
   * @link https://stackoverflow.com/questions/25492179/decode-a-base64-string-using-cryptojs Crypto JS base64 encode/decode reference.
   * @param string encryptedString The encrypted string to be decrypt.
   * @param string key The key.
   * @return string Return decrypted string.
   */
  decrypt(encryptedString, key) {
    var json = JSON.parse(Utf8.stringify(Base64.parse(encryptedString)));

    var salt = Hex.parse(json.salt);
    var iv = Hex.parse(json.iv);

    var encrypted = json.ciphertext;// no need to base64 decode.

    var iterations = parseInt(json.iterations);
    if (iterations <= 0) {
      iterations = 999;
    }
    var encryptMethodLength = (this.encryptMethodLength / 4);// example: AES number is 256 / 4 = 64
    var hashKey = CryptoJS.PBKDF2(key, salt, { 'hasher': CryptoJS.algo.SHA512, 'keySize': (encryptMethodLength / 8), 'iterations': iterations });

    var decrypted = AES.decrypt(encrypted, hashKey, { 'mode': CryptoJS.mode.CBC, 'iv': iv });

    return decrypted.toString(Utf8);
  }// decrypt


  /**
   * Encrypt string.
   *
   * @link https://stackoverflow.com/questions/41222162/encrypt-in-php-openssl-and-decrypt-in-javascript-cryptojs Reference.
   * @link https://stackoverflow.com/questions/25492179/decode-a-base64-string-using-cryptojs Crypto JS base64 encode/decode reference.
   * @param string string The original string to be encrypt.
   * @param string key The key.
   * @return string Return encrypted string.
   */
  encrypt(string, key) {
    var iv = CryptoJS.lib.WordArray.random(16);// the reason to be 16, please read on `encryptMethod` property.

    var salt = CryptoJS.lib.WordArray.random(256);
    var iterations = 999;
    var encryptMethodLength = (this.encryptMethodLength / 4);// example: AES number is 256 / 4 = 64
    var hashKey = CryptoJS.PBKDF2(key, salt, { 'hasher': CryptoJS.algo.SHA512, 'keySize': (encryptMethodLength / 8), 'iterations': iterations });

    var encrypted = AES.encrypt(string, hashKey, { 'mode': CryptoJS.mode.CBC, 'iv': iv });
    var encryptedString = Base64.stringify(encrypted.ciphertext);

    var output = {
      'ciphertext': encryptedString,
      'iv': Hex.stringify(iv),
      'salt': Hex.stringify(salt),
      'iterations': iterations
    };

    return Base64.stringify(Utf8.parse(JSON.stringify(output)));
  }// encrypt
}

import { Base64 as Base64V1 } from './js/base64.js';
import { mcrypt } from './js/mcrypt.js';

class EncryptionV1 {

  fnEncrypt($sValue, $sSecretKey) {

    return Base64V1.encode(mcrypt.Encrypt($sValue, undefined, $sSecretKey, 'rijndael-256', 'ecb'));
  }

  uniqId(prefix, more_entropy) {
    //  discuss at: http://phpjs.org/functions/uniqid/
    // original by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
    //  revised by: Kankrelune (http://www.webfaktory.info/)
    //        note: Uses an internal counter (in php_js global) to avoid collision
    //        test: skip
    //   example 1: uniqid();
    //   returns 1: 'a30285b160c14'
    //   example 2: uniqid('foo');
    //   returns 2: 'fooa30285b1cd361'
    //   example 3: uniqid('bar', true);
    //   returns 3: 'bara20285b23dfd1.31879087'

    if (typeof prefix === 'undefined') {
      prefix = '';
    }

    let retId;
    const formatSeed = function (seed, reqWidth) {
      seed = parseInt(seed, 10)
        .toString(16); // to hex str
      if (reqWidth < seed.length) { // so long we split
        return seed.slice(seed.length - reqWidth);
      }
      if (reqWidth > seed.length) { // so short we pad
        return Array(1 + (reqWidth - seed.length))
          .join('0') + seed;
      }
      return seed;
    };

    // BEGIN REDUNDANT
    if (!this.php_js) {
      this.php_js = {};
    }
    // END REDUNDANT
    if (!this.php_js.uniqidSeed) { // init seed with big random int
      this.php_js.uniqidSeed = Math.floor(Math.random() * 0x75bcd15);
    }
    this.php_js.uniqidSeed++;

    retId = prefix; // start with prefix, add current milliseconds hex string
    retId += formatSeed(parseInt(new Date()
      .getTime() / 1000, 10), 8);
    retId += formatSeed(this.php_js.uniqidSeed, 5); // add seed hex string
    if (more_entropy) {
      // for more entropy we add a float lower to 10
      retId += (Math.random() * 10)
        .toFixed(8)
        .toString();
    }

    return retId;
  }

  encrypt(user, pass) {
    const prefix = this.uniqId('pxp');
    this._user = this.fnEncrypt(prefix + '$$' + user, pass);

    return this._user
  }


}

class PXPClient {
  constructor() {
    if (!PXPClient.instance) {
      PXPClient.instance = this;
    }
    return PXPClient.instance;
  }

  init(host, baseUrl = 'rest/', mode = 'same-origin', port = '80', protocol = 'http', backendRestVersion = '2', initWebSocket = 'NO', portWs = '8010', backendVersion = 'v1') {
    this.host = host;
    this.baseUrl = baseUrl;
    this.session = baseUrl;
    this.port = port;
    this.protocol = protocol;
    this.mode = mode;
    this.backendRestVersion = backendRestVersion;
    this.sessionDied = false;
    this._authenticated = localStorage.aut ? JSON.parse(localStorage.aut) : false;
    this.authenticatedListener = (val) => { };
    this.initWebSocket = initWebSocket; // this is a flag YES OR NO for init the websocket
    this.portWs = portWs;
    this.eventsWs = {};
    this.backendVersion = backendVersion; // this is for see if is php pxp version or node pxp version


    this.onCloseWebSocketListener = (val) => { };
  }

  get authenticated() {
    return this._authenticated;
  }

  set authenticated(val) {
    this._authenticated = val;
    console.log('_authenticated', val)
    if (!val) {
      delete localStorage.aut;
    } else {
      localStorage.aut = JSON.stringify(val);
    }
    this.authenticatedListener(val);
  }

  onCloseWebSocket(callBack) {
    this.onCloseWebSocketListener = callBack;
  }

  onAuthStateChanged(callBack) {
    this.authenticatedListener = callBack;
    if (this.initWebSocket === 'YES') {
      if (this._authenticated === false) {
        this.authenticatedListener(this._authenticated);
      } else {
        this.initClientWebSocket(this._authenticated)
          .then(success => {
            if (success) {
              this.authenticatedListener(this._authenticated);
            }
          })
          .catch(error => alert(error))
      }

    } else {
      this.authenticatedListener(this._authenticated);
    }
  }

  login(user, pass, language = '') {
    this.user = user.normalize("NFD").replace(/[\u0300-\u036f]/g, "");//remove accents from user
    const md5Pass = md5(pass).toString();
    this.sessionDied = false;
    let encrypted;
    const deviceID = localStorage.deviceID || '';
    if (parseInt(this.backendRestVersion, 10) === 1) {
      const enc = new EncryptionV1();
      encrypted = enc.encrypt(this.user, md5Pass);
    } else {

      this.prefix = uuidv4();
      const enc = new Encryption();
      encrypted = enc.encrypt(this.prefix + '$$' + this.user, md5Pass);
    }


    const request = this.request({
      url: this.backendVersion === 'v1' ? 'seguridad/Auten/verificarCredenciales' : 'auth/login',
      ...(this.backendVersion === 'v1' ? {
        headers: {
          'Pxp-user': this.user,
          'auth-version': this.backendRestVersion,
          'Php-Auth-User': encrypted,
          'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
      } : {
          headers: {
            'Content-Type': 'application/json',
            //'Access-Control-Allow-Origin': '*'
          }
        }),
      ...(this.backendVersion === 'v1' ? { params: { language, deviceID } } : { params: { username: user, password: pass } }),
    });
    return fetch(request)
      .then(response => response.json())
      .then(data => {
        const error = data.ROOT ? data.ROOT.error : false;
        if (!error) {
          //this.initWebsocket(data);
          console.log('this.initWebSocket', this.initWebSocket)
          if (this.initWebSocket === 'YES') {
            this.initClientWebSocket(data)
              .then(success => {
                if (success) {
                  this.authenticated = {
                    ...data,
                    user: this.user,
                    userId: (data.id_usuario || data.userId),
                    username: (data.nombre_usuario || data.userId)
                  };
                }
              })
              .catch(error => alert(error))
          } else {
            this.authenticated = {
              ...data,
              user: this.user,
              userId: (data.id_usuario || data.userId),
              username: (data.nombre_usuario || data.username)
            };
          }

        }
        return { ...data, user };
      })
      .catch(err => console.log('error', err));
  }

  oauthLogin(userId, token, name, surname, email, urlPhoto, type, device, language = '') {
    this.user = email;
    this.sessionDied = false;
    const deviceID = localStorage.deviceID || '';
    const request = this.request({
      url: 'seguridad/Auten/oauthLogin',
      params: {
        user_id: userId,
        token,
        name,
        surname,
        email,
        url_photo: urlPhoto,
        type,
        device,
        language,
        deviceID,
      },
    });
    return fetch(request)
      .then(response => response.json())
      .then(data => {
        const error = data.ROOT ? data.ROOT.error : false;
        if (!error) {
          if (this.initWebSocket === 'YES') {
            this.initClientWebSocket(data)
              .then(success => {
                if (success) {
                  this.authenticated = { ...data, ...{ user: email } };
                }
              })
              .catch(error => alert(error))
          } else {
            this.authenticated = { ...data, ...{ user: email } };
          }
        }
        return { ...data, ...{ user: email } };
      })
      .catch(err => console.log('error', err));
  }

  createTokenUser({ name, surname, email, token, url_photo, login_type }) {
    const request = this.request({
      url: 'seguridad/Auten/createTokenUser',
      params: {
        name,
        surname,
        email,
        token,
        url_photo,
        login_type
      },
    });
    return fetch(request)
      .then(response => response.json())
      .then(data => {
        return data;
      })
      .catch(err => console.log('error', err));
  }
  logout() {
    this.sessionDied = false;
    const deviceID = localStorage.deviceID || '';
    const request = this.request({
      url: 'seguridad/Auten/cerrarSesion',
      params: { deviceID },
    });
    return fetch(request)
      .then(response => response.json())
      .then(data => {
        this.authenticated = false;
        this.webSocket && this.webSocket.close();
        return data;
      })
      .catch(err => console.log('error', err));
  }
  request(obj) {
    const headers = obj.headers || {};
    let params = '';
    if (obj.params && obj.type !== 'upload') {
      if (this.backendVersion === 'v1') {
        params = this.encodeFormData(obj.params);
      } else {
        if (obj.method === 'GET') {
          params = this.encodeFormData(obj.params);
        } else {
          params = JSON.stringify(obj.params);
        }
      }
    }
    if (obj.type === 'upload') {
      params = obj.params;
    }
    let urlRequest = `${this.protocol}://${this.host}:${this.port}/${this.baseUrl}/${obj.url}`;
    if (obj.method === 'GET') {
      urlRequest = `${urlRequest}?${params}`;
    }
    return new Request(
      urlRequest,
      {
        method: obj.method || 'POST',
        mode: this.mode,
        ...(obj.type !== 'upload' && {
          headers: {
            ...headers,
            ...(this.backendVersion === 'v2' && { 'Content-Type': 'application/json' }),
          },
        }),
        cache: 'no-cache',
        //...(this.backendVersion === 'v1' && { credentials: 'include' }),
        credentials: 'include',
        ...(obj.method !== 'GET' && { body: params }),
        redirect: 'follow'
      }
    );
  }
  doRequest(obj) {
    const request = this.request(obj);

    return fetch(request)
      .then(response => {
        if (response.status === 401) {
          this.sessionDied = true;
          this.authenticated = false;
        }
        return response.json()
      })
      .then(data => {
        if (data.ROOT) {
          return {
            error: data.ROOT.error,
            detail: data.ROOT.detalle ? {
              message: data.ROOT.detalle.mensaje,
              tecMessage: data.ROOT.detalle.mensaje_tec || undefined,
              origin: data.ROOT.detalle.origen || undefined,
              procedure: data.ROOT.detalle.procedimiento || undefined,
              transaction: data.ROOT.detalle.transaccion || undefined,
              layer: data.ROOT.detalle.capa || undefined,
              query: data.ROOT.detalle.consulta || undefined
            } : {},
            data: data.ROOT.datos
          }
        }
        return data
      })
      .catch(err => console.log('error', err));
  }

  encodeFormData(data) {
    return Object.keys(data)
      .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(data[key]))
      .join('&');
  }



  initClientWebSocket(data) {
    console.log('initClientWebSocket........', data)

    return new Promise((resolve, reject) => {
      const json = JSON.stringify({
        data: { "id_usuario": data.id_usuario },
        tipo: "registrarUsuarioSocket"
      });
      const ws = this.protocol === 'https' ? 'wss' : 'ws';
      const folderWss = ws === 'wss' ? 'wss' : '';
      this.webSocket = new WebSocket(`${ws}://${this.host}:${this.portWs}/${folderWss}?sessionIDPXP=${data.phpsession}`);
      console.log(`${ws}://${this.host}:${this.portWs}?sessionIDPXP=${data.phpsession}`)
      this.webSocket.onopen = () => {
        this.webSocket.send(json);
        console.log('webSocket has been initialized')
        resolve(true);
      };
      this.eventsWs = {};
      this.webSocket.onmessage = ev => {
        const response = JSON.parse(ev.data);
        //config for send the msg
        const data = response.data;

        if (data.tipo == 'respuesta de envio') {
          // resp for user that has sent the message
        } else { // msg has to execute an event
          if (data.id_contenedor !== undefined) {
            this.eventsWs[data.id_usuario + '_' + data.id_contenedor + '_' + data.evento].handle(response);
          } else {
            //todo events into of class for message or alerts in all app
          }
        }
      }
      this.webSocket.onclose = e => {
        console.log('webSocket has closed');
        if (this.authenticated !== false) {
          this.onCloseWebSocketListener(e);
        }
        //location.reload();
      }
      this.webSocket.onerror = error => resolve(false);
    })
  }


  webSocketListener(obj) {
    //console.log(this.webSocket.readyState)
    this.eventsWs[this._authenticated.id_usuario + '_' + obj.idComponent + '_' + obj.event] = {
      handle: obj.handle
    };
    const json = JSON.stringify({
      data: {
        id_usuario: this._authenticated.id_usuario,
        nombre_usuario: this._authenticated.nombre_usuario,
        evento: obj.event,
        id_contenedor: obj.idComponent,
        metodo: 'obj.handle' // change that because now we are using handle directly for executing
      },
      tipo: 'escucharEvento'

    });
    this.webSocket.send(json);

  }

  removeWebSocketListener({ idComponent, event }) {
    this.eventsWs[this._authenticated.id_usuario + '_' + idComponent + '_' + event] = undefined;
    console.log(this.eventsWs)
    const json = JSON.stringify({
      data: {
        id_contenedor: idComponent,
        evento: event,
      },
      tipo: 'eleminarEvento'

    });
    this.webSocket.send(json);

  }

  sendMessageWs(obj) {
    console.log(obj)
    const json = JSON.stringify({
      tipo: 'enviarMensaje',
      data: {
        evento: obj.event,
        mensaje: obj.msg
      },
      from: {
        user: this._authenticated.nombre_usuario,
        idUser: this._authenticated.id_usuario
      },
      idChat: obj.idChat || null
    });
    this.webSocket.send(json);
  }

}

const connection = new PXPClient();
export default connection;
export const webSocketListener = (obj) => { connection.webSocketListener(obj) };
export const removeWebSocketListener = ({ idComponent, event }) => { connection.removeWebSocketListener({ idComponent, event }) };
export const sendMessageWs = (obj) => { connection.sendMessageWs(obj) };
export const onCloseWebSocket = (callback) => { connection.onCloseWebSocket(callback) };


