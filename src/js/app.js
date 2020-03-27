/* global atob, Buffer, TextDecoder, BUILD_VERSION, TextEncoder */

import 'bootstrap';
import $ from "jquery";
import jose from "node-jose";
import NodeRSA from "node-rsa";
const requiredKeys = ['algorithm', 'keyId', 'headers', 'signature'];

const ITERATION_DEFAULT = 8192,
      ITERATION_MAX = 100001,
      ITERATION_MIN = 50;

function subtleCryptoAlgorithm(alg) {
  if (alg =='rsa-sha256') {
    return "RSASSA-PKCS1-v1_5";
  }
  if (alg =='hmac-sha256') {
    return "HMAC";
  }
  return "null";
}
function reformIndents(s) {
  let s2 = s.split(new RegExp('\n', 'g'))
    .map(s => s.trim())
    .join("\n");
  return s2.trim();
}

function handlePaste(e) {
  let elt = this;
  setTimeout(function () {
    var text = reformIndents($(elt).val());
    $(elt).val(text);
  }, 100);
}

function getPbkdf2IterationCount() {
  let icountvalue = $('#ta_pbkdf2_iterations').val(),
      icount = ITERATION_DEFAULT;
  try {
    icount = Number.parseInt(icountvalue, 10);
  }
  catch (exc1) {
    setAlert("not a number? defaulting to iteration count: "+ icount);
  }
  if (icount > ITERATION_MAX || icount < ITERATION_MIN) {
    icount = ITERATION_DEFAULT;
    setAlert("iteration count out of range. defaulting to: "+ icount);
  }
  return icount;
}

function getPbkdf2SaltBuffer() {
  let keyvalue = $('#ta_pbkdf2_salt').val();
  let coding = $('.sel-symkey-pbkdf2-salt-coding').find(':selected').text().toLowerCase();
  let knownCodecs = ['utf-8', 'base64', 'hex'];

  if (knownCodecs.indexOf(coding)>=0) {
    return Buffer.from(keyvalue, coding);
  }
  throw new Error('unsupported salt encoding'); // will not happen
}

async function getSymmetricKeyBuffer() {
  let keyvalue = $('#ta_symmetrickey').val();
  let coding = $('.sel-symkey-coding').find(':selected').text().toLowerCase();
  let knownCodecs = ['utf-8', 'base64', 'hex'];

  if (knownCodecs.indexOf(coding)>=0) {
    return Promise.resolve(Buffer.from(keyvalue, coding));
  }

  if (coding == 'pbkdf2') {
    let kdfParams = {
          salt: getPbkdf2SaltBuffer(),
          iterations: getPbkdf2IterationCount(),
          length: 256 / 8
        };
    return jose.JWA.derive("PBKDF2-SHA-256", Buffer.from(keyvalue, 'utf-8'), kdfParams);
  }

  throw new Error('unknown key encoding: ' + coding);  // will not happen
}

function getPrivateKey() {
  return $('#ta_privatekey').val();
}

function getPublicKey() {
  return $('#ta_publickey').val();
}

function copyToClipboard(event) {
  let $elt = $(this),
      sourceElement = $elt.data('target'),
      // grab the element to copy
      $source = $('#' + sourceElement),
      // Create a temporary hidden textarea.
      $temp = $("<textarea>");

  //let textToCopy = $source.val();
  // in which case do I need text() ?
  let textToCopy = ($source[0].tagName == 'TEXTAREA' || $source[0].tagName == 'INPUT') ? $source.val() : $source.text();

  $("body").append($temp);
  $temp.val(textToCopy).select();
  let success;
  try {
    success = document.execCommand("copy");
    if (success) {
      // Animation to indicate copy.
      // CodeMirror obscures the original textarea, and appends a div as the next sibling.
      // We want to flash THAT.
      let $cmdiv = $source.next();
      if ($cmdiv.length>0 && $cmdiv.prop('tagName').toLowerCase() == 'div' && $cmdiv.hasClass('CodeMirror')) {
        $cmdiv.addClass('copy-to-clipboard-flash-bg')
          .delay('1000')
          .queue( _ => $cmdiv.removeClass('copy-to-clipboard-flash-bg').dequeue() );
      }
      else {
        // no codemirror (probably the secretkey field, which is just an input)
        $source.addClass('copy-to-clipboard-flash-bg')
          .delay('1000')
          .queue( _ => $source.removeClass('copy-to-clipboard-flash-bg').dequeue() );
      }
    }
  }
  catch (e) {
    success = false;
  }
  $temp.remove();
  return success;
}

function checkKeyLength(alg, keybuffer) {
  const length = keybuffer.byteLength,
        requiredLength = 256 / 8;
  if (length >= requiredLength) return Promise.resolve(keybuffer);
  return Promise.reject(new Error('insufficient key length. You need at least ' + requiredLength + ' chars for ' + alg));
}

function getStringToSign(headers, ordering) {
  let list = (ordering) ? ordering.split(' ') : Object.keys(headers);
  return list
        .map(hdrName => hdrName.toLowerCase() + ': ' + headers[hdrName])
        .join('\n');
}

function getHeaders() {
  let text = $('#ta_headerlist').val(),
      re2 = new RegExp('^(.+?):(.+)$'),
      onNewlines = new RegExp('(\r\n|\n)', 'g'),
      headers = {};
  text
    .split(onNewlines)
    .forEach(line => {
      if (line.trim().length > 3) {
        let match = re2.exec(line);
        if (match && match.length == 3) {
          let hname = match[1].trim().toLowerCase();
          headers[hname] = match[2].trim();
        }
      }
    });
  return headers;
}

function generateSignature(event) {
  let headers = getHeaders(),
      alg = $('.sel-alg').find(':selected').text(),
      p = null;
  if (alg == 'hmac-sha256') {
    p = getSymmetricKeyBuffer(alg)
      .then( keyBuffer => checkKeyLength(alg, keyBuffer))
      .then( keyBuffer => window.crypto.subtle.importKey("raw", keyBuffer, {name:"HMAC", hash: "SHA-256"}, false, ['sign', 'verify']));
  }
  else if (alg == 'rsa-sha256') {
    let keydata = pem2bin(getPrivateKey());
    p = window.crypto.subtle.importKey("pkcs8", keydata, {name:"RSASSA-PKCS1-v1_5", hash: "SHA-256"}, false, ['sign']);
  }
  else {
    throw new Error('unsupported algorithm');
  }

  p = p
    .then( signingKey => {
      const stringToSign = getStringToSign(headers);
      const buf = new TextEncoder().encode(stringToSign);
      return window.crypto.subtle.sign(subtleCryptoAlgorithm(alg), signingKey, buf);
    })
    .then(signatureData => {
      return window.btoa(String.fromCharCode(...new Uint8Array(signatureData)));
    });

  return p
    .then( signature => {
      $('#ta_signature').val(signature);
      let headerList = Object.keys(headers).join(' ');
      let hdr = `Signature keyId="test", algorithm="${alg}", headers="${headerList}", signature="${signature}"`;
      $('#ta_httpsigheader').val(hdr);
    })
    .catch( e => {
      console.log(e.stack);
      setAlert(e);
    });
}


const ParseState = {
      BEGIN : 0,
      NAME : 1,
      VALUE : 2,
      COMMA : 3,
      QUOTE : 4,
      INTEGER : 5
    };

function parseHttpSigHeader(str) {
  str = str.trim();
  const re1 = new RegExp('^Signature +(.+)$');
  let m = re1.exec(str);
  if ( ! m || !m[1]) {
    throw new Error("malformed Signature header?");
  }
  const checkNameChar = function(c) {
          var code = c.charCodeAt(0);
          if ((code >= 0x41 && code <= 0x5a) || // A-Z
              (code >= 0x61 && code <= 0x7a)) { // a-z
          }
          else if (code == 0x20) {
            throw new Error('invalid whitespace before parameter name');
          }
          else {
            throw new Error('invalid parameter name');
          }
        };
  const checkIntegerChar = function(c) {
          var code = c.charCodeAt(0);
          if (code >= 0x30 && code <= 0x39) { // 0-9
          }
          else {
            throw new Error('invalid integer value');
          }
        };
  let content = m[1].trim(),
      state = ParseState.NAME,
      name = '',
      value = '',
      parsed = {},
      i = 0;
  do {
    var c = content.charAt(i);
    //console.log('state: ' + Number(state));
    switch (Number(state)) {

    case ParseState.NAME:
      if (c === '=') {
        if (parsed[name])
          throw new Error('duplicate auth-param at position ' + i);
        state = (name=='created' || name=='expires') ? ParseState.INTEGER : ParseState.QUOTE;
      }
      else if (c === ' ') {
        /* skip OWS between auth-params */
        if (name != '')
          throw new Error(`whitespace in name at position ${i}`);
      }
      else {
        checkNameChar(c);
        name += c;
      }
      break;

    case ParseState.INTEGER:
      if (c === ',') {
        // this must be a seconds-since-epoch  eg, 1402170695
        if (value.length != 10)
          throw new Error(`bad value (${value}) at posn ${i}`);
        state = ParseState.NAME;
        parsed[name] = value;
        name = '';
        value = '';
      }
      else {
        checkIntegerChar(c);
        value += c;
      }
      break;

    case ParseState.QUOTE:
      if (c === '"') {
        value = '';
        state = ParseState.VALUE;
      } else {
        throw new Error('expecting quote at position ' + i);
      }
      break;

    case ParseState.VALUE:
      if (name.length == 0)
        throw new Error('bad param name at posn ' + i);
      if (c === '"') {
        parsed[name] = value;
        state = ParseState.COMMA;
      } else {
        value += c;
      }
      break;

    case ParseState.COMMA:
      if (c === ',') {
        name = '';
        value = '';
        state = ParseState.NAME;
      } else {
        throw new Error('bad param format');
      }
      break;

    default:
      throw new Error('Invalid format at posn ' + i);
    }

    i++;
  } while (i < content.length);

  let requiredKeys = ['algorithm', 'keyId', 'headers', 'signature'];
  requiredKeys.forEach(key => {
    if ( ! parsed[key])
      throw new Error('missing ' + key);
  });

  let validKeys = requiredKeys.concat(['created','expires']);
  Object.keys(parsed).forEach(key => {
    if ( ! validKeys.includes(key))
      throw new Error('unsupported parameter: ' + key);
  });

  if ((parsed.algorithm != 'rsa-sha256') && (parsed.algorithm != 'hmac-sha256'))
    throw new Error('bad algorithm');

  return parsed;
}


function verifySignature(event) {
  try {
    const sigHeader = parseHttpSigHeader($('#ta_httpsigheader').val()),
          sigBytes = Buffer.from(sigHeader.signature, 'base64'),
          stringToSign = getStringToSign(getHeaders(), sigHeader.headers),
          data = new TextEncoder().encode(stringToSign);
    let p = null;
    if (sigHeader.algorithm == 'rsa-sha256') {
      let keydata = pem2bin(getPublicKey());
      p = window
        .crypto
        .subtle
        .importKey("spki", keydata, {name:"RSASSA-PKCS1-v1_5", hash: "SHA-256"}, false, ['verify'])
        .then(publicKey =>
              window.crypto.subtle.verify(
                "RSASSA-PKCS1-v1_5",
                publicKey, //from generateKey or importKey above
                sigBytes, //ArrayBuffer of the signature
                data //ArrayBuffer of the data
              ));
    }
    else if (sigHeader.algorithm == 'hmac-sha256') {
      p = getSymmetricKeyBuffer(sigHeader.algorithm)
        .then( keyBuffer => checkKeyLength(sigHeader.algorithm, keyBuffer))
        .then( keyBuffer =>
               window
               .crypto
               .subtle
               .importKey("raw", keyBuffer, {name:"HMAC", hash: "SHA-256"}, false, ['sign', 'verify']))
        .then(symmetricKey =>
              window.crypto.subtle.verify(
                "HMAC",
                symmetricKey, //from generateKey or importKey above
                sigBytes, //ArrayBuffer of the signature
                data //ArrayBuffer of the data
              ));
    }
    else {
      throw new Error('unknown algorithm');
    }
    p.then( isvalid =>
            (isvalid) ?
            setAlert('The signature is valid.', 'success') :
            setAlert('The signature is not valid', 'warning'));
  }
  catch (exc1) {
    setAlert('Incomplete or malformed HTTP Signature header');
    return;
  }
}



function setAlert(html, alertClass) {
  let buttonHtml = '<button type="button" class="close" data-dismiss="alert" aria-label="Close">\n' +
    ' <span aria-hidden="true">&times;</span>\n' +
    '</button>',
      $mainalert = $("#mainalert");
  $mainalert.html(html + buttonHtml);
  if (alertClass) {
    $mainalert.removeClass('alert-warning'); // this is the default
    $mainalert.addClass('alert-' + alertClass); // success, primary, warning, etc
  }
  else {
    $mainalert.addClass('alert-warning');
  }
  // show()
  $mainalert.removeClass('fade').addClass('show');
  setTimeout(() => $("#mainalert").addClass('fade').removeClass('show'), 5650);
}

function closeAlert(event){
  //$("#mainalert").toggle();
  $('#mainalert').removeClass('show').addClass('fade');
  return false; // Keep close.bs.alert event from removing from DOM
}

function updateKeyValue(flavor /* public || private */, keyvalue) {
  $('#ta_' + flavor + 'key').val(keyvalue);
}

function key2pem(flavor, keydata) {
  let body = window.btoa(String.fromCharCode(...new Uint8Array(keydata)));
  body = body.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${flavor} KEY-----\n${body}\n-----END ${flavor} KEY-----`;
}

function pem2bin(str) {
  if (str.indexOf("BEGIN RSA PRIVATE KEY")>0) {
    const key = new NodeRSA(str);
    return pkcs8pem2Binary(key.exportKey('pkcs8'));
  }
  return pkcs8pem2Binary(str);
}

function pkcs8pem2Binary(pem) { // pkcs8 only
  let encoded = pem
    .split('\n')
    .filter(line => line.indexOf('-----') < 0)
    .join('');
  let byteStr = atob(encoded);
  let bytes = new Uint8Array(byteStr.length);
    for (var i = 0; i < byteStr.length; i++) {
        bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes.buffer;
}

function getGenKeyParams(alg) {
  if (alg.startsWith('rsa')) return {
    name: "RSASSA-PKCS1-v1_5", // this name also works for RSA-PSS !
    modulusLength: 2048, //can be 1024, 2048, or 4096
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-256"}
  };
  throw new Error('invalid key flavor');
}

function newKeyPair(event) {
  let alg = $('.sel-alg').find(':selected').text();
  if (alg.startsWith('rsa')) {
    let keyUse = ["sign", "verify"], // irrelevant for our purposes (PEM Export)
        isExtractable = true,
        genKeyParams = getGenKeyParams(alg);
    return window.crypto.subtle.generateKey(genKeyParams, isExtractable, keyUse)
      .then(key => window.crypto.subtle.exportKey( "spki", key.publicKey )
            .then(keydata => updateKeyValue('public', key2pem('PUBLIC', keydata)) )
            .then( () => window.crypto.subtle.exportKey( "pkcs8", key.privateKey ))
            .then(keydata => updateKeyValue('private', key2pem('PRIVATE', keydata)) ))
      .then( () => {
        $('#mainalert').removeClass('show').addClass('fade');
    });
  }
}

function selectAlgorithm(algName) {
  let currentlySelectedAlg = $('.sel-alg').find(':selected').text().toLowerCase();
  if (algName.toLowerCase() != currentlySelectedAlg) {
    let $option = $('.sel-alg option[value="'+ algName +'"]');
    if ( ! $option.length) {
      $option = $('.sel-alg option[value="??"]');
    }
    $option
      .prop('selected', true)
      .trigger("change");
  }
}


function keysAreCompatible(alg1, alg2) {
  let prefix1 = alg1.substring(0, 2),
      prefix2 = alg2.substring(0, 2);
  if (['RS', 'PS'].indexOf(prefix1)>=0 &&
      ['RS', 'PS'].indexOf(prefix2)>=0 ) return true;
  if (prefix1 == 'ES') return alg1 == alg2;
  return false;
}


function changeSymmetricKeyCoding(event) {
  let $this = $(this),
      newSelection = $this.find(':selected').text().toLowerCase(),
      previousSelection = $this.data('prev');
  if (newSelection != previousSelection) {
    if (newSelection == 'pbkdf2') {
      // display the salt and iteration count
      $('#pbkdf2_params').show();
    }
    else {
      $('#pbkdf2_params').hide();
    }
  }
  $this.data('prev', newSelection);
}


function onChangeAlg(event) {
  let $this = $(this),
      newSelection = $this.find(':selected').text(),
      previousSelection = $this.data('prev'),
      headerObj = null;

  if (newSelection != previousSelection) {

    if (newSelection == 'hmac-sha256') {
      $('.btn-newkeypair').hide();
      $('#privatekey').hide();
      $('#publickey').hide();
      $('#symmetrickey').show();
    }
    else if (newSelection == 'rsa-sha256') {
      $('.btn-newkeypair').show();
      $('#privatekey').show();
      $('#publickey').show();
      $('#symmetrickey').hide();
    }

    if (headerObj){
      // always base64
      $('.sel-symkey-pbkdf2-salt-coding option[value="Base64"]')
        .prop('selected', true)
        .trigger("change");
      // user can change these but it probably won't work
    }
  }
  $this.data('prev', newSelection);
}


$(document).ready(function() {
  $( '#version_id').text(BUILD_VERSION);
  $( '.btn-copy' ).on('click', copyToClipboard);
  $( '.btn-generate' ).on('click', generateSignature);
  $( '.btn-verify' ).on('click', verifySignature);
  $( '.btn-newkeypair' ).on('click', newKeyPair);
  $( '.sel-alg').on('change', onChangeAlg);

  $('#ta_privatekey').on('paste', handlePaste);
  $('#ta_publickey').on('paste', handlePaste);

  $( '.sel-symkey-coding').on('change', changeSymmetricKeyCoding);

  $('#mainalert').addClass('fade');
  $('#mainalert').on('close.bs.alert', closeAlert);

  $('#symmetrickey').hide();
  $('#pbkdf2_params').hide();

  var text = reformIndents($('#ta_headerlist').val());
  $('#ta_headerlist').val(text);

  newKeyPair();

});
