/* global atob, Buffer, TextDecoder, BUILD_VERSION, TextEncoder */

import 'bootstrap';
import $ from "jquery";
import NodeRSA from "node-rsa";
import SignatureParser from "./SignatureParser.js";
import LocalStorage from './LocalStorage.js';

const html5AppId = '04ed4dea-499a-4de6-9e24-0e156b1d6c4d';
const storage = LocalStorage.init(html5AppId);
let datamodel = {
      'sel-alg':'',
      'chk-created': true,
      'sel-expiry': 10,
      'sel-symkey-coding': '',
      'ta_publickey' : '',
      'ta_privatekey' : '',
      'ta_symmetrickey' : ''
    };

const requiredKeys = ['algorithm', 'keyId', 'headers', 'signature'];
const pwComponents = [
        ['Vaguely', 'Undoubtedly', 'Indisputably', 'Understandably', 'Definitely', 'Possibly'],
        ['Salty', 'Fresh', 'Ursine', 'Excessive', 'Daring', 'Delightful', 'Stable', 'Evolving'],
        ['Mirror', 'Caliper', 'Postage', 'Return', 'Roadway', 'Passage', 'Statement', 'Toolbox', 'Paradox', 'Orbit', 'Bridge']
      ];

const PBKDF_ITERATIONS = {DEFAULT:8192, MAX: 100001, MIN:50};

function quantify(quantity, term) {
  let termIsPlural = term.endsWith('s');
  let quantityIsPlural = (quantity != 1 && quantity != -1);

  if (termIsPlural && !quantityIsPlural)
    return term.slice(0, -1);

  if ( ! termIsPlural && quantityIsPlural)
    return term + 's';

  return term;
}

function randomBoolean() {
  return Math.floor(Math.random() * 2) == 1;
}

function randomNumber() {
  let min = (randomBoolean())? 10: 100,
      max = (randomBoolean())? 100000: 1000;
  return Math.floor(Math.random() * (max - min)) + min;
}

function selectRandomValue (a) {
  let L = a.length,
      n = Math.floor(Math.random() * L);
  return a[n];
}

function randomOctetKey() {
  var array = new Uint8Array(48);
  window.crypto.getRandomValues(array);
  return array;
}

function randomPassword() {
  return pwComponents
    .map(selectRandomValue)
    .join('-') +
    '-' +
    randomNumber().toFixed(0).padStart(4, '0').substr(-4) +
    '-' +
    randomNumber().toFixed(0).padStart(7, '0').substr(-7);
}

function subtleCryptoAlgorithm(alg) {
  if (alg =='rsa-sha256') {
    return "RSASSA-PKCS1-v1_5";
  }
  if (alg =='hmac-sha256') {
    return "HMAC";
  }
  if (alg =='hs2019 (hmac)') {
    return "HMAC";
  }
  if (alg =='hs2019 (rsa)') {
    // I could not find the required saltLength documented in the Http Sig
    // specification. Here, the value is equal to the length of the output
    // hash. This is what JWT specifies, and other systems commonly use this
    // approach.
    return { name: "RSA-PSS", saltLength: 512 / 8};
  }
  return "null";
}

function algSelectionToAlg(alg) {
  if ((alg =='hs2019 (hmac)') || (alg =='hs2019 (rsa)')) {
    return "hs2019";
  }
  return alg;
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
      icount = PBKDF_ITERATIONS.DEFAULT;
  try {
    icount = Number.parseInt(icountvalue, 10);
  }
  catch (exc1) {
    setAlert("not a number? defaulting to iteration count: "+ icount);
  }
  if (icount > PBKDF_ITERATIONS.MAX || icount < PBKDF_ITERATIONS.MIN) {
    icount = PBKDF_ITERATIONS.DEFAULT;
    setAlert("iteration count out of range. defaulting to: "+ icount);
  }
  return icount;
}

function getPbkdf2SaltBuffer() {
  let keyvalue = $('#ta_pbkdf2_salt').val();
  let coding = $('.sel-symkey-pbkdf2-salt-coding').find(':selected').text();
  let knownCodecs = ['UTF-8', 'Base64', 'Hex'];

  if (knownCodecs.indexOf(coding)>=0) {
    return Buffer.from(keyvalue, coding);
  }
  throw new Error('unsupported salt encoding'); // will not happen
}

function checkKeyLength(alg, keyBuffer) {
  const length = keyBuffer.byteLength,
        requiredLength = 256 / 8;
  if (length >= requiredLength) return Promise.resolve(keyBuffer);
  return Promise.reject(new Error('insufficient key length. You need at least ' + requiredLength + ' chars for ' + alg));
}

function getHashFromAlg(alg) {
  if (alg.startsWith('hs2019')) return "SHA-512";
  return "SHA-256"; // rsa-sha256 or hmac-sha256
}

function getSymmetricKey(alg) {
  const keyvalue = $('#ta_symmetrickey').val(),
        coding = $('.sel-symkey-coding').find(':selected').text(),
        knownCodecs = ['UTF-8', 'Base64', 'Hex'];

  if (knownCodecs.indexOf(coding)>=0) {
    return Promise.resolve(Buffer.from(keyvalue, coding))
      .then( keyBuffer => checkKeyLength(alg, keyBuffer))
      .then( keyBuffer => window
             .crypto
             .subtle
             .importKey("raw",
                        keyBuffer,
                        {name:"HMAC", hash: getHashFromAlg(alg)},
                        false,
                        ['sign', 'verify']));

  }

  if (coding == 'PBKDF2') {
    return window
      .crypto
      .subtle
      .importKey('raw',
                 Buffer.from(keyvalue, 'utf-8'),
                 {name: 'PBKDF2'},
                 false,
                 ['deriveBits', 'deriveKey'] )
      .then(rawKey => window
            .crypto
            .subtle
            .deriveKey( { name: 'PBKDF2',
                          salt: getPbkdf2SaltBuffer(),
                          iterations: getPbkdf2IterationCount(),
                          hash: 'SHA-256'
                        },
                        rawKey,
                        { name: 'HMAC', hash: getHashFromAlg(alg)},
                        true,
                        [ "sign", "verify" ]));
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

  try {
    document.execCommand("copy");

    // Animation to indicate copy.
    // CodeMirror obscures the original textarea, and appends a div as the next sibling.
    // We want to flash THAT.
    let $cmdiv = $source.next();
    if ($cmdiv.length>0 && $cmdiv.prop('tagName').toLowerCase() == 'div' && $cmdiv.hasClass('CodeMirror')) {
      $cmdiv
        .addClass('copy-to-clipboard-flash-bg')
        .delay('16')
        .queue( _ => $cmdiv.removeClass('copy-to-clipboard-flash-bg').dequeue() );
    }
    else {
      // no codemirror (probably the secretkey field, which is just an input)
      $source.addClass('copy-to-clipboard-flash-bg');
      setTimeout( _ => $source.removeClass('copy-to-clipboard-flash-bg'), 1800);
      // $source.addClass('copy-to-clipboard-flash-bg')
      //   .delay('1000')
      //   .queue( _ => $source.removeClass('copy-to-clipboard-flash-bg').dequeue() );
    }
  }
  catch (e) {
    // gulp
  }
  $temp.remove();

}

function getHeaderList(headers, times) {
  let list = Object.keys(headers);
  if (times.created) {
    list.push("created");
  }
  if (times.expires) {
    list.push("expires");
  }
  return list.join(' ');
}

function getStringToSign(headers, times, ordering) {
  let list = null;
  if (ordering) {
    list =  ordering.split(' ')
      .map(hdrName => {
        if (hdrName == 'created') return '(created): ' + times.created;
        if (hdrName == 'expires') return '(expires): ' + times.expires;
        return hdrName.toLowerCase() + ': ' + headers[hdrName];
      });
  }
  else {
    list = Object.keys(headers)
      .map(hdrName => hdrName.toLowerCase() + ': ' + headers[hdrName]);
    if (times.created) list.push('(created): ' + times.created);
    if (times.expires) list.push('(expires): ' + times.expires);
  }

  return list.join('\n');
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

function getCreatedAndExpiryTimesForGeneration(selectedAlg) {
  let ret = {};
  if (selectedAlg.startsWith('hs2019')) {
    let now = Math.floor((new Date()).valueOf() / 1000),
        wantCreated = $('#chk-created').prop('checked'),
        $expirySelection = $('#sel-expiry').find(':selected'),
        desiredExpiry = $expirySelection.text().toLowerCase(),
        desiredLifetime = Number($expirySelection.val());

    if (wantCreated) {
      ret.created = now;
    }

    if (desiredExpiry != 'no expiry') {
      //ret.expires = now + desiredLifetime;
      let matches = (new RegExp('^([1-9][0-9]*) (minutes|seconds)$')).exec(desiredExpiry);
      if (matches && matches.length == 3) {
        let factor = (matches[2] == 'minutes') ? 60 : 1;
        ret.expires = now + parseInt(matches[1], 10) * factor;
      }
    }
  }
  return ret;
}

function generateSignature(event) {
  let headers = getHeaders(),
      algSelection = $('.sel-alg').find(':selected').text(),
      p = null;
  if ((algSelection == 'hmac-sha256') || (algSelection == 'hs2019 (hmac)')) {
    p = getSymmetricKey(algSelection);
  }
  else if (algSelection == 'rsa-sha256') {
    let keydata = pem2bin(getPrivateKey());
    p = window.crypto.subtle.importKey('pkcs8', keydata, {name:'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['sign']);
  }
  else if (algSelection == 'hs2019 (rsa)') {
    let keydata = pem2bin(getPrivateKey());
    p = window.crypto.subtle.importKey('pkcs8', keydata, {name:'RSA-PSS', hash: 'SHA-512'}, false, ['sign']);
  }
  else {
    throw new Error('unsupported algorithm');
  }

  let times = getCreatedAndExpiryTimesForGeneration(algSelection);

  return p
    .then( signingKey => {
      const stringToSign = getStringToSign(headers, times);
      const buf = new TextEncoder().encode(stringToSign);
      return window.crypto.subtle.sign(subtleCryptoAlgorithm(algSelection), signingKey, buf);
    })
    .then(signatureData => {
      return window.btoa(String.fromCharCode(...new Uint8Array(signatureData)));
    })
    .then( signature => {
      $('#ta_signature').val(signature);
      let headerList = getHeaderList(headers, times),
          algForHeader = algSelectionToAlg(algSelection),
          flavor = algFlavor(algSelection),
          items = [
            `keyId="${flavor}-test"`,
            `algorithm="${algForHeader}"`,
            `headers="${headerList}"`
          ];

      if (headerList.indexOf('created') >= 0) {
        items.push(`created=${times.created}`);
      }
      if (headerList.indexOf('expires') >= 0) {
        items.push(`expires=${times.expires}`);
      }
      items.push(`signature="${signature}"`);

      $('#ta_httpsigheader').val('Signature ' + items.join(', '));
    })
    .catch( e => {
      console.log(e.stack);
      setAlert(e);
    });
}

function secondsAccuracyIsoString(t) {
  return t.toISOString().replace( new RegExp('\\\.\\d{3}Z$'), 'Z');
}

function verifySignature(event) {
  try {
    const sigHeader = SignatureParser.parse($('#ta_httpsigheader').val()),
          sigBytes = Buffer.from(sigHeader.signature, 'base64'),
          times = {created: sigHeader.created, expires: sigHeader.expires},
          stringToSign = getStringToSign(getHeaders(), times, sigHeader.headers),
          data = new TextEncoder().encode(stringToSign),
          selectedAlg = $('.sel-alg').find(':selected').text(),
          flavor = algFlavor(selectedAlg);
    let p = null;
    if (sigHeader.algorithm == 'rsa-sha256') {
      let keydata = pem2bin(getPublicKey());
      p = window
        .crypto
        .subtle
        .importKey("spki", keydata, {name:"RSASSA-PKCS1-v1_5", hash: "SHA-256"}, false, ['verify'])
        .then(publicKey =>
              window.crypto.subtle.verify(
                subtleCryptoAlgorithm(sigHeader.algorithm),
                publicKey,
                sigBytes,
                data
              ));
    }
    else if ( (sigHeader.algorithm == 'hmac-sha256') ||
              ((sigHeader.algorithm == 'hs2019') && (flavor == 'hmac') )) {
      p = getSymmetricKey(sigHeader.algorithm)
        .then(symmetricKey =>
              window.crypto.subtle.verify(
                "HMAC",
                symmetricKey,
                sigBytes,
                data
              ));
    }
    else if ((sigHeader.algorithm == 'hs2019') && (flavor == 'rsa')) {
      // Infer the type of crypto based on the SELECTED alg in the dropdown
      let keydata = pem2bin(getPublicKey());
      p = window
        .crypto
        .subtle
        .importKey("spki", keydata, {name:"RSA-PSS", hash: "SHA-512"}, false, ['verify'])
        .then(publicKey =>
              window.crypto.subtle.verify(
                subtleCryptoAlgorithm('hs2019 (rsa)'),
                publicKey,
                sigBytes,
                data
              ));
    }
    else {
      throw new Error('unknown algorithm');
    }

    // check created and expires IFF hs2019
    if (sigHeader.algorithm == 'hs2019') {
      p.then(isvalid => {
        if (isvalid) {
          let nowDate = new Date(),
              nowSeconds = Math.floor(nowDate.valueOf() / 1000),
              reasons = [],
              notes = [];
          if (sigHeader.created) {
            if (sigHeader.created > nowSeconds)
              reasons.push('the created time is in the future');
          }
          if (sigHeader.expires) {
            let expiry = new Date(sigHeader.expires * 1000),
                expiresString = secondsAccuracyIsoString(expiry),
                delta = nowSeconds - sigHeader.expires,
                timeUnit = quantify(delta, 'seconds');
            if (delta > 0) {
              reasons.push(`the expiry time (${expiresString}) is in the past, ${delta} ${timeUnit} ago`);
            }
            else {
              let nowString = secondsAccuracyIsoString(nowDate);
              delta *= -1;
              notes.push('expires: ' + expiresString);
              notes.push('now: ' + nowString);
              notes.push(`time remaining: ${delta} ${timeUnit}`);
            }
          }

          if (reasons.length == 0) {
            setAlert('The signature is valid. ' + notes.join('; '),
                     'success') ;
          }
          else {
            setAlert('The signature is valid, but ' + reasons.join('; '), 'warning') ;
          }
        }
        else {
          setAlert('The signature is not valid', 'warning');
        }
      });
    }
    else {
      p.then( isvalid =>
              (isvalid) ?
              setAlert('The signature is valid.', 'success') :
              setAlert('The signature is not valid', 'warning'));
    }
  }
  catch (exc1) {
    setAlert('error processing HTTP Signature header: ' + exc1.message);
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
  $("#mainalert").css('z-index', 99);
  setTimeout(() => {
    $("#mainalert").addClass('fade').removeClass('show');
    setTimeout(() => $("#mainalert").css('z-index', -1), 800);
  }, 5650);
}

function closeAlert(event){
  $("#mainalert").addClass('fade').removeClass('show');
  setTimeout(() => $("#mainalert").css('z-index', -1), 800);
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
  if (alg == 'rsa-sha256') return {
    name: "RSASSA-PKCS1-v1_5", // this name also works for RSA-PSS !
    modulusLength: 2048, //can be 1024, 2048, or 4096
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-256"}
  };
  if (alg == 'hs2019 (rsa)') return {
    name: "RSA-PSS", // not sure if this is required
    modulusLength: 2048, //can be 1024, 2048, or 4096
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-512"} // I believe this is important
  };
  throw new Error('invalid key flavor');
}

function newKey(event) {
  let alg = $('.sel-alg').find(':selected').text(),
      flavor = algFlavor(alg);
  if (flavor == 'hmac') {
    let coding = $('.sel-symkey-coding').find(':selected').text();
    let keyString = null;
    if (coding == 'UTF-8' || coding == 'PBKDF2') {
      keyString = randomPassword();
    }
    else if (coding == 'Base64' || coding == 'Hex') {
      keyString = Buffer.from(randomOctetKey()).toString(coding);
    }
    if (keyString) {
      $('#ta_symmetrickey').val(keyString);
      saveSetting('ta_symmetrickey', keyString); // for reload
    }
  }
  else if (flavor == 'rsa') {
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

// function selectAlgorithm(algName) {
//   let currentlySelectedAlg = $('.sel-alg').find(':selected').text().toLowerCase();
//   if (algName.toLowerCase() != currentlySelectedAlg) {
//     let $option = $('.sel-alg option[value="'+ algName +'"]');
//     if ( ! $option.length) {
//       $option = $('.sel-alg option[value="??"]');
//     }
//     $option
//       .prop('selected', true)
//       .trigger("change");
//   }
// }

// function keysAreCompatible(alg1, alg2) {
//   let prefix1 = alg1.substring(0, 2),
//       prefix2 = alg2.substring(0, 2);
//   if (['RS', 'PS'].indexOf(prefix1)>=0 &&
//       ['RS', 'PS'].indexOf(prefix2)>=0 ) return true;
//   if (prefix1 == 'ES') return alg1 == alg2;
//   return false;
// }


function changeSymmetricKeyCoding(event) {
  let $this = $(this),
      newSelection = $this.find(':selected').text(),
      previousSelection = $this.data('previous-coding');
  if (newSelection != previousSelection) {
    if (newSelection == 'PBKDF2') {
      // display the salt and iteration count
      $('#pbkdf2_params').show();
    }
    else {
      $('#pbkdf2_params').hide();
    }
  }
  $this.data('previous-coding', newSelection);
  saveSetting('sel-symkey-coding', newSelection);
}

function algFlavor(algString) {
  if ( ! algString) return 'unknown';
  if (algString.indexOf('hmac') >= 0) return 'hmac';
  if (algString.indexOf('rsa') >= 0) return 'rsa';
  return 'unknown';
}

function onChangeCreated(event) {
  let wantCreated = $('#chk-created').prop('checked');
  saveSetting('chk-created', String(wantCreated));
}

function onChangeExpiry(event) {
  let $this = $(this),
      selectedExpiry = $this.find(':selected').text();
  saveSetting('sel-expiry', selectedExpiry);
}

function onChangeAlg(event) {
  let $this = $(this),
      selectedAlg = $this.find(':selected').text(),
      newFlavor = algFlavor(selectedAlg),
      previousFlavor = $this.data('previous-flavor');

  if (newFlavor != previousFlavor) {
    if (newFlavor == 'hmac') {
      $('#privatekey').hide();
      $('#publickey').hide();
      $('#symmetrickey').show();
      if ( ! $('#ta_symmetrickey').val()) {
        newKey(null);
      }
      changeSymmetricKeyCoding.call(document.querySelector('#sel-symkey-coding'), null);
    }
    else if (newFlavor == 'rsa') {
      $('#privatekey').show();
      $('#publickey').show();
      $('#symmetrickey').hide();
      let privatekey = $('#ta_privatekey').val().trim(),
          publickey = $('#ta_publickey').val().trim();
      if ( ! privatekey || !publickey) {
        newKey(null);
      }
    }
  }
  if (selectedAlg.startsWith('hs2019')) {
    $('#hs2019-settings').show();
  }
  else {
    $('#hs2019-settings').hide();
  }
  $this.data('previous-flavor', newFlavor);
  saveSetting('sel-alg', selectedAlg);
}

function retrieveLocalState() {
    Object.keys(datamodel)
    .forEach(key => {
      var value = storage.get(key);
      if (key.startsWith('chk-')) {
        datamodel[key] = Boolean(value);
      }
      else {
        datamodel[key] = value;
      }
    });
}

function saveSetting(key, value) {
  datamodel[key] = value;
  storage.store(key, value);
}

function applyState() {
    Object.keys(datamodel)
    .forEach(key => {
      let value = datamodel[key],
          $item = $('#' + key);
      if (key.startsWith('sel-')) {
        // selection
        $item.find("option[value='"+value+"']")
          .prop('selected', 'selected')
          .trigger("change");
      }
      else if (key.startsWith('chk-')) {
        $item.prop("checked", Boolean(value));
      }
      else {
        $item.val(value);
      }
    });

  let alg = datamodel['sel-alg'];
  if (!alg) {
    alg = 'rsa-sha256'; // default
    saveSetting('sel-alg', alg);
    let $item = $('#sel-alg');
    $item.find("option[value='"+alg+"']")
      .prop('selected', 'selected')
      .trigger("change");
  }
  let flavor = algFlavor(alg);
  if (flavor == 'hmac') {
    $('#symmetrickey').show();
    $('#privatekey').hide();
    $('#publickey').hide();
    let coding = $('.sel-symkey-coding').find(':selected').text();
    if (coding == 'PBKDF2') {
      $('#pbkdf2_params').show();
    }
    else {
      $('#pbkdf2_params').hide();
    }
  }
  else {
    $('#symmetrickey').hide();
    //$('#pbkdf2_params').hide();
    $('#privatekey').show();
    $('#publickey').show();
  }
}

$(document).ready(function() {
  $('#version_id').text(BUILD_VERSION);
  $('.btn-copy').on('click', copyToClipboard);
  $('.btn-generate').on('click', generateSignature);
  $('.btn-verify').on('click', verifySignature);
  $('.btn-newkey').on('click', newKey);

  $('#ta_privatekey').on('paste', handlePaste);
  $('#ta_publickey').on('paste', handlePaste);

  $('#mainalert').addClass('fade');
  $('#mainalert').on('close.bs.alert', closeAlert);

  $('#hs2019-settings').hide();

  var text = reformIndents($('#ta_headerlist').val());
  $('#ta_headerlist').val(text);

  retrieveLocalState();

  $('.sel-symkey-coding').on('change', changeSymmetricKeyCoding);
  $('#sel-alg').on('change', onChangeAlg);
  $('#sel-expiry').on('change', onChangeExpiry);
  $('#chk-created').on('change', onChangeCreated);

  applyState();

  let flavor = algFlavor(datamodel['sel-alg']);
  if ( ! datamodel.ta_symmetrickey && flavor == 'hmac') {
    newKey();
  }
  else if (( ! datamodel.ta_privatekey || !datamodel.ta_privatekey) && flavor == 'rsa') {
    newKey();
  }

  //onChangeAlg.call(document.querySelector('#sel-alg'), null);

});
