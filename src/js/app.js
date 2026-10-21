/* global BUILD_VERSION, TextEncoder, navigator */

import { pemToDer } from "./pem.js";
import { bytesFromText, textFromBytes, bytesFromBase64 } from "./encoding.js";
import SignatureParser from "./SignatureParser.js";
import LocalStorage from './LocalStorage.js';

const html5AppId = '04ed4dea-499a-4de6-9e24-0e156b1d6c4d';
const storage = LocalStorage.init(html5AppId);
let datamodel = {
      'sel-alg':'',
      'chk-created': true,
      'sel-expiry': 10,
      'sel-symkey-coding': '',
      'ta-keyid' : 'abcdefg-123',
      'ta_publickey' : '',
      'ta_privatekey' : '',
      'ta_symmetrickey' : '',
      ta_headerlist : ''
    };

const requiredKeys = ['algorithm', 'keyId', 'headers', 'signature'];
const pwComponents = [
        [
          'Vaguely', 'Undoubtedly', 'Indisputably', 'Understandably',
          'Definitely', 'Possibly', 'Verifiably'
        ],
        [
          'Salty', 'Fresh', 'Ursine', 'Excessive', 'Daring', 'Delightful', 'Stable',
          'Evolving', 'Resilient', 'Dynamic', 'Confounding', 'Ordered', 'Infinite',
          'Public', 'Private', 'Personal', 'Strategic'
        ],
        [
          'Mirror', 'Collection','Caliper', 'Postage', 'Portfolio', 'Roadway',
          'Passage', 'Statement', 'Toolbox', 'Paradox', 'Orbit', 'Bridge', 'Story',
          'Bracket', 'Journey', 'Expedition', 'Strategy'
        ]
      ];

const $sel = (query) => document.querySelector(query),
      $all = (query) => document.querySelectorAll(query),
      selectedText = (query) => {
        const el = $sel(query);
        return el.selectedIndex >= 0 ? el.options[el.selectedIndex].text : '';
      },
      setVisible = (query, visible) => { $sel(query).hidden = !visible; };

const PBKDF_ITERATIONS = {DEFAULT:8192, MAX: 100001, MIN:50};
const defaultHeaders =
  '              x-request-id: 00000000-0000-0000-0000-000000000004\n' +
'              tpp-redirect-uri: https://www.sometpp.com/redirect/\n' +
'              digest: SHA-256=TGGHcPGLechhcNo4gndoKUvCBhWaQOPgtoVDIpxc6J4=\n' +
  '              psu-id: 1337\n' ;

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
  const elt = e.currentTarget;
  setTimeout(function () {
    elt.value = reformIndents(elt.value);
    saveSetting(elt.id, elt.value);
  }, 100);
}

function getPbkdf2IterationCount() {
  let icountvalue = $sel('#ta_pbkdf2_iterations').value,
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
  let keyvalue = $sel('#ta_pbkdf2_salt').value;
  let coding = selectedText('.sel-symkey-pbkdf2-salt-coding');
  let knownCodecs = ['UTF-8', 'Base64', 'Hex'];

  if (knownCodecs.indexOf(coding)>=0) {
    return bytesFromText(keyvalue, coding);
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
  const keyvalue = $sel('#ta_symmetrickey').value,
        coding = selectedText('.sel-symkey-coding'),
        knownCodecs = ['UTF-8', 'Base64', 'Hex'];

  if (knownCodecs.indexOf(coding)>=0) {
    return Promise.resolve(bytesFromText(keyvalue, coding))
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
                 bytesFromText(keyvalue, 'utf-8'),
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
  return $sel('#ta_privatekey').value;
}

function getPublicKey() {
  return $sel('#ta_publickey').value;
}

async function copyToClipboard(event) {
  const sourceElement = event.currentTarget.getAttribute('data-target'),
        $source = document.getElementById(sourceElement),
        textToCopy = ($source.tagName == 'TEXTAREA' || $source.tagName == 'INPUT') ? $source.value : $source.textContent;

  try {
    await navigator.clipboard.writeText(textToCopy);
    // Animation to indicate copy.
    $source.classList.add('copy-to-clipboard-flash-bg');
    setTimeout( _ => $source.classList.remove('copy-to-clipboard-flash-bg'), 1800);
  }
  catch (e) {
    // gulp
  }
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

function getKeyId() {
  let text = $sel('#ta-keyid').value.trim();
  saveSetting('ta-keyid', text);
  return text;
}

function getHeaders() {
  let text = $sel('#ta_headerlist').value,
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
        wantCreated = $sel('#chk-created').checked,
        desiredExpiry = selectedText('#sel-expiry').toLowerCase();

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
      algSelection = selectedText('.sel-alg'),
      p = null;
  if ((algSelection == 'hmac-sha256') || (algSelection == 'hs2019 (hmac)')) {
    p = getSymmetricKey(algSelection);
  }
  else if (algSelection == 'rsa-sha256') {
    let keydata = pemToDer(getPrivateKey());
    p = window.crypto.subtle.importKey('pkcs8', keydata, {name:'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['sign']);
  }
  else if (algSelection == 'hs2019 (rsa)') {
    let keydata = pemToDer(getPrivateKey());
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
      $sel('#ta_signature').value = signature;
      let headerList = getHeaderList(headers, times),
          algForHeader = algSelectionToAlg(algSelection),
          flavor = algFlavor(algSelection),
          keyId = getKeyId(),
          items = [
            `keyId="${keyId}"`,
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

      $sel('#ta_httpsigheader').value = 'Signature ' + items.join(', ');
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
    const sigHeader = SignatureParser.parse($sel('#ta_httpsigheader').value),
          sigBytes = bytesFromBase64(sigHeader.signature),
          times = {created: sigHeader.created, expires: sigHeader.expires},
          stringToSign = getStringToSign(getHeaders(), times, sigHeader.headers),
          data = new TextEncoder().encode(stringToSign),
          selectedAlg = selectedText('.sel-alg'),
          flavor = algFlavor(selectedAlg);
    let p = null;
    if (sigHeader.algorithm == 'rsa-sha256') {
      let keydata = pemToDer(getPublicKey());
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
      let keydata = pemToDer(getPublicKey());
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
  const buttonHtml = '<button type="button" class="close" aria-label="Close">\n' +
    ' <span aria-hidden="true">&times;</span>\n' +
    '</button>',
        $mainalert = $sel("#mainalert");
  $mainalert.innerHTML = html + buttonHtml;
  $mainalert.classList.remove('alert-warning', 'alert-success', 'alert-info');
  $mainalert.classList.add('alert-' + (alertClass || 'warning')); // success, info, warning
  // show()
  $mainalert.classList.remove('fade');
  $mainalert.classList.add('show');
  $mainalert.style.zIndex = 99;
  const tid = setTimeout(closeAlert, 5650);
  $mainalert.querySelector('button.close').addEventListener('click', () => {
    clearTimeout(tid);
    closeAlert();
  });
}

function closeAlert() {
  const $mainalert = $sel("#mainalert");
  $mainalert.classList.add('fade');
  $mainalert.classList.remove('show');
  setTimeout(() => { $mainalert.style.zIndex = -1; }, 800);
}

function updateKeyValue(flavor /* public || private */, keyvalue) {
  const id = 'ta_' + flavor + 'key';
  $sel('#' + id).value = keyvalue;
  saveSetting(id, keyvalue);
}

function key2pem(flavor, keydata) {
  let body = window.btoa(String.fromCharCode(...new Uint8Array(keydata)));
  body = body.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${flavor} KEY-----\n${body}\n-----END ${flavor} KEY-----`;
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
  let alg = selectedText('.sel-alg'),
      flavor = algFlavor(alg);
  if (flavor == 'hmac') {
    let coding = selectedText('.sel-symkey-coding');
    let keyString = null;
    if (coding == 'UTF-8' || coding == 'PBKDF2') {
      keyString = randomPassword();
    }
    else if (coding == 'Base64' || coding == 'Hex') {
      keyString = textFromBytes(randomOctetKey(), coding);
    }
    if (keyString) {
      $sel('#ta_symmetrickey').value = keyString;
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
      .then( () => closeAlert());
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


function changeSymmetricKeyCoding() {
  const coding = selectedText('#sel-symkey-coding');
  // display the salt and iteration count only for PBKDF2
  setVisible('#pbkdf2_params', coding == 'PBKDF2');
  saveSetting('sel-symkey-coding', coding);
}

function algFlavor(algString) {
  if ( ! algString) return 'unknown';
  if (algString.indexOf('hmac') >= 0) return 'hmac';
  if (algString.indexOf('rsa') >= 0) return 'rsa';
  return 'unknown';
}

function onChangeCreated(event) {
  saveSetting('chk-created', String(event.currentTarget.checked));
}

function onChangeExpiry(event) {
  saveSetting('sel-expiry', selectedText('#sel-expiry'));
}

// Show the key inputs and settings that apply to the selected algorithm.
function updateUiForAlg(selectedAlg) {
  const flavor = algFlavor(selectedAlg);
  setVisible('#privatekey', flavor == 'rsa');
  setVisible('#publickey', flavor == 'rsa');
  setVisible('#symmetrickey', flavor == 'hmac');
  setVisible('#pbkdf2_params', flavor == 'hmac' && selectedText('#sel-symkey-coding') == 'PBKDF2');
  setVisible('#hs2019-settings', selectedAlg.startsWith('hs2019'));
}

function keysMissingFor(flavor) {
  if (flavor == 'hmac') {
    return !$sel('#ta_symmetrickey').value;
  }
  return !$sel('#ta_privatekey').value.trim() || !$sel('#ta_publickey').value.trim();
}

function onChangeAlg(event) {
  const selectedAlg = selectedText('#sel-alg');
  updateUiForAlg(selectedAlg);
  if (keysMissingFor(algFlavor(selectedAlg))) {
    newKey(null);
  }
  saveSetting('sel-alg', selectedAlg);
}

function retrieveLocalState() {
  Object.keys(datamodel)
    .forEach(key => {
      const value = storage.get(key);
      if (value === null || (key == 'ta-keyid' && !value)) {
        return; // nothing stored yet; keep the default
      }
      datamodel[key] = key.startsWith('chk-') ? value == 'true' : value;
    });
}

function fixupHeaderList() {
  const $headers = $sel('#ta_headerlist');
  let text = $headers.value;
  if ( !text || text.trim() == '') {
    text = defaultHeaders;
  }
  let reformedText = reformIndents(text);
  if (reformedText != $headers.value) {
    saveSetting('ta_headerlist', reformedText);
    $headers.value = reformedText;
  }
}

function saveSetting(key, value) {
  datamodel[key] = value;
  storage.store(key, value);
}

function applyState() {
  Object.keys(datamodel)
    .forEach(key => {
      const value = datamodel[key],
            $item = $sel('#' + key);
      if (key.startsWith('sel-')) {
        const $option = $item.querySelector(`option[value='${value}']`);
        if ($option) {
          $option.selected = true;
        }
      }
      else if (key.startsWith('chk-')) {
        $item.checked = (String(value) == 'true');
      }
      else if (value) {
        $item.value = value;
      }
    });

  if (!datamodel['sel-alg']) {
    saveSetting('sel-alg', selectedText('#sel-alg')); // default
  }
  updateUiForAlg(selectedText('#sel-alg'));
}

document.addEventListener('DOMContentLoaded', () => {
  $sel('#version_id').textContent = BUILD_VERSION;
  $all('.btn-copy').forEach(btn => btn.addEventListener('click', copyToClipboard));
  $sel('.btn-generate').addEventListener('click', generateSignature);
  $sel('.btn-verify').addEventListener('click', verifySignature);
  $all('.btn-newkey').forEach(btn => btn.addEventListener('click', newKey));

  ['#ta_privatekey', '#ta_publickey'].forEach(id =>
    $sel(id).addEventListener('paste', handlePaste));
  ['#ta_privatekey', '#ta_publickey', '#ta_symmetrickey', '#ta_headerlist', '#ta-keyid'].forEach(id =>
    $sel(id).addEventListener('input', e => saveSetting(e.currentTarget.id, e.currentTarget.value)));

  retrieveLocalState();
  applyState();
  fixupHeaderList();

  $sel('#sel-symkey-coding').addEventListener('change', changeSymmetricKeyCoding);
  $sel('#sel-alg').addEventListener('change', onChangeAlg);
  $sel('#sel-expiry').addEventListener('change', onChangeExpiry);
  $sel('#chk-created').addEventListener('change', onChangeCreated);

  if (keysMissingFor(algFlavor(selectedText('#sel-alg')))) {
    newKey();
  }
});
