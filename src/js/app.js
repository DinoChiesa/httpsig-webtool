/* global BUILD_VERSION, navigator */

import { bytesFromText, textFromBytes } from "./encoding.js";
import LocalStorage from './LocalStorage.js';
import { parseMessage } from "./message.js";
import {
  availableComponents,
  isDefaultCovered,
  buildSignatureParams,
  signatureBase,
  signatureFields,
  parseSignatureFields,
} from "./rfc9421.js";
import { keyFamily, importPemKey, importHmacKey, sign, verify, generateKeyPair } from "./sigcrypto.js";
import { contentDigestValue, contentDigestMatches, digestAlgorithmOf, setHeader } from "./digest.js";

const html5AppId = '04ed4dea-499a-4de6-9e24-0e156b1d6c4d';
const storage = LocalStorage.init(html5AppId);
const ASYMMETRIC_FAMILIES = ['rsa', 'ec-p256', 'ec-p384', 'ed25519'];

const datamodel = {
  'sel-alg': '',
  'sel-symkey-coding': '',
  'sel-expiry': '',
  'chk-created': true,
  'chk-alg': true,
  'chk-nonce': false,
  'chk-darkmode': true,
  'nonce-value': '',
  'ta-label': 'sig1',
  'ta-keyid': 'test-key',
  'ta-tag': '',
  'ta_message': '',
  'ta_symmetrickey': '',
  'component-choices': '{}',
};
ASYMMETRIC_FAMILIES.forEach(family => {
  datamodel[`ta_privatekey-${family}`] = '';
  datamodel[`ta_publickey-${family}`] = '';
});

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

// The test-request message from RFC 9421 Appendix B.2.
const defaultMessage = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
Content-Length: 18

{"hello": "world"}`;

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

function randomNonce() {
  return textFromBytes(window.crypto.getRandomValues(new Uint8Array(12)), 'base64')
    .replace(/\+/g, '-').replace(/\//g, '_');
}

function reformIndents(s) {
  let s2 = s.split(new RegExp('\n', 'g'))
    .map(s => s.trim())
    .join("\n");
  return s2.trim();
}

function saveSetting(key, value) {
  datamodel[key] = value;
  storage.store(key, value);
}

// ---------------------------------------------------------------- keys

const selectedAlg = () => selectedText('#sel-alg');
const selectedFamily = () => keyFamily(selectedAlg());

function getPbkdf2IterationCount() {
  let icountvalue = $sel('#ta_pbkdf2_iterations').value,
      icount = Number.parseInt(icountvalue, 10);
  if (Number.isNaN(icount)) {
    icount = PBKDF_ITERATIONS.DEFAULT;
    setAlert("not a number? defaulting to iteration count: "+ icount);
  }
  if (icount > PBKDF_ITERATIONS.MAX || icount < PBKDF_ITERATIONS.MIN) {
    icount = PBKDF_ITERATIONS.DEFAULT;
    setAlert("iteration count out of range. defaulting to: "+ icount);
  }
  return icount;
}

function getPbkdf2SaltBuffer() {
  return bytesFromText($sel('#ta_pbkdf2_salt').value, selectedText('.sel-symkey-pbkdf2-salt-coding'));
}

function checkKeyLength(keyBytes) {
  const requiredLength = 256 / 8;
  if (keyBytes.byteLength < requiredLength) {
    throw new Error('insufficient key length. You need at least ' + requiredLength + ' bytes for hmac-sha256');
  }
  return keyBytes;
}

async function getSymmetricKey() {
  const keyvalue = $sel('#ta_symmetrickey').value,
        coding = selectedText('.sel-symkey-coding');

  if (coding != 'PBKDF2') {
    return importHmacKey(checkKeyLength(bytesFromText(keyvalue, coding)));
  }
  const rawKey = await window.crypto.subtle.importKey('raw', bytesFromText(keyvalue, 'utf-8'),
                                                      {name: 'PBKDF2'}, false, ['deriveBits']);
  const derived = await window.crypto.subtle.deriveBits({ name: 'PBKDF2',
                                                          salt: getPbkdf2SaltBuffer(),
                                                          iterations: getPbkdf2IterationCount(),
                                                          hash: 'SHA-256' },
                                                        rawKey, 256);
  return importHmacKey(new Uint8Array(derived));
}

async function getKey(alg, usage /* sign | verify */) {
  if (keyFamily(alg) == 'hmac') {
    return getSymmetricKey();
  }
  const pem = $sel(usage == 'sign' ? '#ta_privatekey' : '#ta_publickey').value.trim();
  if (!pem) {
    throw new Error(`no ${usage == 'sign' ? 'private' : 'public'} key`);
  }
  return importPemKey(alg, pem, usage);
}

function storeKeyValue(flavor /* public | private */, family, keyvalue) {
  saveSetting(`ta_${flavor}key-${family}`, keyvalue);
}

function showKeysForFamily(family) {
  $sel('#ta_privatekey').value = datamodel[`ta_privatekey-${family}`] || '';
  $sel('#ta_publickey').value = datamodel[`ta_publickey-${family}`] || '';
}

const keysMissingFor = (family) =>
  family == 'hmac'
    ? !$sel('#ta_symmetrickey').value
    : !datamodel[`ta_privatekey-${family}`] || !datamodel[`ta_publickey-${family}`];

async function newKey() {
  const alg = selectedAlg(),
        family = keyFamily(alg);
  if (family == 'hmac') {
    const coding = selectedText('.sel-symkey-coding');
    const keyString = (coding == 'UTF-8' || coding == 'PBKDF2') ? randomPassword() : textFromBytes(randomOctetKey(), coding);
    $sel('#ta_symmetrickey').value = keyString;
    saveSetting('ta_symmetrickey', keyString); // for reload
    return;
  }
  try {
    const { publicKey, privateKey } = await generateKeyPair(alg);
    storeKeyValue('public', family, publicKey);
    storeKeyValue('private', family, privateKey);
    if (selectedFamily() == family) {
      showKeysForFamily(family);
    }
    closeAlert();
  }
  catch (e) {
    setAlert(`cannot generate a key for ${alg} in this browser: ${e.message}`);
  }
}

// ---------------------------------------------------------------- components

function readMessage() {
  return parseMessage($sel('#ta_message').value);
}

// The user's explicit check/uncheck choices, keyed by component identifier.
// Components without a choice use isDefaultCovered.
function componentChoices() {
  try {
    return JSON.parse(datamodel['component-choices']);
  }
  catch (_e) {
    return {};
  }
}

// Rebuild the checkbox list from the message, keeping the user's choices.
// Rebuild the checkbox list from the message, keeping the user's choices.
function renderComponentChoices(message) {
  const choices = componentChoices(),
        $list = $sel('#components');
  $list.textContent = '';
  availableComponents(message).forEach(id => {
    const $label = document.createElement('label'),
          $box = document.createElement('input');
    $box.type = 'checkbox';
    $box.value = id;
    $box.checked = id in choices ? choices[id] : isDefaultCovered(id);
    $box.addEventListener('change', onToggleComponent);
    $label.append($box, ' ', id);
    $list.append($label);
  });
}



function onToggleComponent(event) {
  const choices = componentChoices();
  choices[event.currentTarget.value] = event.currentTarget.checked;
  saveSetting('component-choices', JSON.stringify(choices));
  onInputsChanged();
}

const coveredComponents = () =>
  Array.from($all('#components input[type=checkbox]')).filter(b => b.checked).map(b => b.value);

// ---------------------------------------------------------------- parameters

function expiryLifetimeSeconds() {
  const matches = /^([1-9][0-9]*) (minutes|seconds)$/.exec(selectedText('#sel-expiry').toLowerCase());
  return matches ? parseInt(matches[1], 10) * (matches[2] == 'minutes' ? 60 : 1) : 0;
}

function currentSignatureParams(nowSeconds) {
  const lifetime = expiryLifetimeSeconds();
  return {
    created: $sel('#chk-created').checked ? nowSeconds : undefined,
    expires: lifetime ? nowSeconds + lifetime : undefined,
    keyid: $sel('#ta-keyid').value.trim(),
    alg: $sel('#chk-alg').checked ? selectedAlg() : undefined,
    nonce: $sel('#chk-nonce').checked ? datamodel['nonce-value'] : undefined,
    tag: $sel('#ta-tag').value.trim(),
  };
}

const signatureLabel = () => $sel('#ta-label').value.trim() || 'sig1';

// ---------------------------------------------------------------- base, sign, verify

function setBase(text, isError) {
  const $base = $sel('#ta_sigbase');
  $base.value = text;
  $base.classList.toggle('is-error', !!isError);
}

function markOutputsStale(stale) {
  ['#ta_sig_input', '#ta_signature'].forEach(id => $sel(id).classList.toggle('stale', stale));
}

// Live preview of the signature base for the current inputs.
function previewBase() {
  try {
    const message = readMessage();
    renderComponentChoices(message);
    const params = buildSignatureParams(coveredComponents(), currentSignatureParams(Math.floor(Date.now() / 1000)));
    setBase(signatureBase(message, params));
  }
  catch (e) {
    setBase(e.message, true);
  }
}

function onInputsChanged() {
  previewBase();
  markOutputsStale(true);
}

async function signMessage() {
  try {
    const alg = selectedAlg(),
          message = readMessage(),
          params = buildSignatureParams(coveredComponents(), currentSignatureParams(Math.floor(Date.now() / 1000))),
          base = signatureBase(message, params),
          signatureBytes = await sign(alg, await getKey(alg, 'sign'), base),
          fields = signatureFields(signatureLabel(), params, signatureBytes);
    setBase(base);
    $sel('#ta_sig_input').value = fields.signatureInput;
    $sel('#ta_signature').value = fields.signature;
    markOutputsStale(false);
    saveSetting('ta-keyid', $sel('#ta-keyid').value.trim());
  }
  catch (e) {
    console.log(e.stack);
    setAlert(e.message || String(e));
  }
}

function secondsAccuracyIsoString(t) {
  return t.toISOString().replace( new RegExp('\\\.\\d{3}Z$'), 'Z');
}

function timeProblems(params) {
  const nowDate = new Date(),
        nowSeconds = Math.floor(nowDate.valueOf() / 1000),
        reasons = [],
        notes = [];
  if (params.created && params.created > nowSeconds) {
    reasons.push('the created time is in the future');
  }
  if (params.expires) {
    let expiresString = secondsAccuracyIsoString(new Date(params.expires * 1000)),
        delta = nowSeconds - params.expires,
        timeUnit = quantify(delta, 'seconds');
    if (delta > 0) {
      reasons.push(`the expiry time (${expiresString}) is in the past, ${delta} ${timeUnit} ago`);
    }
    else {
      delta *= -1;
      notes.push('expires: ' + expiresString);
      notes.push('now: ' + secondsAccuracyIsoString(nowDate));
      notes.push(`time remaining: ${delta} ${timeUnit}`);
    }
  }
  return { reasons, notes };
}

// Sets the Content-Digest header (RFC 9530) from the message body.
async function setContentDigest() {
  try {
    const message = readMessage();
    if (message.body === undefined) {
      throw new Error('the message has no body; add a blank line after the headers, then the body');
    }
    const existing = message.fields.find(f => f.name == 'content-digest'),
          value = await contentDigestValue(message.body, digestAlgorithmOf(existing && existing.values[0])),
          $message = $sel('#ta_message');
    $message.value = setHeader($message.value, 'Content-Digest', value);
    saveSetting('ta_message', $message.value);
    onInputsChanged();
  }
  catch (e) {
    setAlert('cannot set Content-Digest: ' + (e.message || String(e)));
  }
}

// When Content-Digest is covered, a valid signature still says nothing about
// the body unless the digest matches it.
async function contentDigestWarning(message, signatureParams) {
  const covered = signatureParams.value.some(item => item.value == 'content-digest' && !(item.params || []).length),
        field = message.fields.find(f => f.name == 'content-digest');
  if (!covered || !field || message.body === undefined) {
    return '';
  }
  const matches = await contentDigestMatches(field.values.join(', '), message.body);
  return matches === false ? 'Content-Digest does not match the body' : '';
}

async function verifySignature() {
  try {
    const parsed = parseSignatureFields($sel('#ta_sig_input').value, $sel('#ta_signature').value, signatureLabel()),
          alg = parsed.params.alg || selectedAlg(),
          message = readMessage(),
          base = signatureBase(message, parsed.signatureParams);
    setBase(base);
    if (parsed.params.alg && parsed.params.alg != selectedAlg()) {
      throw new Error(`the signature uses alg="${parsed.params.alg}"; select that algorithm and supply its key`);
    }
    const isValid = await verify(alg, await getKey(alg, 'verify'), base, parsed.signatureBytes);
    if (!isValid) {
      setAlert(`The signature "${parsed.label}" is not valid.`, 'warning');
      return;
    }
    const { reasons, notes } = timeProblems(parsed.params),
          digestWarning = await contentDigestWarning(message, parsed.signatureParams);
    if (digestWarning) {
      reasons.push(digestWarning);
    }
    if (reasons.length == 0) {
      setAlert(`The signature "${parsed.label}" is valid. ` + notes.join('; '), 'success');
    }
    else {
      setAlert(`The signature "${parsed.label}" is valid, but ` + reasons.join('; '), 'warning');
    }
  }
  catch (e) {
    setAlert('cannot verify: ' + (e.message || String(e)));
  }
}

// ---------------------------------------------------------------- page plumbing

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

function handlePaste(e) {
  const elt = e.currentTarget;
  setTimeout(function () {
    elt.value = reformIndents(elt.value);
    onKeyEdited(e);
  }, 100);
}

function onKeyEdited(event) {
  const flavor = event.currentTarget.id == 'ta_privatekey' ? 'private' : 'public',
        family = selectedFamily();
  if (family != 'hmac') {
    storeKeyValue(flavor, family, event.currentTarget.value);
  }
  markOutputsStale(true);
}

// Show the key inputs and settings that apply to the selected algorithm.
function updateUiForAlg() {
  const family = selectedFamily();
  setVisible('#privatekey', family != 'hmac');
  setVisible('#publickey', family != 'hmac');
  setVisible('#symmetrickey', family == 'hmac');
  setVisible('#pbkdf2_params', family == 'hmac' && selectedText('#sel-symkey-coding') == 'PBKDF2');
  if (family != 'hmac') {
    showKeysForFamily(family);
  }
}

function onChangeAlg() {
  saveSetting('sel-alg', selectedAlg());
  updateUiForAlg();
  if (keysMissingFor(selectedFamily())) {
    newKey();
  }
  onInputsChanged();
}

function onChangeSymmetricKeyCoding() {
  saveSetting('sel-symkey-coding', selectedText('#sel-symkey-coding'));
  updateUiForAlg();
  markOutputsStale(true);
}

function onChangeNonce(event) {
  saveSetting('chk-nonce', String(event.currentTarget.checked));
  saveSetting('nonce-value', event.currentTarget.checked ? randomNonce() : '');
  onInputsChanged();
}

function retrieveLocalState() {
  Object.keys(datamodel)
    .forEach(key => {
      const value = storage.get(key);
      if (value === null) {
        return; // nothing stored yet; keep the default
      }
      datamodel[key] = key.startsWith('chk-') ? value == 'true' : value;
    });
}

function applyState() {
  Object.keys(datamodel)
    .forEach(key => {
      const value = datamodel[key],
            $item = $sel('#' + key);
      if (!$item) {
        return; // stored values without a matching element, e.g. per-family keys
      }
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
  if (!$sel('#ta_message').value.trim()) {
    $sel('#ta_message').value = defaultMessage;
  }
  updateUiForAlg();
  applyDarkMode();
}

function applyDarkMode() {
  document.body.classList.toggle('dark-mode', $sel('#chk-darkmode').checked);
}

document.addEventListener('DOMContentLoaded', () => {
  $sel('#version_id').textContent = BUILD_VERSION;
  $all('.btn-copy').forEach(btn => btn.addEventListener('click', copyToClipboard));
  $sel('.btn-sign').addEventListener('click', signMessage);
  $sel('.btn-verify').addEventListener('click', verifySignature);
  $sel('.btn-digest').addEventListener('click', setContentDigest);
  $all('.btn-newkey').forEach(btn => btn.addEventListener('click', newKey));

  retrieveLocalState();
  applyState();

  ['#ta_privatekey', '#ta_publickey'].forEach(id => {
    $sel(id).addEventListener('paste', handlePaste);
    $sel(id).addEventListener('input', onKeyEdited);
  });
  // Text inputs that are persisted and feed the signature base.
  ['#ta_message', '#ta-label', '#ta-keyid', '#ta-tag'].forEach(id =>
    $sel(id).addEventListener('input', e => {
      saveSetting(e.currentTarget.id, e.currentTarget.value);
      onInputsChanged();
    }));
  $sel('#ta_symmetrickey').addEventListener('input', e => {
    saveSetting('ta_symmetrickey', e.currentTarget.value);
    markOutputsStale(true);
  });
  ['#chk-created', '#chk-alg'].forEach(id =>
    $sel(id).addEventListener('change', e => {
      saveSetting(e.currentTarget.id, String(e.currentTarget.checked));
      onInputsChanged();
    }));
  $sel('#chk-nonce').addEventListener('change', onChangeNonce);
  $sel('#chk-darkmode').addEventListener('change', e => {
    saveSetting('chk-darkmode', String(e.currentTarget.checked));
    applyDarkMode();
  });
  $sel('#sel-expiry').addEventListener('change', () => {
    saveSetting('sel-expiry', selectedText('#sel-expiry'));
    onInputsChanged();
  });
  $sel('#sel-symkey-coding').addEventListener('change', onChangeSymmetricKeyCoding);
  $sel('#sel-alg').addEventListener('change', onChangeAlg);

  if (!datamodel['sel-alg']) {
    saveSetting('sel-alg', selectedAlg()); // default
  }
  if (keysMissingFor(selectedFamily())) {
    newKey();
  }
  previewBase();
});

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
