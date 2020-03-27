// SignatureParser.js
// ------------------------------------------------------------------
//
// created: Fri Mar 27 12:37:23 2020
// last saved: <2020-March-27 14:35:21>

/* jshint esversion:9, node:true, strict:implied */
/* global process, console, Buffer */

const ParseState = {
      BEGIN : 0,
      NAME : 1,
      VALUE : 2,
      COMMA : 3,
      QUOTE : 4,
      INTEGER : 5
    };
const requiredHdrParams = ['algorithm', 'keyId', 'headers', 'signature'];
const validHdrParams = requiredHdrParams.concat(['created','expires']);
const validAlgorithms = ['rsa-sha256', 'hmac-sha256', 'hs2019'];

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

const parseHttpSigHeader = function(str) {
        str = str.trim();
        const re1 = new RegExp('^Signature +(.+)$');
        let m = re1.exec(str);
        if ( ! m || !m[1]) {
          throw new Error("malformed Signature header?");
        }
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

        requiredHdrParams.forEach(key => {
          if ( ! parsed[key])
            throw new Error('missing ' + key);
        });

        Object.keys(parsed).forEach(key => {
          if ( ! validHdrParams.includes(key))
            throw new Error('unsupported header parameter: ' + key);
        });

        if (validAlgorithms.indexOf(parsed.algorithm) < 0) {
          throw new Error('bad algorithm');
        }

        return parsed;
      };


module.exports = {
  parse: parseHttpSigHeader,
  validAlgorithms
};
