/**
 * Homoglyph normalization — maps visually similar Unicode characters to ASCII.
 */

// Cyrillic, Greek, and fullwidth characters that look like Latin letters
const HOMOGLYPH_MAP = {
  // Cyrillic lowercase
  '\u0430': 'a', // а
  '\u0441': 'c', // с
  '\u0435': 'e', // е
  '\u043E': 'o', // о
  '\u0440': 'p', // р
  '\u0445': 'x', // х
  '\u0443': 'y', // у
  '\u0456': 'i', // і
  '\u0455': 's', // ѕ
  '\u0458': 'j', // ј
  '\u043A': 'k', // к (close enough in some fonts)
  '\u043D': 'h', // н (looks like h in some fonts)
  '\u0442': 't', // т (in some serif fonts)
  '\u0432': 'b', // в (looks like b in some fonts)
  '\u0433': 'r', // г (looks like r in some fonts)
  '\u0437': '3', // з (looks like 3)
  '\u0456': 'i', // і (Ukrainian i)
  '\u0491': 'r', // ґ

  // Cyrillic uppercase
  '\u0410': 'a', // А
  '\u0412': 'b', // В
  '\u0421': 'c', // С
  '\u0415': 'e', // Е
  '\u041D': 'h', // Н
  '\u0406': 'i', // І
  '\u0408': 'j', // Ј
  '\u041A': 'k', // К
  '\u041C': 'm', // М
  '\u041E': 'o', // О
  '\u0420': 'p', // Р
  '\u0405': 's', // Ѕ
  '\u0422': 't', // Т
  '\u0425': 'x', // Х
  '\u0423': 'y', // У

  // Greek lowercase
  '\u03BF': 'o', // ο
  '\u03B1': 'a', // α
  '\u03BD': 'v', // ν
  '\u03C1': 'p', // ρ
  '\u03B5': 'e', // ε
  '\u03B9': 'i', // ι
  '\u03BA': 'k', // κ
  '\u03C4': 't', // τ (in some fonts)

  // Greek uppercase
  '\u0391': 'a', // Α
  '\u0392': 'b', // Β
  '\u0395': 'e', // Ε
  '\u0397': 'h', // Η
  '\u0399': 'i', // Ι
  '\u039A': 'k', // Κ
  '\u039C': 'm', // Μ
  '\u039D': 'n', // Ν
  '\u039F': 'o', // Ο
  '\u03A1': 'p', // Ρ
  '\u03A4': 't', // Τ
  '\u03A5': 'y', // Υ
  '\u03A7': 'x', // Χ
  '\u0396': 'z', // Ζ

  // Fullwidth period
  '\uFF0E': '.',

  // Common symbols
  '\u2024': '.', // one dot leader
  '\u2025': '..', // two dot leader
  '\u00B7': '.', // middle dot (sometimes used as period)
};

// Add fullwidth Latin letters (U+FF21-FF3A uppercase, U+FF41-FF5A lowercase)
(function () {
  for (let i = 0; i < 26; i++) {
    // Fullwidth uppercase A-Z → lowercase a-z
    HOMOGLYPH_MAP[String.fromCharCode(0xFF21 + i)] = String.fromCharCode(0x61 + i);
    // Fullwidth lowercase a-z → lowercase a-z
    HOMOGLYPH_MAP[String.fromCharCode(0xFF41 + i)] = String.fromCharCode(0x61 + i);
  }
  // Fullwidth digits 0-9
  for (let i = 0; i < 10; i++) {
    HOMOGLYPH_MAP[String.fromCharCode(0xFF10 + i)] = String.fromCharCode(0x30 + i);
  }
})();

/**
 * Replaces homoglyph characters with ASCII equivalents and lowercases the result.
 * @param {string} str - Input string possibly containing homoglyphs
 * @returns {string} Normalized ASCII-lowercase string
 */
function normalizeToAscii(str) {
  if (!str) return '';
  let result = '';
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    result += HOMOGLYPH_MAP[ch] || ch;
  }
  return result.toLowerCase();
}
