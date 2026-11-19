// Luau -> Lua 5.3 preprocessor (token-aware: preserves strings & comments)

function preprocessLuau(src) {
  const out = [];
  const n = src.length;
  let i = 0;

  // Track last statement boundary in `out` for compound assignments
  let stmtStartOutIdx = 0;

  function isIdentStart(ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_';
  }
  function isIdentChar(ch) {
    return isIdentStart(ch) || (ch >= '0' && ch <= '9');
  }
  function isDigit(ch) {
    return ch >= '0' && ch <= '9';
  }
  function isHex(ch) {
    return isDigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
  }

  function skipLongBracket(pos) {
    if (src[pos] !== '[') return -1;
    let eq = 0;
    let p = pos + 1;
    while (p < n && src[p] === '=') { eq++; p++; }
    if (p < n && src[p] === '[') return { eq, contentStart: p + 1 };
    return -1;
  }

  function findLongEnd(start, eq) {
    let p = start;
    while (p < n) {
      if (src[p] === ']') {
        let k = 0;
        let q = p + 1;
        while (k < eq && q < n && src[q] === '=') { k++; q++; }
        if (k === eq && q < n && src[q] === ']') return q + 1;
      }
      p++;
    }
    return n;
  }

  // Simple token scanner to find matching RHS end for compound assignment
  function readRhsExpr(startPos) {
    let p = startPos;
    let paren = 0, brack = 0, brace = 0;
    const stopKws = new Set(['end', 'else', 'elseif', 'until', 'then', 'do', 'local', 'for', 'while', 'repeat', 'if', 'return', 'function']);
    let sawToken = false;
    let lastWasOp = false;
    while (p < n) {
      const ch = src[p];
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') { p++; continue; }
      if (ch === '-' && src[p + 1] === '-') {
        const lb = skipLongBracket(p + 2);
        if (lb !== -1) p = findLongEnd(lb.contentStart, lb.eq);
        else { while (p < n && src[p] !== '\n') p++; }
        continue;
      }
      if (paren === 0 && brack === 0 && brace === 0) {
        if (ch === ';') break;
      }
      if (ch === '"' || ch === "'") {
        const q = ch; p++;
        while (p < n && src[p] !== q) {
          if (src[p] === '\\') p += 2; else p++;
        }
        if (p < n) p++;
        sawToken = true; lastWasOp = false; continue;
      }
      const lb = skipLongBracket(p);
      if (lb !== -1) {
        p = findLongEnd(lb.contentStart, lb.eq);
        sawToken = true; lastWasOp = false; continue;
      }
      if (ch === '(') { paren++; p++; sawToken = true; lastWasOp = true; continue; }
      if (ch === ')') {
        if (paren === 0 && brack === 0 && brace === 0) break;
        paren--; p++; sawToken = true; lastWasOp = false; continue;
      }
      if (ch === '[') { brack++; p++; sawToken = true; lastWasOp = true; continue; }
      if (ch === ']') {
        if (paren === 0 && brack === 0 && brace === 0) break;
        brack--; p++; sawToken = true; lastWasOp = false; continue;
      }
      if (ch === '{') { brace++; p++; sawToken = true; lastWasOp = true; continue; }
      if (ch === '}') {
        if (paren === 0 && brack === 0 && brace === 0) break;
        brace--; p++; sawToken = true; lastWasOp = false; continue;
      }
      if (isIdentStart(ch)) {
        let q = p + 1;
        while (q < n && isIdentChar(src[q])) q++;
        const word = src.slice(p, q);
        if (paren === 0 && brack === 0 && brace === 0) {
          if (stopKws.has(word)) break;
          // Statement boundary: two adjacent non-keyword identifiers/calls without an operator
          if (sawToken && !lastWasOp && word !== 'and' && word !== 'or') {
            // Check if previous non-space wasn't '.' or ':'
            break;
          }
        }
        p = q;
        sawToken = true;
        lastWasOp = (word === 'and' || word === 'or' || word === 'not');
        continue;
      }
      if (isDigit(ch)) {
        if (paren === 0 && brack === 0 && brace === 0 && sawToken && !lastWasOp) break;
        let q = p + 1;
        while (q < n && (isIdentChar(src[q]) || src[q] === '.')) q++;
        p = q; sawToken = true; lastWasOp = false; continue;
      }
      if (ch === '.' && src[p + 1] === '.') {
        p += 2; lastWasOp = true; continue;
      }
      if (ch === '.' || ch === ':') {
        p++; lastWasOp = true; continue;
      }
      if (ch === '/' && src[p + 1] === '/') {
        p += 2; lastWasOp = true; continue;
      }
      if ('+-*/%^<>~='.includes(ch)) {
        if ((ch === '<' || ch === '>' || ch === '~' || ch === '=') && src[p + 1] === '=') p += 2;
        else p++;
        lastWasOp = true; continue;
      }
      if (ch === ',' && paren === 0 && brack === 0 && brace === 0) break;
      p++;
    }
    return p;
  }

  // Track simple token stream for LHS extraction on += -= etc.
  const tokens = []; // { type, text, outIdx }
  const forStack = []; // { state: 'vars'|'expr', inOutIdx, paren, brack, brace }
  while (i < n) {
    const ch = src[i];

    // Whitespace
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
      let j = i + 1;
      while (j < n && (src[j] === ' ' || src[j] === '\t' || src[j] === '\r' || src[j] === '\n')) j++;
      out.push(src.slice(i, j));
      i = j;
      continue;
    }

    // Comments
    if (ch === '-' && src[i + 1] === '-') {
      const lb = skipLongBracket(i + 2);
      const end = lb !== -1 ? findLongEnd(lb.contentStart, lb.eq) : (() => { let p = i + 2; while (p < n && src[p] !== '\n') p++; return p; })();
      out.push(src.slice(i, end));
      i = end;
      continue;
    }

    // Quoted strings
    if (ch === '"' || ch === "'") {
      const q = ch;
      let j = i + 1;
      while (j < n && src[j] !== q) {
        if (src[j] === '\\') j += 2; else j++;
      }
      if (j < n) j++;
      const s = src.slice(i, j);
      tokens.push({ type: 'str', text: s, outIdx: out.length });
      out.push(s);
      i = j;
      continue;
    }

    // Long strings
    const lb = skipLongBracket(i);
    if (lb !== -1) {
      const end = findLongEnd(lb.contentStart, lb.eq);
      const s = src.slice(i, end);
      tokens.push({ type: 'str', text: s, outIdx: out.length });
      out.push(s);
      i = end;
      continue;
    }

    // Numbers (handle 0b... and underscores)
    if (isDigit(ch) || (ch === '.' && i + 1 < n && isDigit(src[i + 1]))) {
      let text;
      if (ch === '0' && (src[i + 1] === 'b' || src[i + 1] === 'B')) {
        let j = i + 2;
        while (j < n && (src[j] === '0' || src[j] === '1' || src[j] === '_')) j++;
        const bits = src.slice(i + 2, j).replace(/_/g, '');
        text = BigInt('0b' + (bits || '0')).toString(10) + '.0';
        i = j;
      } else if (ch === '0' && (src[i + 1] === 'x' || src[i + 1] === 'X')) {
        let j = i + 2;
        while (j < n && (isHex(src[j]) || src[j] === '_')) j++;
        const hex = src.slice(i + 2, j).replace(/_/g, '');
        text = BigInt('0x' + (hex || '0')).toString(10) + '.0';
        i = j;
      } else {
        let j = i;
        while (j < n && (isDigit(src[j]) || src[j] === '_' || src[j] === '.')) j++;
        if (j < n && (src[j] === 'e' || src[j] === 'E')) {
          j++;
          if (j < n && (src[j] === '+' || src[j] === '-')) j++;
          while (j < n && (isDigit(src[j]) || src[j] === '_')) j++;
        }
        text = src.slice(i, j).replace(/_/g, '');
        if (!text.includes('.') && !/[eE]/.test(text)) {
          text += '.0';
        }
        i = j;
      }
      tokens.push({ type: 'num', text, outIdx: out.length });
      out.push(text);
      continue;
    }

    // Identifiers / keywords
    if (isIdentStart(ch)) {
      let j = i + 1;
      while (j < n && isIdentChar(src[j])) j++;
      const word = src.slice(i, j);
      const topFor = forStack.length > 0 ? forStack[forStack.length - 1] : null;
      if (word === 'for') {
        forStack.push({ state: 'vars', inOutIdx: -1, paren: 0, brack: 0, brace: 0 });
      } else if (topFor && topFor.paren === 0 && topFor.brack === 0 && topFor.brace === 0) {
        if (topFor.state === 'vars' && word === 'in') {
          topFor.state = 'expr';
          topFor.inOutIdx = out.length;
        } else if (word === 'do') {
          if (topFor.state === 'expr') {
            out[topFor.inOutIdx] = 'in __luau_iter(';
            out.push(') ');
          }
          forStack.pop();
        }
      }
      tokens.push({ type: 'id', text: word, outIdx: out.length });
      out.push(word);
      i = j;
      continue;
    }

    // Compound assignment: += -= *= /= %= ..=
    const two = src.slice(i, i + 2);
    const three = src.slice(i, i + 3);
    let compOp = null, opLen = 0;
    if (three === '..=') { compOp = '..'; opLen = 3; }
    else if (three === '//=') { compOp = '//'; opLen = 3; }
    else if (two === '+=') { compOp = '+'; opLen = 2; }
    else if (two === '-=') { compOp = '-'; opLen = 2; }
    else if (two === '*=') { compOp = '*'; opLen = 2; }
    else if (two === '/=') { compOp = '/'; opLen = 2; }
    else if (two === '%=') { compOp = '%'; opLen = 2; }
    else if (two === '^=') { compOp = '^'; opLen = 2; }

    if (compOp) {
      // Find LHS tokens walking backwards in `tokens`
      let ti = tokens.length - 1;
      let bDepth = 0, pDepth = 0;
      while (ti >= 0) {
        const tk = tokens[ti];
        if (tk.text === ']') bDepth++;
        else if (tk.text === '[') { if (bDepth > 0) bDepth--; else break; }
        else if (tk.text === ')') pDepth++;
        else if (tk.text === '(') { if (pDepth > 0) pDepth--; else break; }
        else if (bDepth === 0 && pDepth === 0) {
          if (tk.type === 'id' || tk.text === '.') {
            // Stop at keywords like do, then, else, ;, =, etc.
            if (tk.type === 'id' && ['do', 'then', 'else', 'elseif', 'local', 'return', 'end', 'in', 'repeat', 'until'].includes(tk.text)) break;
            // If previous token before an identifier isn't '.' or '[', check if current is start of LHS
            const prev = ti > 0 ? tokens[ti - 1] : null;
            if (tk.type === 'id' && prev && prev.text !== '.' && prev.text !== ':' && prev.text !== '[') {
              ti--;
              break;
            }
          } else {
            break;
          }
        }
        ti--;
      }
      const lhsStartOutIdx = tokens[ti + 1].outIdx;
      const lhsStr = out.slice(lhsStartOutIdx).join('');
      const rhsEnd = readRhsExpr(i + opLen);
      const rhsRaw = src.slice(i + opLen, rhsEnd);
      const rhsPre = preprocessLuau(rhsRaw);
      out.push(` = ${lhsStr} ${compOp} (${rhsPre})`);
      i = rhsEnd;
      continue;
    }

    // Multi-char operators
    if (two === '//' || two === '..' || two === '==' || two === '~=' || two === '<=' || two === '>=') {
      tokens.push({ type: 'op', text: two, outIdx: out.length });
      out.push(two);
      i += 2;
      continue;
    }

    const topFor = forStack.length > 0 ? forStack[forStack.length - 1] : null;
    if (topFor) {
      if (ch === '(') topFor.paren++;
      else if (ch === ')' && topFor.paren > 0) topFor.paren--;
      else if (ch === '[') topFor.brack++;
      else if (ch === ']' && topFor.brack > 0) topFor.brack--;
      else if (ch === '{') topFor.brace++;
      else if (ch === '}' && topFor.brace > 0) topFor.brace--;
      else if (ch === '=' && topFor.state === 'vars' && topFor.paren === 0 && topFor.brack === 0 && topFor.brace === 0) {
        topFor.state = 'num';
      }
    }

    tokens.push({ type: 'op', text: ch, outIdx: out.length });
    out.push(ch);
    i++;
  }

  return out.join('');
}

module.exports = { preprocessLuau };
