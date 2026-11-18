// Dynamic SnowVeil V3 (SVBG CFG) -> Clean Luau Decompiler

function fmtConst(c) {
  if (!c || c.t === 'nil') return 'nil';
  if (c.t === 'bool') return c.v ? 'true' : 'false';
  if (c.t === 'num') return String(c.v);
  if (c.t === 'str') return JSON.stringify(c.v);
  return String(c.v ?? 'nil');
}

function isIdent(s) {
  return typeof s === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(s);
}

function isSimpleExpr(e) {
  if (!e) return true;
  if (e.simple) return true;
  return /^[A-Za-z0-9_."'\[\]()]+$/.test(e.code);
}

function wrapParens(e) {
  if (!e) return 'nil';
  if (e.simple || /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*(\([^)]*\))?$/.test(e.code)) return e.code;
  if (/^(".*"|\d+(\.\d+)?|true|false|nil)$/.test(e.code)) return e.code;
  return `(${e.code})`;
}

// Lift every block in a proto into structured IR instructions
function liftBlock(blk, proto, recipes, opSemantics) {
  const consts = proto.consts;
  const fields = blk.fields || [];
  const opKinds = blk.operandKinds || [];
  const ops = blk.operands || [];
  const imms = blk.immediates || [];
  const ir = [];

  for (let ri = 0; ri < blk.count; ri++) {
    const sel = blk.selectors[ri];
    const recipe = recipes[sel] || [];
    const sem = opSemantics[sel];
    const steps = sem?.steps || [];
    const baseField = blk.starts[ri] - 1; // 0-based into fields

    for (let si = 0; si < recipe.length; si++) {
      const stepName = steps[si] || 'UNKNOWN_STEP';
      const ao = baseField + si * 5;
      const opBase = fields[ao] - 1;       // 0-based into opKinds/ops
      const immBase = fields[ao + 1] - 1;  // 0-based into imms
      const scrDst = fields[ao + 2];       // 1-based scratch slot (0 = none)
      const outKind = fields[ao + 3];      // 0 = none, 1 = reg, 2 = upval
      const outIdx = fields[ao + 4];       // 0-based reg/upval

      const readY = (k) => ({
        kind: opKinds[opBase + k],
        val: ops[opBase + k]
      });

      ir.push({
        stepName,
        opBase,
        immBase,
        scrDst,
        outKind,
        outIdx,
        readY,
        ops,
        imms,
        consts
      });
    }
  }

  // Terminal
  const ti = blk.count;
  const termSel = blk.selectors[ti];
  const termSem = opSemantics[termSel];
  const termAo = blk.starts[ti] - 1;
  const termOpBase = fields[termAo] - 1;
  const termImmBase = fields[termAo + 1] - 1;

  return {
    token: blk.token,
    nextToken: blk.nextToken,
    targetToken: blk.targetToken,
    ir,
    term: {
      op: termSem?.op || 'UNKNOWN_TERM',
      sel: termSel,
      opBase: termOpBase,
      immBase: termImmBase,
      ops,
      imms
    }
  };
}

// Compute post-dominators / reachable sets for structuring if/else/while
function buildCFGInfo(liftedMap, entryTok) {
  const reachable = new Set();
  const order = [];
  const preds = new Map();
  const succs = new Map();

  function addEdge(u, v) {
    if (!v) return;
    if (!succs.has(u)) succs.set(u, []);
    if (!succs.get(u).includes(v)) succs.get(u).push(v);
    if (!preds.has(v)) preds.set(v, []);
    if (!preds.get(v).includes(u)) preds.get(v).push(u);
  }

  const stack = [entryTok];
  while (stack.length > 0) {
    const t = stack.pop();
    if (!t || reachable.has(t) || !liftedMap.has(t)) continue;
    reachable.add(t);
    order.push(t);
    const b = liftedMap.get(t);
    const op = b.term.op;
    if (op === 'RETURN' || op === 'TAILCALL') continue;
    if (op === 'JUMPIFNOT' || op === 'JUMPIF') {
      addEdge(t, b.nextToken);
      addEdge(t, b.targetToken);
      stack.push(b.targetToken, b.nextToken);
    } else if (op === 'TFORLOOP' || op === 'FORLOOP' || op === 'FORNPREP') {
      addEdge(t, b.targetToken);
      addEdge(t, b.nextToken);
      stack.push(b.nextToken, b.targetToken);
    } else if (b.nextToken) {
      addEdge(t, b.nextToken);
      stack.push(b.nextToken);
    }
  }

  // Detect natural loops via back-edges (u -> h where h dominates u)
  const allNodes = [...reachable];
  const dom = new Map();
  for (const n of allNodes) dom.set(n, n === entryTok ? new Set([entryTok]) : new Set(allNodes));
  let changed = true;
  while (changed) {
    changed = false;
    for (const n of allNodes) {
      if (n === entryTok) continue;
      const ps = (preds.get(n) || []).filter(p => reachable.has(p));
      if (ps.length === 0) continue;
      let inter = new Set(dom.get(ps[0]));
      for (let i = 1; i < ps.length; i++) {
        const dp = dom.get(ps[i]);
        for (const x of [...inter]) {
          if (!dp.has(x)) inter.delete(x);
        }
      }
      inter.add(n);
      if (inter.size !== dom.get(n).size) {
        dom.set(n, inter);
        changed = true;
      }
    }
  }

  // Back-edges: u -> h where dom[u].has(h)
  const loopHeaders = new Map(); // headerTok -> { backSources: Set, body: Set, exitTok }
  for (const u of allNodes) {
    for (const h of (succs.get(u) || [])) {
      if (dom.get(u)?.has(h)) {
        if (!loopHeaders.has(h)) {
          loopHeaders.set(h, { backSources: new Set(), body: new Set([h]), exitTok: null });
        }
        loopHeaders.get(h).backSources.add(u);
      }
    }
  }
  for (const [h, info] of loopHeaders.entries()) {
    const q = [...info.backSources];
    while (q.length > 0) {
      const x = q.pop();
      if (info.body.has(x)) continue;
      info.body.add(x);
      for (const p of (preds.get(x) || [])) {
        if (reachable.has(p)) q.push(p);
      }
    }
    // Exit target = successor of header (or body node) outside loop body
    const hdrBlk = liftedMap.get(h);
    if (hdrBlk && (hdrBlk.term.op === 'JUMPIFNOT' || hdrBlk.term.op === 'JUMPIF')) {
      const s1 = hdrBlk.nextToken, s2 = hdrBlk.targetToken;
      info.exitTok = !info.body.has(s1) ? s1 : (!info.body.has(s2) ? s2 : null);
    } else {
      for (const bn of info.body) {
        const bb = liftedMap.get(bn);
        if (bb?.term.op === 'TFORLOOP' && !info.body.has(bb.nextToken)) {
          info.exitTok = bb.nextToken;
          break;
        }
      }
    }
  }

  // Compute immediate post-dominator map for if/else merge detection
  // Walk reverse CFG from nodes with out-degree 0
  const exitNodes = allNodes.filter(n => (succs.get(n) || []).length === 0);
  const pdom = new Map();
  for (const n of allNodes) {
    pdom.set(n, exitNodes.includes(n) ? new Set([n]) : new Set(allNodes));
  }
  changed = true;
  while (changed) {
    changed = false;
    for (const n of allNodes) {
      const ss = (succs.get(n) || []).filter(s => reachable.has(s));
      if (ss.length === 0) continue;
      let inter = new Set(pdom.get(ss[0]));
      for (let i = 1; i < ss.length; i++) {
        const ds = pdom.get(ss[i]);
        for (const x of [...inter]) {
          if (!ds.has(x)) inter.delete(x);
        }
      }
      inter.add(n);
      if (inter.size !== pdom.get(n).size) {
        pdom.set(n, inter);
        changed = true;
      }
    }
  }

  // Forward-only reachability (do not traverse across loop back-edges u -> h)
  const reachFrom = new Map();
  for (const start of reachable) {
    const seen = new Set();
    const q = [start];
    while (q.length > 0) {
      const u = q.pop();
      if (seen.has(u)) continue;
      seen.add(u);
      for (const v of (succs.get(u) || [])) {
        if (dom.get(u)?.has(v)) seen.add(v);
        else q.push(v);
      }
    }
    reachFrom.set(start, seen);
  }

  function findMerge(b1, b2, stopSet = null) {
    if (!b1 || !b2) return null;
    if (b1 === b2) return b1;
    if (stopSet && stopSet.has(b2)) return b2;
    if (stopSet && stopSet.has(b1)) return b1;
    const r2 = reachFrom.get(b2);
    if (!r2) return null;
    const seen = new Set();
    const q = [b1];
    while (q.length > 0) {
      const cur = q.shift();
      if (seen.has(cur)) continue;
      seen.add(cur);
      if (r2.has(cur)) return cur;
      for (const s of (succs.get(cur) || [])) {
        if (!dom.get(cur)?.has(s)) q.push(s);
      }
    }
    return null;
  }

  return { reachable, preds, succs, dom, pdom, loopHeaders, findMerge };
}

function decompileSV3Proto(proto, recipes, opSemantics, allProtos, outerUpvals = [], indent = '') {
  const liftedMap = new Map();
  for (const blk of proto.blocks) {
    liftedMap.set(blk.token, liftBlock(blk, proto, recipes, opSemantics));
  }
  const cfg = buildCFGInfo(liftedMap, proto.entry);
  const consts = proto.consts;

  const cellSet = new Set(proto.cells || []);
  const boundCells = new Set();

  // Pre-count how many times each register is referenced across blocks, or if it's a closure/mutable
  function initEnv() {
    const regs = {};
    for (let i = 0; i < proto.params; i++) {
      regs[i] = { code: `p${i + 1}`, simple: true, isParam: true };
    }
    const upvals = {};
    for (let i = 0; i < (proto.captures || []).length; i++) {
      if (outerUpvals[i]) {
        upvals[i] = outerUpvals[i];
      } else {
        upvals[i] = { code: `up_${i}`, simple: true };
      }
    }
    return { regs, upvals, scratch: {}, scratchReg: {}, top: proto.params, localCounter: 0 };
  }

  function cloneEnv(env) {
    return {
      regs: { ...env.regs },
      upvals: { ...env.upvals },
      scratch: { ...env.scratch },
      scratchReg: { ...(env.scratchReg || {}) },
      top: env.top,
      localCounter: env.localCounter
    };
  }

  let varSeq = 0;
  function freshVar(prefix = 'v') {
    varSeq++;
    return `${prefix}${varSeq}`;
  }

  // Check if register has a table literal accumulator we can fold `{ ... }`
  function resolveOperand(y, env) {
    const { kind, val } = y;
    switch (kind) {
      case 1: return env.scratch[val] || { code: 'nil', simple: true };
      case 2: return env.regs[val] || { code: 'nil', simple: true };
      case 3: return env.upvals[val] || { code: `up_${val}`, simple: true };
      case 4: {
        const c = consts[val] || { t: 'nil' };
        return { code: fmtConst(c), simple: true, constVal: c };
      }
      case 5: return { code: String(val), simple: true, constVal: { t: 'num', v: val } };
      case 6: return { code: val !== 0 ? 'true' : 'false', simple: true, constVal: { t: 'bool', v: val !== 0 } };
      case 7: return { code: 'nil', simple: true, constVal: { t: 'nil' } };
      default: return { code: 'nil', simple: true };
    }
  }

  function writeReg(env, reg, expr, lines, curIndent) {
    if (cellSet.has(reg)) {
      // Mutable captured local variable
      const cellName = env.regs[reg]?.cellName || `v_${proto.id}_${reg}`;
      if (!boundCells.has(reg)) {
        boundCells.add(reg);
        lines.push(`${curIndent}local ${cellName} = ${expr.code}`);
      } else if (expr.code !== cellName) {
        lines.push(`${curIndent}${cellName} = ${expr.code}`);
      }
      env.regs[reg] = { code: cellName, simple: true, isCell: true, cellName };
    } else {
      env.regs[reg] = expr;
    }
    if (reg + 1 > env.top) env.top = reg + 1;
  }

  function execBlockIR(b, env, lines, curIndent) {
    for (const st of b.ir) {
      const { stepName, opBase, immBase, scrDst, outKind, outIdx, readY, ops, imms } = st;
      let res = null;

      const writeStd = (valExpr) => {
        if (outKind === 1) writeReg(env, outIdx, valExpr, lines, curIndent);
        else if (outKind === 2) {
          const uName = env.upvals[outIdx]?.code || `up_${outIdx}`;
          lines.push(`${curIndent}${uName} = ${valExpr.code}`);
        }
        if (scrDst !== 0) env.scratch[scrDst] = valExpr;
      };

      switch (stepName) {
        case 'FUSED_MOVE': {
          const src = ops[opBase];
          const dst = imms[immBase];
          const val = env.regs[src] || { code: 'nil', simple: true };
          writeReg(env, dst, val, lines, curIndent);
          break;
        }
        case 'FUSED_LOADK': {
          const kIdx = ops[opBase];
          const dst = imms[immBase];
          const c = consts[kIdx] || { t: 'nil' };
          writeReg(env, dst, { code: fmtConst(c), simple: true, constVal: c }, lines, curIndent);
          break;
        }
        case 'FUSED_LOADBOOL': {
          const bv = ops[opBase] !== 0;
          const dst = imms[immBase];
          writeReg(env, dst, { code: bv ? 'true' : 'false', simple: true, constVal: { t: 'bool', v: bv } }, lines, curIndent);
          break;
        }
        case 'FUSED_LOADNIL': {
          const dst = imms[immBase];
          writeReg(env, dst, { code: 'nil', simple: true, constVal: { t: 'nil' } }, lines, curIndent);
          break;
        }
        case 'FUSED_GETUPVAL': {
          const uIdx = ops[opBase];
          const dst = imms[immBase];
          const val = env.upvals[uIdx] || { code: `up_${uIdx}`, simple: true };
          writeReg(env, dst, val, lines, curIndent);
          break;
        }
        case 'FUSED_STORE_REG': {
          const val = resolveOperand(readY(0), env);
          const dst = imms[immBase];
          writeReg(env, dst, val, lines, curIndent);
          break;
        }
        case 'FUSED_STORE_UPVAL':
        case 'FUSED_STORE_UPVAL_Y': {
          const val = resolveOperand(readY(0), env);
          const uDst = imms[immBase];
          const uName = env.upvals[uDst]?.code || `up_${uDst}`;
          if (!env.upvals[uDst]) env.upvals[uDst] = { code: uName, simple: true };
          lines.push(`${curIndent}${uName} = ${val.code}`);
          break;
        }
        case 'FUSED_STORE_UPVAL_R': {
          const val = env.regs[ops[opBase]] || { code: 'nil', simple: true };
          const uDst = imms[immBase];
          const uName = env.upvals[uDst]?.code || `up_${uDst}`;
          if (!env.upvals[uDst]) env.upvals[uDst] = { code: uName, simple: true };
          lines.push(`${curIndent}${uName} = ${val.code}`);
          break;
        }
        case 'FUSED_NEWTABLE': {
          const tblId = freshVar('t');
          const tblExpr = { code: '{}', simple: false, tableEntries: [], isNewTable: true, tblId, createdBlock: b.token };
          writeReg(env, outIdx, tblExpr, lines, curIndent);
          break;
        }
        case 'FUSED_GETGLOBAL':
        case 'FUSED_GETGLOBAL_Y': {
          const key = resolveOperand(readY(0), env);
          const gName = (key.constVal?.t === 'str' && isIdent(key.constVal.v))
            ? key.constVal.v
            : `_ENV[${key.code}]`;
          writeStd({ code: gName, simple: true });
          break;
        }
        case 'FUSED_GETGLOBAL_K': {
          const keyC = consts[ops[opBase]] || { t: 'nil' };
          const gName = (keyC.t === 'str' && isIdent(keyC.v))
            ? keyC.v
            : `_ENV[${fmtConst(keyC)}]`;
          writeReg(env, outIdx, { code: gName, simple: true }, lines, curIndent);
          break;
        }
        case 'FUSED_UNM': case 'FUSED_NOT': case 'FUSED_LEN': {
          const syms = { FUSED_NOT: 'not ', FUSED_LEN: '#', FUSED_UNM: '-' };
          const unop = stepName.slice(6);
          const a = resolveOperand(readY(0), env);
          writeStd({ code: `${syms[stepName]}${wrapParens(a)}`, simple: false, unop, operand: a });
          break;
        }
        case 'NEWCELL': {
          const reg = imms[immBase];
          cellSet.add(reg);
          if (!boundCells.has(reg)) {
            const cellName = `v_${proto.id}_${reg}`;
            boundCells.add(reg);
            lines.push(`${curIndent}local ${cellName}`);
            env.regs[reg] = { code: cellName, simple: true, isCell: true, cellName };
          }
          break;
        }
        case 'FUSED_GETTABLE_K': {
          const obj = env.regs[ops[opBase]] || { code: 'nil', simple: true };
          const keyC = consts[ops[opBase + 1]] || { t: 'nil' };
          const code = (keyC.t === 'str' && isIdent(keyC.v))
            ? `${wrapParens(obj)}.${keyC.v}`
            : `${wrapParens(obj)}[${fmtConst(keyC)}]`;
          writeReg(env, outIdx, { code, simple: true }, lines, curIndent);
          break;
        }
        case 'FUSED_SETTABLE_K': {
          const obj = env.regs[ops[opBase]] || { code: 'nil', simple: true };
          const keyC = consts[ops[opBase + 1]] || { t: 'nil' };
          const val = env.regs[ops[opBase + 2]] || { code: 'nil', simple: true };
          if (obj.isNewTable && obj.tableEntries) {
            obj.tableEntries.push({ key: keyC, val });
            obj.code = formatTableLiteral(obj.tableEntries);
          } else {
            const lhs = (keyC.t === 'str' && isIdent(keyC.v))
              ? `${wrapParens(obj)}.${keyC.v}`
              : `${wrapParens(obj)}[${fmtConst(keyC)}]`;
            lines.push(`${curIndent}${lhs} = ${val.code}`);
          }
          break;
        }
        case 'GETGLOBAL': {
          const key = resolveOperand(readY(0), env);
          const gName = (key.constVal?.t === 'str' && isIdent(key.constVal.v))
            ? key.constVal.v
            : `_ENV[${key.code}]`;
          writeStd({ code: gName, simple: true });
          break;
        }
        case 'SETGLOBAL': {
          const key = resolveOperand(readY(0), env);
          const val = resolveOperand(readY(1), env);
          const gName = (key.constVal?.t === 'str' && isIdent(key.constVal.v))
            ? key.constVal.v
            : `_ENV[${key.code}]`;
          lines.push(`${curIndent}${gName} = ${val.code}`);
          break;
        }
        case 'NEWTABLE': {
          const tblId = freshVar('t');
          writeStd({ code: '{}', simple: false, tableEntries: [], isNewTable: true, tblId, createdBlock: b.token });
          break;
        }
        case 'GETTABLE': {
          const obj = resolveOperand(readY(0), env);
          const key = resolveOperand(readY(1), env);
          const code = (key.constVal?.t === 'str' && isIdent(key.constVal.v))
            ? `${wrapParens(obj)}.${key.constVal.v}`
            : `${wrapParens(obj)}[${key.code}]`;
          writeStd({ code, simple: true });
          break;
        }
        case 'SETTABLE': {
          const obj = resolveOperand(readY(0), env);
          const key = resolveOperand(readY(1), env);
          const val = resolveOperand(readY(2), env);
          if (obj.isNewTable && obj.tableEntries) {
            obj.tableEntries.push({ key: key.constVal || { t: 'expr', code: key.code }, val });
            obj.code = formatTableLiteral(obj.tableEntries);
          } else {
            const lhs = (key.constVal?.t === 'str' && isIdent(key.constVal.v))
              ? `${wrapParens(obj)}.${key.constVal.v}`
              : `${wrapParens(obj)}[${key.code}]`;
            lines.push(`${curIndent}${lhs} = ${val.code}`);
          }
          break;
        }
        case 'ADD': case 'SUB': case 'MUL': case 'DIV': case 'IDIV': case 'MOD': case 'POW': case 'CONCAT':
        case 'EQ': case 'NEQ': case 'LT': case 'LE': case 'GT': case 'GE': {
          const syms = {
            ADD: '+', SUB: '-', MUL: '*', DIV: '/', IDIV: '//', MOD: '%', POW: '^', CONCAT: '..',
            EQ: '==', NEQ: '~=', LT: '<', LE: '<=', GT: '>', GE: '>='
          };
          const a = resolveOperand(readY(0), env);
          const b = resolveOperand(readY(1), env);
          writeStd({ code: `${wrapParens(a)} ${syms[stepName]} ${wrapParens(b)}`, simple: false, lhs: a, rhs: b, binop: stepName });
          break;
        }
        case 'NOT': case 'LEN': case 'UNM': {
          const syms = { NOT: 'not ', LEN: '#', UNM: '-' };
          const a = resolveOperand(readY(0), env);
          writeStd({ code: `${syms[stepName]}${wrapParens(a)}`, simple: false, unop: stepName, operand: a });
          break;
        }
        case 'MOVE_Y': {
          const a = resolveOperand(readY(0), env);
          writeStd(a);
          break;
        }
        case 'MOVE_REG': {
          const rIdx = imms[immBase];
          const a = env.regs[rIdx] || { code: 'nil', simple: true };
          writeStd(a);
          if (scrDst !== 0) {
            env.scratchReg = env.scratchReg || {};
            env.scratchReg[scrDst] = rIdx;
          }
          break;
        }
        default: {
          lines.push(`${curIndent}-- [unhandled step ${stepName}]`);
          break;
        }
      }
    }
  }

  function formatTableLiteral(entries) {
    if (entries.length === 0) return '{}';
    const parts = [];
    let seqIdx = 1;
    for (const e of entries) {
      if (e.key && e.key.t === 'num' && e.key.v === seqIdx) {
        parts.push(e.val.code);
        seqIdx++;
      } else if (e.key && e.key.t === 'str' && isIdent(e.key.v)) {
        parts.push(`${e.key.v} = ${e.val.code}`);
      } else if (e.key && e.key.t === 'expr') {
        parts.push(`[${e.key.code}] = ${e.val.code}`);
      } else {
        parts.push(`[${fmtConst(e.key)}] = ${e.val.code}`);
      }
    }
    if (parts.join(', ').length <= 80 && !parts.some(p => p.includes('\n'))) {
      return `{ ${parts.join(', ')} }`;
    }
    return `{\n    ${parts.join(',\n    ')}\n}`;
  }

  function execTerminal(b, env, lines, curIndent) {
    const t = b.term;
    const im = t.imms;
    const ib = t.immBase;
    switch (t.op) {
      case 'GETVARARGS': {
        const base = im[ib];
        const count = im[ib + 1];
        if (count === -1) {
          writeReg(env, base, { code: '...', simple: true }, lines, curIndent);
          env.top = base + 1;
        } else {
          for (let k = 0; k < count; k++) {
            writeReg(env, base + k, { code: '...', simple: true }, lines, curIndent);
          }
          env.top = base + count;
        }
        break;
      }
      case 'JMP': return;
      case 'SELF': {
        const base = im[ib];
        const methodK = consts[im[ib + 1]] || { t: 'nil' };
        const obj = env.regs[base + 1] || { code: 'nil', simple: true };
        const mName = (methodK.t === 'str' && isIdent(methodK.v)) ? methodK.v : fmtConst(methodK);
        env.regs[base] = {
          code: `${wrapParens(obj)}:${mName}`,
          simple: true,
          isSelfMethod: true,
          selfBase: base,
          selfObj: obj,
          methodName: mName
        };
        break;
      }
      case 'CALL': {
        const base = im[ib];
        const nArg = im[ib + 1];
        const nRet = im[ib + 2];
        const fn = env.regs[base] || { code: 'nil', simple: true };
        const args = [];
        const actualCount = nArg === -1 ? Math.max(0, env.top - base - 1) : nArg;
        const startArg = fn.isSelfMethod ? base + 2 : base + 1;
        for (let r = startArg; r < base + 1 + actualCount; r++) {
          args.push((env.regs[r] || { code: 'nil' }).code);
        }
        const callCode = `${fn.code}(${args.join(', ')})`;
        // Also materialize any unmaterialized fresh NEWTABLE passed into a multi-block call like table.insert(t, x)
        for (let r = startArg; r < base + 1 + actualCount; r++) {
          const argObj = env.regs[r];
          if (argObj?.isNewTable && !argObj.materialized) {
            const hasLoopOrMultiBlock = argObj.createdBlock && argObj.createdBlock !== b.token;
            if (hasLoopOrMultiBlock) {
              // Emit fallback if not already materialized at block exit
              lines.push(`${curIndent}local ${argObj.tblId} = ${argObj.code}`);
              argObj.code = argObj.tblId;
              argObj.simple = true;
              argObj.materialized = true;
              args[r - startArg] = argObj.tblId;
            }
          }
        }
        const fnCallExpr = fn.isClosure ? `(${fn.code})` : fn.code;
        const finalCallCode = `${fnCallExpr}(${args.join(', ')})`;
        if (nRet === 0) {
          lines.push(`${curIndent}${finalCallCode}`);
          env.top = base;
        } else if (nRet === 1) {
          const isPureGetter = fn.isSelfMethod && (fn.methodName === 'GetService' || fn.methodName === 'FindFirstChild' || fn.methodName === 'WaitForChild');
          if (isPureGetter && !cellSet.has(base)) {
            writeReg(env, base, { code: finalCallCode, simple: true }, lines, curIndent);
          } else if (cellSet.has(base)) {
            writeReg(env, base, { code: finalCallCode, simple: true }, lines, curIndent);
          } else {
            const v = freshVar('res');
            lines.push(`${curIndent}local ${v} = ${finalCallCode}`);
            writeReg(env, base, { code: v, simple: true }, lines, curIndent);
          }
          env.top = base + 1;
        } else if (nRet === -1) {
          writeReg(env, base, { code: finalCallCode, simple: false, isMultiRet: true }, lines, curIndent);
          env.top = base + 1;
        } else {
          const vs = [];
          for (let ri = 0; ri < nRet; ri++) {
            const v = freshVar('r');
            vs.push(v);
            env.regs[base + ri] = { code: v, simple: true };
          }
          lines.push(`${curIndent}local ${vs.join(', ')} = ${finalCallCode}`);
          env.top = base + nRet;
        }
        break;
      }
      case 'CALL2': {
        const fnReg = im[ib];
        const a1Reg = im[ib + 1];
        const a2Reg = im[ib + 2];
        const dstReg = im[ib + 3];
        const nRet = im[ib + 4];
        const fn = env.regs[fnReg] || { code: 'nil', simple: true };
        const a1 = env.regs[a1Reg] || { code: 'nil' };
        const a2 = env.regs[a2Reg] || { code: 'nil' };
        const callCode = fn.isSelfMethod
          ? `${fn.code}(${a2.code})`
          : `${fn.code}(${a1.code}, ${a2.code})`;
        if (nRet === 0) {
          lines.push(`${curIndent}${callCode}`);
        } else if (nRet === 1) {
          const isPureGetter = fn.isSelfMethod && (fn.methodName === 'GetService' || fn.methodName === 'FindFirstChild' || fn.methodName === 'WaitForChild');
          if (isPureGetter && !cellSet.has(dstReg)) {
            writeReg(env, dstReg, { code: callCode, simple: true }, lines, curIndent);
          } else if (cellSet.has(dstReg)) {
            writeReg(env, dstReg, { code: callCode, simple: true }, lines, curIndent);
          } else {
            const v = freshVar('res');
            lines.push(`${curIndent}local ${v} = ${callCode}`);
            writeReg(env, dstReg, { code: v, simple: true }, lines, curIndent);
          }
        } else {
          const vs = [];
          for (let ri = 0; ri < nRet; ri++) {
            const v = freshVar('r');
            vs.push(v);
            env.regs[dstReg + ri] = { code: v, simple: true };
          }
          lines.push(`${curIndent}local ${vs.join(', ')} = ${callCode}`);
        }
        break;
      }
      case 'SETLIST': {
        const tblReg = im[ib];
        const startIdx = im[ib + 1];
        const srcReg = im[ib + 2];
        const count = im[ib + 3];
        const tbl = env.regs[tblReg];
        const actualCount = count === -1 ? Math.max(0, env.top - srcReg) : count;
        if (tbl && tbl.isNewTable && tbl.tableEntries) {
          for (let k = 0; k < actualCount; k++) {
            tbl.tableEntries.push({
              key: { t: 'num', v: startIdx + k },
              val: env.regs[srcReg + k] || { code: 'nil', simple: true }
            });
          }
          tbl.code = formatTableLiteral(tbl.tableEntries);
        } else {
          for (let k = 0; k < actualCount; k++) {
            const v = env.regs[srcReg + k] || { code: 'nil' };
            lines.push(`${curIndent}${tbl ? tbl.code : 't'}[${startIdx + k}] = ${v.code}`);
          }
        }
        break;
      }
      case 'CLOSURE': {
        const dstReg = im[ib];
        const subId = im[ib + 1];
        const subProto = allProtos[subId];
        if (subProto) {
          const outerUps = (subProto.captures || []).map(cap => {
            if (cap[0] === 0) {
              const rIdx = cap[1];
              const existing = env.regs[rIdx];
              if (existing && /^[A-Za-z_][A-Za-z0-9_]*$/.test(existing.code)) return existing;
              return existing || { code: `local_${rIdx}`, simple: true };
            }
            return env.upvals[cap[1]] || { code: `up_${cap[1]}`, simple: true };
          });
          const pnames = [];
          for (let i = 0; i < subProto.params; i++) pnames.push(`p${i + 1}`);
          if (subProto.vararg) pnames.push('...');
          const subBody = decompileSV3Proto(subProto, recipes, opSemantics, allProtos, outerUps, curIndent + '    ');
          const fnCode = subBody.trim()
            ? `function(${pnames.join(', ')})\n${subBody}\n${curIndent}end`
            : `function(${pnames.join(', ')}) end`;
          writeReg(env, dstReg, { code: fnCode, simple: false, isClosure: true }, lines, curIndent);
        } else {
          writeReg(env, dstReg, { code: `function(...) end`, simple: false }, lines, curIndent);
        }
        break;
      }
      case 'RETURN': {
        const base = im[ib];
        const count = im[ib + 1];
        const actualCount = count === -1 ? Math.max(0, env.top - base) : count;
        const rets = [];
        for (let k = 0; k < actualCount; k++) {
          rets.push((env.regs[base + k] || { code: 'nil' }).code);
        }
        lines.push(`${curIndent}return${rets.length ? ' ' + rets.join(', ') : ''}`);
        break;
      }
      case 'TAILCALL': {
        const base = im[ib];
        const nArg = im[ib + 1];
        const fn = env.regs[base] || { code: 'nil', simple: true };
        const args = [];
        const actualCount = nArg === -1 ? Math.max(0, env.top - base - 1) : nArg;
        const startArg = fn.isSelfMethod ? base + 2 : base + 1;
        for (let r = startArg; r < base + 1 + actualCount; r++) {
          args.push((env.regs[r] || { code: 'nil' }).code);
        }
        const fnCallExpr = fn.isClosure ? `(${fn.code})` : fn.code;
        lines.push(`${curIndent}return ${fnCallExpr}(${args.join(', ')})`);
        break;
      }
      default: break;
    }
  }

  function skipJMPs(tok, limit = 10) {
    let t = tok;
    while (t && limit-- > 0) {
      const b = liftedMap.get(t);
      if (b && b.term.op === 'JMP' && b.ir.length === 0 && b.nextToken) t = b.nextToken;
      else break;
    }
    return t;
  }

  function renderRegion(startTok, stopSet, env, lines, curIndent, activeLoops) {
    let cur = startTok;
    const seenLocal = new Set();

    while (cur && !stopSet.has(cur) && liftedMap.has(cur)) {
      if (seenLocal.has(cur)) break;
      seenLocal.add(cur);

      const b = liftedMap.get(cur);

      // Check if `cur` is a FORNPREP block leading into a numeric `for i = a, b, c do` loop
      if (b.term.op === 'FORNPREP') {
        execBlockIR(b, env, lines, curIndent);
        const base = b.term.imms[b.term.immBase];
        const startExpr = (env.regs[base] || { code: '1' }).code;
        const limitExpr = (env.regs[base + 1] || { code: '1' }).code;
        const stepExpr = (env.regs[base + 2] || { code: '1' }).code;
        const iVar = freshVar('i');
        env.regs[base + 3] = { code: iVar, simple: true };
        const stepSuffix = stepExpr === '1' ? '' : `, ${stepExpr}`;
        lines.push(`${curIndent}for ${iVar} = ${startExpr}, ${limitExpr}${stepSuffix} do`);
        // Find matching FORLOOP block at loop header
        const bodyEntry = b.nextToken;
        const exitTok = b.targetToken;
        const bodyStop = new Set([...stopSet, exitTok]);
        // Also find FORLOOP block so bodyStop skips its terminal jump
        const loopHdr = skipJMPs(bodyEntry);
        const loopInfo = cfg.loopHeaders.get(loopHdr);
        if (loopInfo) {
          for (const bn of loopInfo.body) {
            const bb = liftedMap.get(bn);
            if (bb?.term.op === 'FORLOOP') bodyStop.add(bb.token);
          }
        }
        renderRegion(bodyEntry, bodyStop, cloneEnv(env), lines, curIndent + '    ', activeLoops);
        lines.push(`${curIndent}end`);
        cur = exitTok;
        continue;
      }

      // Check if `cur` is a FORGPREP block leading into a generic `for` loop
      if (b.term.op === 'FORGPREP') {
        execBlockIR(b, env, lines, curIndent);
        const iterReg = b.term.imms[b.term.immBase];
        const iterExpr = (env.regs[iterReg] || { code: 'pairs({})' }).code;
        const hdrTok = skipJMPs(b.nextToken);
        const hdrBlk = liftedMap.get(hdrTok);

        if (hdrBlk && cfg.loopHeaders.has(hdrTok)) {
          const loopInfo = cfg.loopHeaders.get(hdrTok);
          let tforBlk = null;
          let probe = hdrTok;
          const probeSeen = new Set();
          while (probe && loopInfo.body.has(probe) && !probeSeen.has(probe)) {
            probeSeen.add(probe);
            const pb = liftedMap.get(probe);
            if (pb.term.op === 'TFORLOOP') { tforBlk = pb; break; }
            probe = pb.nextToken;
          }
          if (tforBlk) {
            const kReg = tforBlk.term.imms[tforBlk.term.immBase];
            const vReg = kReg + 1;
            const kVar = freshVar('k');
            const vVar = freshVar('v');
            env.regs[kReg] = { code: kVar, simple: true };
            env.regs[vReg] = { code: vVar, simple: true };
            let finalIter = iterExpr;
            if (lines.length > 0) {
              const prevM = lines[lines.length - 1].match(/^\s*local\s+([A-Za-z_0-9]+)\s*,\s*[A-Za-z_0-9]+\s*,\s*[A-Za-z_0-9]+\s*=\s*(.+)$/);
              if (prevM && prevM[1] === iterExpr) {
                finalIter = prevM[2];
                lines.pop();
              }
            }
            lines.push(`${curIndent}for ${kVar}, ${vVar} in ${finalIter} do`);
            const bodyStop = new Set([...stopSet, hdrTok, tforBlk.token, tforBlk.nextToken]);
            renderRegion(tforBlk.targetToken, bodyStop, cloneEnv(env), lines, curIndent + '    ', activeLoops);
            lines.push(`${curIndent}end`);
            cur = tforBlk.nextToken;
            continue;
          }
        }
      }

      // Check if `cur` is a loop header (`while` loop: either direct JUMPIFNOT/JUMPIF, or JMP chain leading to loop condition, or general `while true do`)
      if (cfg.loopHeaders.has(cur) && !activeLoops.has(cur) && b.term.op !== 'TFORLOOP' && b.term.op !== 'FORLOOP') {
        const loopInfo = cfg.loopHeaders.get(cur);
        const condTok = (b.term.op === 'JMP' && b.ir.length === 0) ? skipJMPs(b.nextToken) : cur;
        const condBlk = liftedMap.get(condTok);
        if (condBlk && (condBlk.term.op === 'JUMPIFNOT' || condBlk.term.op === 'JUMPIF') && (!loopInfo.body.has(condBlk.nextToken) || !loopInfo.body.has(condBlk.targetToken))) {
          const loopEnv = cloneEnv(env);
          execBlockIR(condBlk, loopEnv, lines, curIndent);
          const condScr = condBlk.term.ops[condBlk.term.opBase];
          const condExpr = (loopEnv.scratch[condScr] || { code: 'true' }).code;
          const isLoopBodyNext = loopInfo.body.has(condBlk.nextToken);
          const bodyEntry = isLoopBodyNext ? condBlk.nextToken : condBlk.targetToken;
          const exitTok = isLoopBodyNext ? condBlk.targetToken : condBlk.nextToken;
          const condFinal = (condBlk.term.op === 'JUMPIFNOT') === isLoopBodyNext ? condExpr : `not (${condExpr})`;
          lines.push(`${curIndent}while ${condFinal} do`);
          const nextActive = new Set(activeLoops);
          nextActive.add(cur);
          nextActive.add(condTok);
          const bodyStop = new Set([...stopSet, cur, condTok, exitTok]);
          renderRegion(bodyEntry, bodyStop, cloneEnv(loopEnv), lines, curIndent + '    ', nextActive);
          lines.push(`${curIndent}end`);
          cur = exitTok;
          continue;
        } else if (b.term.op !== 'FORGPREP' && b.term.op !== 'FORNPREP') {
          // General loop header (e.g. `while true do ... if cond then return/break end ... end`)
          lines.push(`${curIndent}while true do`);
          const nextActive = new Set(activeLoops);
          nextActive.add(cur);
          const bodyStop = new Set([...stopSet, cur]);
          const bodyEnv = cloneEnv(env);
          // Execute current header block once and continue from its successor inside the loop body
          execBlockIR(b, bodyEnv, lines, curIndent + '    ');
          if (b.term.op === 'JUMPIFNOT' || b.term.op === 'JUMPIF') {
            const condScr = b.term.ops[b.term.opBase];
            const condExpr = (bodyEnv.scratch[condScr] || { code: 'nil' }).code;
            const trueTok = b.term.op === 'JUMPIFNOT' ? b.nextToken : b.targetToken;
            const falseTok = b.term.op === 'JUMPIFNOT' ? b.targetToken : b.nextToken;
            const inTrue = loopInfo.body.has(trueTok);
            const stayTok = inTrue ? trueTok : falseTok;
            const outTok = inTrue ? falseTok : trueTok;
            const breakCond = inTrue ? `not (${condExpr})` : condExpr;
            const outBlk = liftedMap.get(outTok);
            if (outBlk && outBlk.term.op === 'RETURN' && outBlk.ir.length === 0) {
              lines.push(`${curIndent}    if ${breakCond} then`);
              execTerminal(outBlk, cloneEnv(bodyEnv), lines, curIndent + '        ');
              lines.push(`${curIndent}    end`);
            } else {
              lines.push(`${curIndent}    if ${breakCond} then`);
              lines.push(`${curIndent}        break`);
              lines.push(`${curIndent}    end`);
            }
            renderRegion(stayTok, bodyStop, bodyEnv, lines, curIndent + '    ', nextActive);
            lines.push(`${curIndent}end`);
            cur = (outBlk && outBlk.term.op === 'RETURN') ? null : outTok;
          } else {
            execTerminal(b, bodyEnv, lines, curIndent + '    ');
            renderRegion(b.nextToken, bodyStop, bodyEnv, lines, curIndent + '    ', nextActive);
            lines.push(`${curIndent}end`);
            cur = loopInfo.exitTok || null;
          }
          continue;
        }
      }

      execBlockIR(b, env, lines, curIndent);

      const t = b.term;
      if (t.op === 'RETURN' || t.op === 'TAILCALL') {
        execTerminal(b, env, lines, curIndent);
        break;
      }

      if (t.op === 'JUMPIFNOT' || t.op === 'JUMPIF') {
        const condScr = t.ops[t.opBase];
        const condReg = env.scratchReg ? env.scratchReg[condScr] : undefined;
        const condObj = env.scratch[condScr] || { code: 'nil' };
        const condExpr = condObj.code;
        const trueTok = t.op === 'JUMPIFNOT' ? b.nextToken : b.targetToken;
        const falseTok = t.op === 'JUMPIFNOT' ? b.targetToken : b.nextToken;
        const mergeTok = cfg.findMerge(trueTok, falseTok, stopSet);

        // Short-circuit `and`: JUMPIFNOT R[c] where trueTok falls into falseTok and falseTok re-tests JUMPIFNOT R[c]
        if (t.op === 'JUMPIFNOT' && mergeTok === skipJMPs(falseTok) && condReg !== undefined) {
          const fTok = skipJMPs(falseTok);
          const fBlk = liftedMap.get(fTok);
          if (fBlk && fBlk.term.op === 'JUMPIFNOT') {
            const scEnv = cloneEnv(env);
            const scLines = [];
            renderRegion(trueTok, new Set([fTok]), scEnv, scLines, curIndent, activeLoops);
            const rhsObj = scEnv.regs[condReg];
            if (scLines.length === 0 && rhsObj && rhsObj.code !== condExpr) {
              env.regs[condReg] = { code: `${condExpr} and ${rhsObj.code}`, simple: false };
              cur = fTok;
              continue;
            }
          }
        }
        // Short-circuit `or`: JUMPIFNOT R[c] where skipJMPs(trueTok) == mergeTok and falseTok updates R[c] -> mergeTok (which re-tests R[c])
        if (t.op === 'JUMPIFNOT' && mergeTok === skipJMPs(trueTok) && condReg !== undefined) {
          const tTok = skipJMPs(trueTok);
          const tBlk = liftedMap.get(tTok);
          if (tBlk && tBlk.term.op === 'JUMPIFNOT') {
            const scEnv = cloneEnv(env);
            const scLines = [];
            renderRegion(falseTok, new Set([tTok]), scEnv, scLines, curIndent, activeLoops);
            const rhsObj = scEnv.regs[condReg];
            if (scLines.length === 0 && rhsObj && rhsObj.code !== condExpr) {
              env.regs[condReg] = { code: `${condExpr} or ${rhsObj.code}`, simple: false };
              cur = tTok;
              continue;
            }
          }
        }
        // Short-circuit `or` (JUMPIF): falseTok falls into trueTok
        if (t.op === 'JUMPIF' && mergeTok === skipJMPs(trueTok) && condReg !== undefined) {
          const tTok = skipJMPs(trueTok);
          const tBlk = liftedMap.get(tTok);
          if (tBlk && tBlk.term.op === 'JUMPIF') {
            const scEnv = cloneEnv(env);
            const scLines = [];
            renderRegion(falseTok, new Set([tTok]), scEnv, scLines, curIndent, activeLoops);
            const rhsObj = scEnv.regs[condReg];
            if (scLines.length === 0 && rhsObj && rhsObj.code !== condExpr) {
              env.regs[condReg] = { code: `${condExpr} or ${rhsObj.code}`, simple: false };
              cur = tTok;
              continue;
            }
          }
        }

        // Materialize any fresh unmaterialized tables live across branch
        for (const rKey of Object.keys(env.regs)) {
          const rObj = env.regs[rKey];
          if (rObj?.isNewTable && !rObj.materialized) {
            lines.push(`${curIndent}local ${rObj.tblId} = ${rObj.code}`);
            rObj.code = rObj.tblId;
            rObj.simple = true;
            rObj.materialized = true;
          }
        }

        const branchStop = new Set(stopSet);
        if (mergeTok) branchStop.add(mergeTok);

        const trueLines = [];
        const falseLines = [];
        const trueEnv = cloneEnv(env);
        const falseEnv = cloneEnv(env);
        if (trueTok && !branchStop.has(trueTok)) {
          renderRegion(trueTok, branchStop, trueEnv, trueLines, curIndent + '    ', activeLoops);
        }
        if (falseTok && !branchStop.has(falseTok)) {
          renderRegion(falseTok, branchStop, falseEnv, falseLines, curIndent + '    ', activeLoops);
        }

        // Check if both branches are pure ternary assignments to a register (e.g. R[4] = t1 vs R[4] = {"ไม่พบข้อมูล"})
        if (trueLines.length === 0 && falseLines.length === 0 && mergeTok) {
          // Find which register changed in falseEnv vs env (like `or fallback`)
          for (const rk of Object.keys(falseEnv.regs)) {
            if (falseEnv.regs[rk]?.code !== env.regs[rk]?.code && falseEnv.regs[rk]?.isNewTable) {
              env.regs[rk] = { code: `${condExpr} or ${falseEnv.regs[rk].code}`, simple: false };
            }
          }
        } else if (trueLines.length === 0 && falseLines.length > 0) {
          lines.push(`${curIndent}if not (${condExpr}) then`);
          lines.push(...falseLines);
          lines.push(`${curIndent}end`);
        } else if (trueLines.length > 0 || falseLines.length > 0) {
          lines.push(`${curIndent}if ${condExpr} then`);
          lines.push(...trueLines);
          if (falseLines.length > 0) {
            lines.push(`${curIndent}else`);
            lines.push(...falseLines);
          }
          lines.push(`${curIndent}end`);
        }
        cur = mergeTok;
        continue;
      }

      execTerminal(b, env, lines, curIndent);
      cur = b.nextToken;
    }
  }

  const lines = [];
  const env = initEnv();
  renderRegion(proto.entry, new Set(), env, lines, indent, new Set());

  if (lines.length > 0 && lines[lines.length - 1].trim() === 'return') {
    lines.pop();
  }
  return lines.join('\n');
}

function decompileSV3(extracted) {
  const mainProto = extracted.protos[0];
  if (!mainProto) return '-- No protos extracted';
  return decompileSV3Proto(mainProto, extracted.recipes, extracted.opSemantics, extracted.protos, [], '');
}

module.exports = { decompileSV3, decompileSV3Proto };
