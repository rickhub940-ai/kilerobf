// Dynamic SnowVeil v2.0 (SSA CFG) -> Clean Luau Decompiler

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

function wrapParens(e) {
  if (!e) return 'nil';
  if (e.simple || /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*(\([^)]*\))?$/.test(e.code)) return e.code;
  if (/^(".*"|\d+(\.\d+)?|true|false|nil)$/.test(e.code)) return e.code;
  return `(${e.code})`;
}

function buildSV2CFGInfo(nodeMap, opSemantics, entryId) {
  const reachable = new Set();
  const order = [];
  const preds = new Map();
  const succs = new Map();

  function getOpName(node) {
    if (!node) return 'UNKNOWN';
    if (node.fusedSteps && node.fusedSteps.length > 0) return 'FUSED';
    return opSemantics[node.op]?.op || 'UNKNOWN';
  }

  function addEdge(u, v) {
    if (!v || !nodeMap.has(v)) return;
    if (!succs.has(u)) succs.set(u, []);
    if (!succs.get(u).includes(v)) succs.get(u).push(v);
    if (!preds.has(v)) preds.set(v, []);
    if (!preds.get(v).includes(u)) preds.get(v).push(u);
  }

  const stack = [entryId];
  while (stack.length > 0) {
    const id = stack.pop();
    if (!id || reachable.has(id) || !nodeMap.has(id)) continue;
    reachable.add(id);
    order.push(id);
    const n = nodeMap.get(id);
    const op = getOpName(n);
    if (op === 'RETURN' || op === 'RETURN_SSA' || op === 'TAILCALL') continue;
    for (const br of (n.branches || [])) {
      addEdge(id, br.target);
      stack.push(br.target);
    }
  }

  const allNodes = [...reachable];
  const dom = new Map();
  for (const n of allNodes) {
    dom.set(n, n === entryId ? new Set([entryId]) : new Set(allNodes));
  }
  let changed = true;
  while (changed) {
    changed = false;
    for (const n of allNodes) {
      if (n === entryId) continue;
      const ps = (preds.get(n) || []).filter(p => reachable.has(p));
      if (ps.length === 0) continue;
      const inter = new Set(dom.get(ps[0]));
      for (let i = 1; i < ps.length; i++) {
        const ds = dom.get(ps[i]);
        for (const x of [...inter]) {
          if (!ds.has(x)) inter.delete(x);
        }
      }
      inter.add(n);
      if (inter.size !== dom.get(n).size) {
        dom.set(n, inter);
        changed = true;
      }
    }
  }

  const loopHeaders = new Map();
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
    const hdrNode = nodeMap.get(h);
    const hdrOp = getOpName(hdrNode);
    if (hdrNode && (hdrOp === 'JUMPIFNOT' || hdrOp === 'JUMPIF') && hdrNode.branches.length >= 2) {
      const s1 = hdrNode.branches[0].target;
      const s2 = hdrNode.branches[1].target;
      info.exitTok = !info.body.has(s1) ? s1 : (!info.body.has(s2) ? s2 : null);
    } else {
      for (const bn of info.body) {
        const bb = nodeMap.get(bn);
        if (getOpName(bb) === 'TFORLOOP' && bb.branches.length >= 1 && !info.body.has(bb.branches[0].target)) {
          info.exitTok = bb.branches[0].target;
          break;
        }
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
        if (dom.get(u)?.has(v)) {
          seen.add(v);
        } else {
          q.push(v);
        }
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

  return { reachable, preds, succs, dom, loopHeaders, findMerge, getOpName };
}

function decompileSV2Proto(proto, opSemantics, allProtos, outerUpvals = [], indent = '') {
  const nodeMap = new Map();
  for (const n of proto.nodes) {
    nodeMap.set(n.id, n);
  }
  const cfg = buildSV2CFGInfo(nodeMap, opSemantics, proto.entry);
  const consts = proto.consts;
  const cellSet = new Set(proto.cells || []);
  const boundCells = new Set();

  // Promote loop-carried and branch-merged registers cleanly:
  // 1) Loop-carried: written inside a loop AND (read after loop exit OR read inside loop before any write in the loop)
  // 2) Branch-merged: written before a JUMPIFNOT/JUMPIF, overwritten inside one of its non-empty branches, and read at/after merge
  function collectNodeRegOps(node) {
    const writes = [];
    const reads = [];
    const readsBeforeWrite = [];
    const writtenInNode = new Set();
    const steps = node.fusedSteps && node.fusedSteps.length > 0
      ? node.fusedSteps
      : [{ op: node.op, operands: node.operands || [] }];
    const addRead = (r) => {
      reads.push(r);
      if (!writtenInNode.has(r)) readsBeforeWrite.push(r);
    };
    const addWrite = (r) => {
      writes.push(r);
      writtenInNode.add(r);
    };
    for (const s of steps) {
      const opName = opSemantics[s.op]?.op || 'UNKNOWN';
      const ops = s.operands || [];
      if (opName === 'STORE_REG') addWrite(ops[1]);
      else if (opName === 'LOAD_REG') addRead(ops[0]);
      else if (opName === 'CLOSURE') addWrite(ops[0]);
      else if (opName === 'RETURN') {
        const cnt = ops[1];
        if (cnt > 0) for (let k = 0; k < cnt; k++) addRead(ops[0] + k);
      }
      else if (opName === 'CALL') {
        addRead(ops[0]);
        if (ops[1] > 0) for (let k = 1; k <= ops[1]; k++) addRead(ops[0] + k);
        addWrite(ops[0]);
      }
      else if (opName === 'CALL2') { addRead(ops[0]); addRead(ops[1]); addRead(ops[2]); addWrite(ops[3]); }
      else if (opName === 'SELF') { addRead(ops[0] + 1); addWrite(ops[0]); }
    }
    return { writes, reads, readsBeforeWrite };
  }

  for (const [, loopInfo] of cfg.loopHeaders.entries()) {
    const writtenInLoop = new Set();
    for (const nid of loopInfo.body) {
      const n = nodeMap.get(nid);
      if (!n) continue;
      for (const r of collectNodeRegOps(n).writes) writtenInLoop.add(r);
    }
    // Check which registers in writtenInLoop are read after loop exit before being overwritten,
    // or read inside loop before being written along a path from loop header
    for (const r of writtenInLoop) {
      let liveOut = false;
      if (loopInfo.exitTok) {
        const seen = new Set();
        const q = [loopInfo.exitTok];
        while (q.length > 0 && !liveOut) {
          const nid = q.shift();
          if (!nid || seen.has(nid)) continue;
          seen.add(nid);
          const n = nodeMap.get(nid);
          if (!n) continue;
          const { writes, readsBeforeWrite } = collectNodeRegOps(n);
          if (readsBeforeWrite.includes(r)) { liveOut = true; break; }
          if (writes.includes(r)) continue; // killed on this path
          for (const br of (n.branches || [])) q.push(br.target);
        }
      }
      let liveInLoop = false;
      // Walk forward from loop header without crossing back-edges
      const hdr = [...loopInfo.body].find(id => cfg.loopHeaders.get(id) === loopInfo);
      if (hdr && !liveOut) {
        const seen = new Set();
        const q = [hdr];
        while (q.length > 0 && !liveInLoop) {
          const nid = q.shift();
          if (!nid || seen.has(nid) || !loopInfo.body.has(nid)) continue;
          seen.add(nid);
          const n = nodeMap.get(nid);
          if (!n) continue;
          const { writes, readsBeforeWrite } = collectNodeRegOps(n);
          if (readsBeforeWrite.includes(r)) { liveInLoop = true; break; }
          if (writes.includes(r)) continue;
          for (const br of (n.branches || [])) {
            if (!cfg.dom.get(nid)?.has(br.target)) q.push(br.target);
          }
        }
      }
      if (liveOut || liveInLoop) {
        cellSet.add(r);
      }
    }
  }

  let varSeq = 0;
  function freshVar(prefix = 'v') {
    varSeq++;
    return `${prefix}${varSeq}`;
  }

  function initEnv() {
    const regs = {};
    for (let i = 0; i < proto.params; i++) {
      regs[i] = { code: `p${i + 1}`, simple: true, isParam: true };
    }
    const upvals = {};
    for (let i = 0; i < (proto.captures || []).length; i++) {
      upvals[i] = outerUpvals[i] || { code: `up_${i}`, simple: true };
    }
    const ssaArgs = proto.liveState
      ? (proto.entryParameters || []).map(idx => (idx >= 0 ? (regs[idx] || { code: 'nil', simple: true }) : { code: 'nil', simple: true }))
      : [];
    return { regs, upvals, ssaArgs, top: proto.params };
  }

  function cloneEnv(env) {
    return {
      regs: { ...env.regs },
      upvals: { ...env.upvals },
      ssaArgs: [...env.ssaArgs],
      top: env.top,
    };
  }

  function writeReg(env, reg, expr, lines, curIndent) {
    if (cellSet.has(reg)) {
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

  function mapNextArgs(argMapping, prevArgs, outVal) {
    return (argMapping || []).map(idx => {
      if (idx <= 0) return outVal || { code: 'nil', simple: true };
      return prevArgs[idx - 1] || { code: 'nil', simple: true };
    });
  }

  function execStep(opName, operands, curArgs, env, lines, curIndent) {
    const nilExpr = { code: 'nil', simple: true, constVal: { t: 'nil' } };
    switch (opName) {
      case 'JMP':
      case 'LOADNIL':
        return nilExpr;
      case 'LOADK': {
        const c = consts[operands[0]] || { t: 'nil' };
        return { code: fmtConst(c), simple: true, constVal: c };
      }
      case 'LOADBOOL': {
        const bv = operands[0] !== 0;
        return { code: bv ? 'true' : 'false', simple: true, constVal: { t: 'bool', v: bv } };
      }
      case 'NEWTABLE': {
        const tblId = freshVar('t');
        return { code: '{}', simple: false, tableEntries: [], isNewTable: true, tblId };
      }
      case 'GETGLOBAL': {
        const key = curArgs[(operands[0] || 1) - 1] || nilExpr;
        const gName = (key.constVal?.t === 'str' && isIdent(key.constVal.v))
          ? key.constVal.v
          : `_ENV[${key.code}]`;
        return { code: gName, simple: true };
      }
      case 'SETGLOBAL': {
        const key = curArgs[(operands[0] || 1) - 1] || nilExpr;
        const val = curArgs[(operands[1] || 2) - 1] || nilExpr;
        const gName = (key.constVal?.t === 'str' && isIdent(key.constVal.v))
          ? key.constVal.v
          : `_ENV[${key.code}]`;
        lines.push(`${curIndent}${gName} = ${val.code}`);
        return nilExpr;
      }
      case 'GETUPVAL': {
        const uIdx = operands[0];
        return env.upvals[uIdx] || { code: `up_${uIdx}`, simple: true };
      }
      case 'SETUPVAL': {
        const val = curArgs[(operands[0] || 1) - 1] || nilExpr;
        const uIdx = operands[1] !== undefined ? operands[1] : operands[0];
        const uName = env.upvals[uIdx]?.code || `up_${uIdx}`;
        if (!env.upvals[uIdx]) env.upvals[uIdx] = { code: uName, simple: true };
        lines.push(`${curIndent}${uName} = ${val.code}`);
        return nilExpr;
      }
      case 'LOAD_REG': {
        const rIdx = operands[0];
        return env.regs[rIdx] || nilExpr;
      }
      case 'STORE_REG': {
        const val = curArgs[(operands[0] || 1) - 1] || nilExpr;
        const dst = operands[1];
        writeReg(env, dst, val, lines, curIndent);
        return nilExpr;
      }
      case 'GETTABLE': {
        const obj = curArgs[(operands[0] || 1) - 1] || nilExpr;
        const key = curArgs[(operands[1] || 2) - 1] || nilExpr;
        const code = (key.constVal?.t === 'str' && isIdent(key.constVal.v))
          ? `${wrapParens(obj)}.${key.constVal.v}`
          : `${wrapParens(obj)}[${key.code}]`;
        return { code, simple: true };
      }
      case 'SETTABLE': {
        const obj = curArgs[(operands[0] || 1) - 1] || nilExpr;
        const key = curArgs[(operands[1] || 2) - 1] || nilExpr;
        const val = curArgs[(operands[2] || 3) - 1] || nilExpr;
        if (obj.isNewTable && obj.tableEntries) {
          obj.tableEntries.push({ key: key.constVal || { t: 'expr', code: key.code }, val });
          obj.code = formatTableLiteral(obj.tableEntries);
        } else {
          const lhs = (key.constVal?.t === 'str' && isIdent(key.constVal.v))
            ? `${wrapParens(obj)}.${key.constVal.v}`
            : `${wrapParens(obj)}[${key.code}]`;
          lines.push(`${curIndent}${lhs} = ${val.code}`);
        }
        return nilExpr;
      }
      case 'ADD': case 'SUB': case 'MUL': case 'DIV': case 'IDIV': case 'MOD': case 'POW': case 'CONCAT':
      case 'EQ': case 'NEQ': case 'LT': case 'LE': case 'GT': case 'GE': {
        const syms = {
          ADD: '+', SUB: '-', MUL: '*', DIV: '/', IDIV: '//', MOD: '%', POW: '^', CONCAT: '..',
          EQ: '==', NEQ: '~=', LT: '<', LE: '<=', GT: '>', GE: '>='
        };
        const a = curArgs[(operands[0] || 1) - 1] || nilExpr;
        const b = curArgs[(operands[1] || 2) - 1] || nilExpr;
        return { code: `${wrapParens(a)} ${syms[opName]} ${wrapParens(b)}`, simple: false, lhs: a, rhs: b, binop: opName };
      }
      case 'NOT': case 'LEN': case 'UNM': {
        const syms = { NOT: 'not ', LEN: '#', UNM: '-' };
        const a = curArgs[(operands[0] || 1) - 1] || nilExpr;
        return { code: `${syms[opName]}${wrapParens(a)}`, simple: false, unop: opName, operand: a };
      }
      case 'SELF': {
        const base = operands[0];
        const methodK = consts[operands[1]] || { t: 'nil' };
        const obj = env.regs[base + 1] || nilExpr;
        const mName = (methodK.t === 'str' && isIdent(methodK.v)) ? methodK.v : fmtConst(methodK);
        env.regs[base] = {
          code: `${wrapParens(obj)}:${mName}`,
          simple: true,
          isSelfMethod: true,
          selfBase: base,
          selfObj: obj,
          methodName: mName,
        };
        return nilExpr;
      }
      case 'GETVARARGS': {
        const base = operands[0];
        const count = operands[1];
        if (count === -1) {
          writeReg(env, base, { code: '...', simple: true }, lines, curIndent);
          env.top = base + 1;
        } else {
          for (let k = 0; k < count; k++) {
            writeReg(env, base + k, { code: '...', simple: true }, lines, curIndent);
          }
          env.top = base + count;
        }
        return nilExpr;
      }
      case 'SETLIST': {
        const tblReg = operands[0];
        const startIdx = operands[1];
        const srcReg = operands[2];
        const count = operands[3];
        const tbl = env.regs[tblReg];
        const actualCount = count === -1 ? Math.max(0, env.top - srcReg) : count;
        if (tbl && tbl.isNewTable && tbl.tableEntries) {
          for (let k = 0; k < actualCount; k++) {
            tbl.tableEntries.push({
              key: { t: 'num', v: startIdx + k },
              val: env.regs[srcReg + k] || nilExpr,
            });
          }
          tbl.code = formatTableLiteral(tbl.tableEntries);
        } else {
          for (let k = 0; k < actualCount; k++) {
            const v = env.regs[srcReg + k] || nilExpr;
            lines.push(`${curIndent}${tbl ? tbl.code : 't'}[${startIdx + k}] = ${v.code}`);
          }
        }
        return nilExpr;
      }
      case 'CLOSURE': {
        const dstReg = operands[0];
        const subId = operands[1];
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
          const subBody = decompileSV2Proto(subProto, opSemantics, allProtos, outerUps, curIndent + '    ');
          const fnCode = subBody.trim()
            ? `function(${pnames.join(', ')})\n${subBody}\n${curIndent}end`
            : `function(${pnames.join(', ')}) end`;
          writeReg(env, dstReg, { code: fnCode, simple: false, isClosure: true }, lines, curIndent);
        } else {
          writeReg(env, dstReg, { code: 'function(...) end', simple: false }, lines, curIndent);
        }
        return nilExpr;
      }
      case 'CALL': {
        const base = operands[0];
        const nArg = operands[1];
        const nRet = operands[2];
        const fn = env.regs[base] || nilExpr;
        const args = [];
        const actualCount = nArg === -1 ? Math.max(0, env.top - base - 1) : nArg;
        const startArg = fn.isSelfMethod ? base + 2 : base + 1;
        for (let r = startArg; r < base + 1 + actualCount; r++) {
          const argObj = env.regs[r];
          if (argObj?.isNewTable && !argObj.materialized) {
            lines.push(`${curIndent}local ${argObj.tblId} = ${argObj.code}`);
            argObj.code = argObj.tblId;
            argObj.simple = true;
            argObj.materialized = true;
          }
          args.push((env.regs[r] || nilExpr).code);
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
        return nilExpr;
      }
      case 'CALL2': {
        const fnReg = operands[0];
        const a1Reg = operands[1];
        const a2Reg = operands[2];
        const dstReg = operands[3];
        const nRet = operands[4];
        const fn = env.regs[fnReg] || nilExpr;
        const a1 = env.regs[a1Reg] || nilExpr;
        const a2 = env.regs[a2Reg] || nilExpr;
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
        return nilExpr;
      }
      case 'TAILCALL': {
        const base = operands[0];
        const nArg = operands[1];
        const fn = env.regs[base] || nilExpr;
        const args = [];
        const actualCount = nArg === -1 ? Math.max(0, env.top - base - 1) : nArg;
        const startArg = fn.isSelfMethod ? base + 2 : base + 1;
        for (let r = startArg; r < base + 1 + actualCount; r++) {
          args.push((env.regs[r] || nilExpr).code);
        }
        const fnCallExpr = fn.isClosure ? `(${fn.code})` : fn.code;
        lines.push(`${curIndent}return ${fnCallExpr}(${args.join(', ')})`);
        return nilExpr;
      }
      case 'CALL_SSA': {
        const fn = curArgs[(operands[0] || 1) - 1] || nilExpr;
        const nArg = operands[1] ?? 0;
        const nRet = operands[2] ?? 0;
        const args = [];
        for (let k = 0; k < nArg; k++) {
          const argObj = curArgs[(operands[3 + k] || 1) - 1] || nilExpr;
          if (argObj?.isNewTable && !argObj.materialized) {
            lines.push(`${curIndent}local ${argObj.tblId} = ${argObj.code}`);
            argObj.code = argObj.tblId;
            argObj.simple = true;
            argObj.materialized = true;
          }
          args.push(argObj.code);
        }
        const fnCallExpr = fn.isClosure ? `(${fn.code})` : fn.code;
        const finalCallCode = `${fnCallExpr}(${args.join(', ')})`;
        if (nRet === 0) {
          lines.push(`${curIndent}${finalCallCode}`);
          return nilExpr;
        }
        const v = freshVar('res');
        lines.push(`${curIndent}local ${v} = ${finalCallCode}`);
        return { code: v, simple: true };
      }
      case 'RETURN_SSA': {
        const count = operands[0] ?? 0;
        const rets = [];
        for (let k = 0; k < count; k++) {
          rets.push((curArgs[(operands[1 + k] || 1) - 1] || nilExpr).code);
        }
        lines.push(`${curIndent}return${rets.length ? ' ' + rets.join(', ') : ''}`);
        return nilExpr;
      }
      case 'RETURN': {
        const base = operands[0];
        const count = operands[1];
        const actualCount = count === -1 ? Math.max(0, env.top - base) : count;
        const rets = [];
        for (let k = 0; k < actualCount; k++) {
          rets.push((env.regs[base + k] || nilExpr).code);
        }
        lines.push(`${curIndent}return${rets.length ? ' ' + rets.join(', ') : ''}`);
        return nilExpr;
      }
      case 'FORGPREP':
        return nilExpr;
      default:
        lines.push(`${curIndent}-- [unhandled sv2 op ${opName}]`);
        return nilExpr;
    }
  }

  function execNode(node, env, lines, curIndent) {
    if (node.fusedSteps && node.fusedSteps.length > 0) {
      let curArgs = env.ssaArgs;
      let outVal = { code: 'nil', simple: true };
      for (const fs of node.fusedSteps) {
        const opName = opSemantics[fs.op]?.op || 'UNKNOWN';
        outVal = execStep(opName, fs.operands || [], curArgs, env, lines, curIndent);
        curArgs = mapNextArgs(fs.args, curArgs, outVal);
      }
      env.ssaArgs = curArgs;
      return outVal;
    }
    const opName = opSemantics[node.op]?.op || 'UNKNOWN';
    const outVal = execStep(opName, node.operands || [], env.ssaArgs, env, lines, curIndent);
    if (node.branches && node.branches.length === 1) {
      env.ssaArgs = mapNextArgs(node.branches[0].args, env.ssaArgs, outVal);
    }
    return outVal;
  }

  function skipJMPs(id, limit = 10) {
    let cur = id;
    while (cur && limit-- > 0) {
      const n = nodeMap.get(cur);
      if (n && cfg.getOpName(n) === 'JMP' && n.branches.length === 1) {
        cur = n.branches[0].target;
      } else {
        break;
      }
    }
    return cur;
  }

  function renderRegion(startId, stopSet, env, lines, curIndent, activeLoops, loopExits = new Set()) {
    let cur = startId;
    const seenLocal = new Set();

    while (cur && !stopSet.has(cur) && nodeMap.has(cur)) {
      if (seenLocal.has(cur)) break;
      seenLocal.add(cur);

      const n = nodeMap.get(cur);
      const opName = cfg.getOpName(n);

      // Generic `for` loop via FORGPREP
      if (opName === 'FORGPREP') {
        execNode(n, env, lines, curIndent);
        const iterReg = n.operands[0];
        const iterExpr = (env.regs[iterReg] || { code: 'pairs({})' }).code;
        const nextTok = n.branches[0]?.target;
        const hdrTok = skipJMPs(nextTok);
        const hdrNode = nodeMap.get(hdrTok);

        if (hdrNode && cfg.loopHeaders.has(hdrTok)) {
          const loopInfo = cfg.loopHeaders.get(hdrTok);
          let tforNode = null;
          let probe = hdrTok;
          const probeSeen = new Set();
          while (probe && loopInfo.body.has(probe) && !probeSeen.has(probe)) {
            probeSeen.add(probe);
            const pn = nodeMap.get(probe);
            if (cfg.getOpName(pn) === 'TFORLOOP') {
              tforNode = pn;
              break;
            }
            probe = pn.branches[0]?.target;
          }
          if (tforNode && tforNode.branches.length >= 2) {
            const kReg = tforNode.operands[0];
            const ctrlReg = tforNode.operands[1];
            const vReg = kReg + 1;
            const kVar = freshVar('k');
            const vVar = freshVar('v');
            env.regs[kReg] = { code: kVar, simple: true };
            env.regs[vReg] = { code: vVar, simple: true };
            if (ctrlReg !== undefined) env.regs[ctrlReg] = { code: kVar, simple: true };
            let finalIter = iterExpr;
            if (lines.length > 0) {
              const prevM = lines[lines.length - 1].match(/^\s*local\s+([A-Za-z_0-9]+)\s*,\s*[A-Za-z_0-9]+\s*,\s*[A-Za-z_0-9]+\s*=\s*(.+)$/);
              if (prevM && prevM[1] === iterExpr) {
                finalIter = prevM[2];
                lines.pop();
              }
            }
            lines.push(`${curIndent}for ${kVar}, ${vVar} in ${finalIter} do`);
            const exitTok = tforNode.branches[0].target;
            const bodyTok = tforNode.branches[1].target;
            const bodyStop = new Set([...stopSet, hdrTok, tforNode.id, exitTok]);
            const bodyEnv = cloneEnv(env);
            bodyEnv.ssaArgs = mapNextArgs(tforNode.branches[1].args, bodyEnv.ssaArgs, { code: 'nil', simple: true });
            const innerExits = new Set(loopExits);
            innerExits.add(exitTok);
            renderRegion(bodyTok, bodyStop, bodyEnv, lines, curIndent + '    ', activeLoops, innerExits);
            lines.push(`${curIndent}end`);
            env.ssaArgs = mapNextArgs(tforNode.branches[0].args, env.ssaArgs, { code: 'nil', simple: true });
            cur = exitTok;
            continue;
          }
        }
        cur = nextTok;
        continue;
      }

      // `while` loop header
      if (cfg.loopHeaders.has(cur) && !activeLoops.has(cur) && (opName === 'JUMPIFNOT' || opName === 'JUMPIF') && n.branches.length >= 2) {
        const loopInfo = cfg.loopHeaders.get(cur);
        const condExpr = (env.ssaArgs[0] || { code: 'true' }).code;
        const b0 = n.branches[0].target;
        const b1 = n.branches[1].target;
        const isLoopBodyB0 = loopInfo.body.has(b0);
        const bodyEntry = isLoopBodyB0 ? b0 : b1;
        const exitTok = isLoopBodyB0 ? b1 : b0;
        const bodyBr = isLoopBodyB0 ? n.branches[0] : n.branches[1];
        const exitBr = isLoopBodyB0 ? n.branches[1] : n.branches[0];
        const condFinal = (opName === 'JUMPIFNOT') === isLoopBodyB0 ? condExpr : `not (${condExpr})`;
        lines.push(`${curIndent}while ${condFinal} do`);
        const nextActive = new Set(activeLoops);
        nextActive.add(cur);
        const bodyEnv = cloneEnv(env);
        bodyEnv.ssaArgs = mapNextArgs(bodyBr.args, bodyEnv.ssaArgs, { code: 'nil', simple: true });
        const bodyStop = new Set([...stopSet, cur, exitTok]);
        const innerExits = new Set(loopExits);
        innerExits.add(exitTok);
        renderRegion(bodyEntry, bodyStop, bodyEnv, lines, curIndent + '    ', nextActive, innerExits);
        lines.push(`${curIndent}end`);
        env.ssaArgs = mapNextArgs(exitBr.args, env.ssaArgs, { code: 'nil', simple: true });
        cur = exitTok;
        continue;
      }

      if (opName === 'RETURN' || opName === 'RETURN_SSA' || opName === 'TAILCALL') {
        execNode(n, env, lines, curIndent);
        break;
      }

      if ((opName === 'JUMPIFNOT' || opName === 'JUMPIF') && n.branches.length >= 2) {
        const condObj = env.ssaArgs[0] || { code: 'nil' };
        const condExpr = condObj.code;
        const trueBr = opName === 'JUMPIFNOT' ? n.branches[0] : n.branches[1];
        const falseBr = opName === 'JUMPIFNOT' ? n.branches[1] : n.branches[0];
        const trueTok = trueBr.target;
        const falseTok = falseBr.target;
        const mergeTok = cfg.findMerge(trueTok, falseTok, stopSet);

        // Materialize fresh unmaterialized tables live across branch
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
        trueEnv.ssaArgs = mapNextArgs(trueBr.args, trueEnv.ssaArgs, { code: 'nil', simple: true });
        const falseEnv = cloneEnv(env);
        falseEnv.ssaArgs = mapNextArgs(falseBr.args, falseEnv.ssaArgs, { code: 'nil', simple: true });

        if (trueTok && !branchStop.has(trueTok)) {
          renderRegion(trueTok, branchStop, trueEnv, trueLines, curIndent + '    ', activeLoops, loopExits);
        }
        if (falseTok && !branchStop.has(falseTok)) {
          renderRegion(falseTok, branchStop, falseEnv, falseLines, curIndent + '    ', activeLoops, loopExits);
        }

        const trueBreak = loopExits.has(skipJMPs(trueTok)) && !stopSet.has(trueTok) && mergeTok !== trueTok;
        const falseBreak = loopExits.has(skipJMPs(falseTok)) && !stopSet.has(falseTok) && mergeTok !== falseTok;
        if (trueBreak && trueLines.length === 0) trueLines.push(`${curIndent}    break`);
        if (falseBreak && falseLines.length === 0) falseLines.push(`${curIndent}    break`);

        if (trueLines.length === 0 && falseLines.length === 0) {
          // Short-circuit expression fold (e.g. `A and B` where true branch only updates a register)
          for (const rKey of Object.keys(trueEnv.regs)) {
            if (trueEnv.regs[rKey] !== env.regs[rKey] && env.regs[rKey]) {
              env.regs[rKey] = {
                code: `${wrapParens(env.regs[rKey])} and ${wrapParens(trueEnv.regs[rKey])}`,
                simple: false,
              };
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
        if (mergeTok) {
          env.ssaArgs = trueLines.length > 0 ? trueEnv.ssaArgs : falseEnv.ssaArgs;
          // Propagate single-branch register updates when merge node reads the updated condition register
          if (falseLines.length === 0 && trueLines.length > 0) {
            const mergeNode = nodeMap.get(mergeTok);
            const mergeReads = mergeNode ? collectNodeRegOps(mergeNode).reads : [];
            for (const rKey of Object.keys(trueEnv.regs)) {
              const rNum = Number(rKey);
              if (trueEnv.regs[rKey] !== env.regs[rKey] && mergeReads.includes(rNum) && env.regs[rKey]) {
                env.regs[rKey] = {
                  code: `${wrapParens(env.regs[rKey])} and ${wrapParens(trueEnv.regs[rKey])}`,
                  simple: false,
                };
              }
            }
          }
        }
        cur = mergeTok;
        continue;
      }

      execNode(n, env, lines, curIndent);
      const nextId = n.branches?.[0]?.target || null;
      if (nextId && loopExits.has(skipJMPs(nextId)) && !stopSet.has(nextId)) {
        lines.push(`${curIndent}break`);
        break;
      }
      cur = nextId;
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

function decompileSV2(extracted) {
  const mainProto = extracted.protos[0];
  if (!mainProto) return '-- No protos extracted';
  return decompileSV2Proto(mainProto, extracted.opSemantics, extracted.protos, [], '');
}

module.exports = { decompileSV2, decompileSV2Proto };
