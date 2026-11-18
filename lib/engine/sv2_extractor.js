// Dynamic SnowVeil v2.0 (SSA CFG) Extractor + Runtime Mock-VM Prober + Opcode Classifier

const { runInSandbox } = require('./sandbox');

const LUA_JSON_HELPER = `
local function __sv_esc_str(s)
  local out = {'"'}
  for i = 1, #s do
    local b = string.byte(s, i)
    if b == 34 then out[#out+1] = '\\\\"'
    elseif b == 92 then out[#out+1] = '\\\\\\\\'
    elseif b == 8 then out[#out+1] = '\\\\b'
    elseif b == 12 then out[#out+1] = '\\\\f'
    elseif b == 10 then out[#out+1] = '\\\\n'
    elseif b == 13 then out[#out+1] = '\\\\r'
    elseif b == 9 then out[#out+1] = '\\\\t'
    elseif b < 32 or b == 127 then out[#out+1] = string.format('\\\\u%04x', b)
    else out[#out+1] = string.char(b) end
  end
  out[#out+1] = '"'
  return table.concat(out)
end

local function __sv_to_json(v)
  local t = type(v)
  if v == nil then return "null"
  elseif t == "boolean" then return v and "true" or "false"
  elseif t == "number" then
    if v ~= v or v == math.huge or v == -math.huge then return "null" end
    if math.floor(v) == v and math.abs(v) < 9007199254740992 then
      return string.format("%.0f", v)
    end
    return tostring(v)
  elseif t == "string" then return __sv_esc_str(v)
  elseif t == "table" then
    local n = #v
    local is_arr = true
    local cnt = 0
    for k in pairs(v) do
      cnt = cnt + 1
      if type(k) ~= "number" or k < 1 or k > n or math.floor(k) ~= k then
        is_arr = false
        break
      end
    end
    if is_arr and cnt == n then
      local items = {}
      for i = 1, n do items[i] = __sv_to_json(v[i]) end
      return "[" .. table.concat(items, ",") .. "]"
    else
      local items = {}
      for k, val in pairs(v) do
        local ks = type(k) == "number" and math.floor(k) == k and string.format("%.0f", k) or tostring(k)
        items[#items+1] = __sv_esc_str(ks) .. ":" .. __sv_to_json(val)
      end
      return "{" .. table.concat(items, ",") .. "}"
    end
  end
  return "null"
end
`;

function extractSV2Dynamic(stage3Code) {
  const tailCalls = [
    ...stage3Code.matchAll(/local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(?:0[bBxX])?0*1\s*,\s*\{\s*\}\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\)/g)
  ];
  if (tailCalls.length === 0) {
    throw new Error('Could not locate SnowVeil v2.0 SSA CFG entry call');
  }
  const lastCall = tailCalls[tailCalls.length - 1];
  const gName = lastCall[1];

  const gRe = new RegExp(
    `${escapeRe(gName)}\\s*=\\s*function\\s*\\([^)]*\\)\\s*local\\s+[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*\\(`
  );
  const mG = stage3Code.match(gRe);
  if (!mG) {
    throw new Error('Could not locate SnowVeil v2.0 proto loader function');
  }
  const loaderName = mG[1];

  const mNodeDec = stage3Code.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)[\s\S]{0,350}\2\.offsets\[\3\]/
  );
  if (!mNodeDec) {
    throw new Error('Could not locate SnowVeil v2.0 node decoder function');
  }
  const nodeDecoderName = mNodeDec[1];

  const head = stage3Code.slice(0, lastCall.index);

  const dumper = `
${LUA_JSON_HELPER}
local __protos = {}
local __usedOps = {}
local __idx = 1
while true do
  local ok, p = pcall(${loaderName}, __idx)
  if not ok or p == nil then break end
  local consts = {}
  for ci = 1, (p.constantCount or 0) do
    local cv = p.constantValues[ci]
    local tv = type(cv)
    if cv == nil then consts[ci] = { t = "nil" }
    elseif tv == "boolean" then consts[ci] = { t = "bool", v = cv }
    elseif tv == "number" then consts[ci] = { t = "num", v = cv }
    elseif tv == "string" then consts[ci] = { t = "str", v = cv }
    else consts[ci] = { t = "other", v = tostring(cv) } end
  end

  local nodes = {}
  for nid in pairs(p.offsets or {}) do
    local _, argCount, op, operands, branches, fusedSteps = ${nodeDecoderName}(p, nid)
    local brOut = {}
    for bi = 1, #(branches or {}) do
      local br = branches[bi]
      local argsArr = {}
      local ba = br.arguments
      if ba then
        for ai = 1, (ba.n or #ba) do
          argsArr[ai] = ba[ai]
        end
      end
      brOut[bi] = { target = br.target, args = argsArr }
    end

    local fusedOut = nil
    if fusedSteps then
      fusedOut = {}
      for fi = 1, #fusedSteps do
        local fs = fusedSteps[fi]
        __usedOps[fs[3]] = true
        local fArgs = {}
        local fa = fs[5]
        if fa then
          for ai = 1, (fa.n or #fa) do
            fArgs[ai] = fa[ai]
          end
        end
        fusedOut[fi] = {
          subId = fs[1],
          argCount = fs[2],
          op = fs[3],
          operands = fs[4] or {},
          args = fArgs
        }
      end
    else
      __usedOps[op] = true
    end

    nodes[#nodes+1] = {
      id = nid,
      argCount = argCount,
      op = op,
      operands = operands or {},
      branches = brOut,
      fusedSteps = fusedOut
    }
  end

  local entryParams = {}
  if p.entryParameters then
    for ei = 1, #p.entryParameters do
      entryParams[ei] = p.entryParameters[ei]
    end
  end

  __protos[#__protos+1] = {
    id = __idx - 1,
    params = p.params or 0,
    max = p.max or 0,
    entry = p.entry,
    entryParameters = entryParams,
    vararg = p.vararg,
    liveState = p.liveState,
    captures = p.captures or {},
    cells = p.cells or {},
    constantCount = p.constantCount or 0,
    consts = consts,
    nodes = nodes
  }
  __idx = __idx + 1
end

-- Runtime Mock-VM Prober: wraps nodeDecoder and executes each op inside the real SV2 VM
local __mock_traces = {}
local __orig_dec = ${nodeDecoderName}
local __mock_active = false
local __mock_nodes = {}
${nodeDecoderName} = function(p, nid)
  if __mock_active and __mock_nodes[nid] then
    local n = __mock_nodes[nid]
    return n.n_id, n.argCount, n.op, n.operands, n.branches, n.fusedSteps
  end
  return __orig_dec(p, nid)
end

local __probe_logs = {}
local function __mkSym(kind, id)
  local t = { __sym = kind, __id = id }
  return setmetatable(t, {
    __add = function() __probe_logs[#__probe_logs+1] = "ADD"; return __mkSym("res", "ADD") end,
    __sub = function() __probe_logs[#__probe_logs+1] = "SUB"; return __mkSym("res", "SUB") end,
    __mul = function() __probe_logs[#__probe_logs+1] = "MUL"; return __mkSym("res", "MUL") end,
    __div = function() __probe_logs[#__probe_logs+1] = "DIV"; return __mkSym("res", "DIV") end,
    __idiv = function() __probe_logs[#__probe_logs+1] = "IDIV"; return __mkSym("res", "IDIV") end,
    __mod = function() __probe_logs[#__probe_logs+1] = "MOD"; return __mkSym("res", "MOD") end,
    __pow = function() __probe_logs[#__probe_logs+1] = "POW"; return __mkSym("res", "POW") end,
    __concat = function() __probe_logs[#__probe_logs+1] = "CONCAT"; return __mkSym("res", "CONCAT") end,
    __unm = function() __probe_logs[#__probe_logs+1] = "UNM"; return __mkSym("res", "UNM") end,
    __len = function() __probe_logs[#__probe_logs+1] = "LEN"; return 1 end,
    __eq = function() __probe_logs[#__probe_logs+1] = "EQ"; return false end,
    __lt = function() __probe_logs[#__probe_logs+1] = "LT"; return false end,
    __le = function() __probe_logs[#__probe_logs+1] = "LE"; return false end,
    __index = function(_, k) __probe_logs[#__probe_logs+1] = "GETTABLE"; return __mkSym("field", tostring(k)) end,
    __newindex = function() __probe_logs[#__probe_logs+1] = "SETTABLE" end,
    __call = function() __probe_logs[#__probe_logs+1] = "CALL:"..tostring(kind); return __mkSym("ret", "CALL") end,
  })
end
local __mock_env = setmetatable({}, {
  __index = function(_, k) __probe_logs[#__probe_logs+1] = "GETGLOBAL"; return __mkSym("G", k) end,
  __newindex = function() __probe_logs[#__probe_logs+1] = "SETGLOBAL" end
})

local p1 = ${loaderName}(1)
if p1 then
  __mock_active = true
  local __retOp = nil
  for op in pairs(__usedOps) do
    __probe_logs = {}
    __mock_nodes = {
      [p1.entry] = {
        n_id = p1.entry, argCount = 0, op = op, operands = { 0, 0, 1, 2 },
        branches = { { target = 999999, arguments = { n = 0 } }, { target = 999998, arguments = { n = 0 } } }
      }
    }
    local ok = pcall(${gName}(1, {}, __mock_env))
    if ok and #__probe_logs == 0 then
      __retOp = op
      __mock_traces[tostring(op)] = { ok = true, logs = {}, isReturn = true }
    end
  end

  local __loadkOp = nil
  if __retOp then
    for op in pairs(__usedOps) do
      if op ~= __retOp then
        __probe_logs = {}
        __mock_nodes = {
          [p1.entry] = {
            n_id = p1.entry, argCount = 0, op = op, operands = { 0 },
            branches = { { target = 900001, arguments = { n = 1, [1] = 0 } }, { target = 900001, arguments = { n = 1, [1] = 0 } } }
          },
          [900001] = {
            n_id = 900001, argCount = 1, op = __retOp, operands = { 1, 1 },
            branches = {}
          }
        }
        local ok, r1 = pcall(${gName}(1, {}, __mock_env))
        if ok and #__probe_logs == 0 and r1 ~= nil then
          __loadkOp = op
          __mock_traces[tostring(op)] = { ok = true, logs = {}, isLoadK = true }
        end
      end
    end
  end

  if __retOp and __loadkOp and p1.constantValues then
    local __origK = {}
    for k = 1, 4 do __origK[k] = p1.constantValues[k]; p1.constantValues[k] = __mkSym("K", k) end
    for op in pairs(__usedOps) do
      if op ~= __retOp and op ~= __loadkOp then
        __probe_logs = {}
        __mock_nodes = {
          [p1.entry] = {
            n_id = p1.entry, argCount = 0, op = __loadkOp, operands = { 0 },
            branches = { { target = 900010, arguments = { n = 4, [1] = 0, [2] = 0, [3] = 0, [4] = 0 } } }
          },
          [900010] = {
            n_id = 900010, argCount = 4, op = op, operands = { 1, 1, 1, 2 },
            branches = {
              { target = 900099, arguments = { n = 1, [1] = 0 } },
              { target = 900098, arguments = { n = 1, [1] = 0 } }
            }
          },
          [900099] = { n_id = 900099, argCount = 1, op = __retOp, operands = { 1, 1 }, branches = {} },
          [900098] = { n_id = 900098, argCount = 1, op = __retOp, operands = { 1, 1 }, branches = {} }
        }
        local ups = { { v = __mkSym("UP", 1) }, { v = __mkSym("UP", 2) } }
        local ok, r1 = pcall(${gName}(1, ups, __mock_env))
        __mock_traces[tostring(op)] = {
          ok = ok,
          logs = __probe_logs,
          ret = (type(r1) == "table" and r1.__sym) or nil
        }
      end
    end
    for k = 1, 4 do p1.constantValues[k] = __origK[k] end
  end
  __mock_active = false
end
${nodeDecoderName} = __orig_dec

__js_capture_dump(__sv_to_json({ protos = __protos, mockTraces = __mock_traces }))
return nil
`;

  const res = runInSandbox(head + '\n' + dumper);
  if (!res.dumpResult) {
    throw new Error('SnowVeil v2.0 dynamic extraction produced no dump');
  }
  const data = JSON.parse(res.dumpResult);
  const opSemantics = classifySV2Opcodes(stage3Code, data.mockTraces || {});
  return { ...data, opSemantics };
}

function escapeRe(s) {
  return s ? s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : '__NONE__';
}

function parseLuaInt(tok) {
  if (/^0[xX]/.test(tok)) return parseInt(tok.slice(2), 16);
  if (/^0[bB]/.test(tok)) return parseInt(tok.slice(2), 2);
  return parseInt(tok, 10);
}

function discoverSV2Helpers(src) {
  const mRead = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*local\s+([A-Za-z_0-9]+)\s*=\s*\2\.registers\[\3\]\s*if\s+\2\.cellregs\[\3\]\s*then\s+return\s+\4\.v\s+end\s+return\s+\4/
  );
  const mWrite = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*if\s+\2\.cellregs\[\3\]\s*then\s+\2\.registers\[\3\]\.v\s*=\s*\4/
  );
  const mEnv =
    src.match(/=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*[A-Za-z_0-9]+\.fn\s*\)\s*\[/) ||
    src.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*[A-Za-z_0-9]+\.fn\s*\)\s*\[[^\]]+\]\s*=/) ||
    src.match(/,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*[A-Za-z_0-9]+\.fn\s*\)\s*\)/);
  const mCall = src.match(
    /(?:local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*)\s*=\s*function)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*local\s+([A-Za-z_0-9]+)\s*=\s*[A-Za-z_0-9]+\[\4\]\s*if\s+\9\s+then\s+if\s*#\3\s*>=\s*(?:0[xX]0*4[eE]20|20000)/
  );
  const mRet = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*local\s+([A-Za-z_0-9]+)\s*=\s*\2\[#\2\];\s*\2\[#\2\]\s*=\s*nil\s+while\s+\4\.continuation\s*==\s*(?:0[xX]0*3|0[bB]0*11|3)\b/
  );
  const mBranch = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*([A-Za-z_0-9]+)\(\s*\2\s*,\s*\3\.arguments\s*,\s*\4\s*,\s*\5\s*\)\s*;\s*\2\.k\s*=\s*\3\.target\s+end/
  );
  const mCollect = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*if\s+\4\s*==\s*-\s*(?:0[xXbB])?0*1\s+then\s+\4\s*=\s*[A-Za-z_0-9]+\(\s*\2\.top\s*-\s*\3/
  );

  return {
    readRegFn: mRead?.[1] || null,
    writeRegFn: mWrite?.[1] || null,
    getfenvFn: mEnv?.[1] || null,
    callFn: mCall?.[1] || mCall?.[2] || null,
    returnFn: mRet?.[1] || null,
    branchFn: mBranch?.[1] || null,
    stepFn: mBranch?.[6] || null,
    collectFn: mCollect?.[1] || null,
  };
}

function extractIfBranchBody(src, startIdx) {
  let depth = 0;
  let i = startIdx;
  const n = src.length;
  let expectingDo = false;
  while (i < n) {
    const ch = src[i];
    if (ch === '"' || ch === "'") {
      i++;
      while (i < n && src[i] !== ch) { if (src[i] === '\\') i += 2; else i++; }
      i++; continue;
    }
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_') {
      let j = i + 1;
      while (j < n && ((src[j] >= 'a' && src[j] <= 'z') || (src[j] >= 'A' && src[j] <= 'Z') || (src[j] >= '0' && src[j] <= '9') || src[j] === '_')) j++;
      const w = src.slice(i, j);
      if (w === 'for' || w === 'while') {
        depth++;
        expectingDo = true;
      } else if (w === 'do') {
        if (expectingDo) expectingDo = false;
        else depth++;
      } else if (w === 'function' || w === 'if') {
        depth++;
      } else if (w === 'end') {
        if (depth === 0) return src.slice(startIdx, i);
        depth--;
      } else if (depth === 0 && (w === 'else' || w === 'elseif')) {
        return src.slice(startIdx, i);
      }
      i = j; continue;
    }
    i++;
  }
  return null;
}

function classifySV2Opcodes(src, mockTraces = {}) {
  const helpers = discoverSV2Helpers(src);
  const opSemantics = {};

  const loopIdx = src.lastIndexOf('while true do');
  const loopSrc = loopIdx !== -1 ? src.slice(loopIdx) : src;

  const ifRe = /(?:else)?if\s+([A-Za-z_][A-Za-z0-9_]*)\s*==\s*(0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)\s*then\b/g;
  let m;
  while ((m = ifRe.exec(loopSrc)) !== null) {
    const id = parseLuaInt(m[2]);
    const body = extractIfBranchBody(loopSrc, m.index + m[0].length);
    if (!body) continue;
    const hasVMCall =
      (helpers.stepFn && body.includes(`${helpers.stepFn}(`)) ||
      (helpers.branchFn && body.includes(`${helpers.branchFn}(`)) ||
      (helpers.returnFn && body.includes(`${helpers.returnFn}(`)) ||
      (helpers.callFn && body.includes(`${helpers.callFn}(`)) ||
      body.includes('.arguments') ||
      body.includes('.resumeEdge');
    if (hasVMCall) {
      opSemantics[id] = classifySV2Handler(body, helpers, mockTraces[String(id)] || null);
    }
  }
  return opSemantics;
}

function classifySV2Handler(body, h, trace) {
  const logs = trace?.logs || [];
  const readReg = escapeRe(h.readRegFn);
  const writeReg = escapeRe(h.writeRegFn);
  const getfenv = escapeRe(h.getfenvFn);
  const callRe = h.callFn ? new RegExp(`\\b${escapeRe(h.callFn)}\\s*\\(`) : null;
  const retRe = h.returnFn ? new RegExp(`\\b${escapeRe(h.returnFn)}\\s*\\(`) : null;
  const branchRe = h.branchFn ? new RegExp(`\\b${escapeRe(h.branchFn)}\\s*\\(`) : null;

  // Fused supernodes have `.arguments`
  if (body.includes('.arguments') && !body.includes('.resumeEdge')) {
    return { op: 'FUSED' };
  }

  // Calls (CALL_SSA vs CALL vs CALL2 vs TAILCALL)
  if ((callRe && callRe.test(body)) || logs.some(l => l.startsWith('CALL'))) {
    if (retRe && retRe.test(body) && /,\s*(?:0[xX]0*3|0[bB]0*11|3)\s*,/.test(body)) return { op: 'TAILCALL' };
    if (/\{n\s*=\s*(?:0[xX]0*2|0[bB]0*10|2)\b/.test(body)) return { op: 'CALL2' };
    if (body.includes('.resumeEdge') && !(h.collectFn && body.includes(`${h.collectFn}(`))) {
      return { op: 'CALL_SSA' };
    }
    return { op: 'CALL' };
  }

  // Returns (RETURN_SSA vs register-based RETURN)
  if (trace?.isReturn || (retRe && retRe.test(body))) {
    if (!(h.collectFn && body.includes(`${h.collectFn}(`)) && !(h.readRegFn && body.includes(`${h.readRegFn}(`))) {
      return { op: 'RETURN_SSA' };
    }
    return { op: 'RETURN' };
  }

  if (body.includes('.prepare1')) return { op: 'FORGPREP' };
  if (body.includes('.captures')) return { op: 'CLOSURE' };
  if (body.includes('listCursor')) return { op: 'SETLIST' };
  if (body.includes('.varargs')) return { op: 'GETVARARGS' };

  if (body.includes('~=nil') && h.writeRegFn && new RegExp(`\\b${writeReg}\\s*\\(`).test(body)) {
    return { op: 'TFORLOOP' };
  }
  if (/\[(?:0[xXbB])?0*2\]/.test(body) && /\bif\s+not\b/.test(body)) return { op: 'JUMPIFNOT' };
  if (/\[(?:0[xXbB])?0*2\]/.test(body) && /\bif\s+[A-Za-z_0-9]+\[/.test(body)) return { op: 'JUMPIF' };

  if (body.includes('.constantValues[') && h.writeRegFn && new RegExp(`\\b${writeReg}\\s*\\(`).test(body)) {
    return { op: 'SELF' };
  }

  if (/\.closure\.b\[[^\]]+\]\.v\s*=/.test(body)) return { op: 'SETUPVAL' };
  if (body.includes('.closure.b[')) return { op: 'GETUPVAL' };

  if (logs.includes('SETGLOBAL') || (h.getfenvFn && new RegExp(`\\b${getfenv}\\([^)]*\\.fn\\)\\[[^\\]]+\\]\\s*=`).test(body))) {
    return { op: 'SETGLOBAL' };
  }
  if (logs.includes('GETGLOBAL') || (h.getfenvFn && new RegExp(`=\\s*${getfenv}\\([^)]*\\.fn\\)\\[`).test(body))) {
    return { op: 'GETGLOBAL' };
  }

  if (trace?.isLoadK || body.includes('.constantValues[')) return { op: 'LOADK' };

  if (h.writeRegFn && new RegExp(`\\b${writeReg}\\s*\\(`).test(body)) return { op: 'STORE_REG' };
  if (h.readRegFn && new RegExp(`=\\s*${readReg}\\s*\\(`).test(body)) return { op: 'LOAD_REG' };

  if (/=\s*\{\}/.test(body)) return { op: 'NEWTABLE' };

  const core = h.branchFn
    ? body.replace(new RegExp(`\\b${escapeRe(h.branchFn)}\\s*\\([\\s\\S]*$`), '')
    : body;

  if (/=\s*[A-Za-z_0-9]+\s*~=\s*(?:0[xXbB])?0+\b/.test(core)) return { op: 'LOADBOOL' };
  if (/=\s*nil\b/.test(core)) return { op: 'LOADNIL' };

  if (logs.includes('NOT') || /=\s*not\s+[A-Za-z_0-9]+/.test(core)) return { op: 'NOT' };
  if (logs.includes('LEN') || /=\s*#\s*[A-Za-z_0-9]+/.test(core)) return { op: 'LEN' };
  if (logs.includes('UNM') || /=\s*-\s*[A-Za-z_0-9]+/.test(core)) return { op: 'UNM' };

  if (logs.includes('SETTABLE') || /\b[A-Za-z_0-9]+\[[A-Za-z_0-9]+\]\s*=\s*[A-Za-z_0-9]+\b/.test(core)) {
    return { op: 'SETTABLE' };
  }

  const mBin = core.match(/=\s*([A-Za-z_0-9]+)\s*(\.\.|\/\/|==|~=|<=|>=|<|>|\+|-|\*|\/|%|\^)\s*([A-Za-z_0-9]+)/);
  if (mBin) {
    const opMap = {
      '~=': 'NEQ', '==': 'EQ', '<=': 'LE', '>=': 'GE', '<': 'LT', '>': 'GT',
      '..': 'CONCAT', '//': 'IDIV', '+': 'ADD', '-': 'SUB', '*': 'MUL', '/': 'DIV', '%': 'MOD', '^': 'POW',
    };
    return { op: opMap[mBin[2]] || 'UNKNOWN' };
  }

  // Fallback directly to Mock-VM metamethod logs if source syntax was obfuscated
  for (const symOp of ['ADD', 'SUB', 'MUL', 'DIV', 'IDIV', 'MOD', 'POW', 'CONCAT', 'EQ', 'LT', 'LE']) {
    if (logs.includes(symOp)) return { op: symOp };
  }

  if (logs.includes('GETTABLE') || /=\s*[A-Za-z_0-9]+\[[A-Za-z_0-9]+\]/.test(core)) return { op: 'GETTABLE' };

  if (branchRe && branchRe.test(body)) return { op: 'JMP' };

  return { op: 'UNKNOWN' };
}

module.exports = { extractSV2Dynamic, classifySV2Opcodes, discoverSV2Helpers };
