// Dynamic SnowVeil v2.0 (SSA CFG / liveState) Extractor + Opcode Classifier

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
  const mTail = stage3Code.match(
    /local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(?:0[bBxX])?0*1\s*,\s*\{\s*\}\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*;?\s*local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)\s*\)\s*return\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]+\)\s*$/
  );
  if (!mTail) {
    throw new Error('Could not locate SnowVeil v2.0 SSA CFG entry tail');
  }
  const gName = mTail[1];

  const gRe = new RegExp(
    `${gName}\\s*=\\s*function\\s*\\([^)]*\\)\\s*local\\s+[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*\\(`
  );
  const mG = stage3Code.match(gRe);
  if (!mG) {
    throw new Error('Could not locate SnowVeil v2.0 proto loader function');
  }
  const loaderName = mG[1];

  // Locate node decoder: `local function y(X, T) ... X.offsets[T] ...`
  const mNodeDec = stage3Code.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)[\s\S]{0,350}\2\.offsets\[\3\]/
  );
  if (!mNodeDec) {
    throw new Error('Could not locate SnowVeil v2.0 node decoder function');
  }
  const nodeDecoderName = mNodeDec[1];

  const head = stage3Code.slice(0, mTail.index);

  const dumper = `
${LUA_JSON_HELPER}
local __protos = {}
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
    local fsOut = nil
    if fusedSteps then
      fsOut = {}
      for si = 1, #fusedSteps do
        local fs = fusedSteps[si]
        local subArgs = {}
        local sa = fs[5]
        if sa then
          for ai = 1, (sa.n or #sa) do
            subArgs[ai] = sa[ai]
          end
        end
        fsOut[si] = {
          subId = fs[1],
          argCount = fs[2],
          op = fs[3],
          operands = fs[4] or {},
          args = subArgs
        }
      end
    end
    nodes[#nodes + 1] = {
      id = nid,
      argCount = argCount,
      op = op,
      operands = operands or {},
      branches = brOut,
      fusedSteps = fsOut
    }
  end

  local entryParams = {}
  for ei = 1, #(p.entryParameters or {}) do
    entryParams[ei] = p.entryParameters[ei]
  end

  __protos[#__protos + 1] = {
    id = __idx - 1,
    params = p.params,
    max = p.max,
    entry = p.entry,
    entryParameters = entryParams,
    vararg = p.vararg,
    liveState = p.liveState,
    captures = p.captures,
    cells = p.cells,
    constantCount = p.constantCount,
    consts = consts,
    nodes = nodes
  }
  __idx = __idx + 1
end
__js_capture_dump(__sv_to_json({ protos = __protos }))
return nil
`;

  const res = runInSandbox(head + '\n' + dumper);
  if (!res.dumpResult) {
    throw new Error('SnowVeil v2.0 dynamic extraction produced no dump');
  }
  const data = JSON.parse(res.dumpResult);
  const opSemantics = classifySV2Opcodes(stage3Code);
  return { ...data, opSemantics };
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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
    readRegFn: mRead?.[1] || 'a',
    writeRegFn: mWrite?.[1] || 'J',
    getfenvFn: mEnv?.[1] || 'K',
    callFn: mCall?.[1] || mCall?.[2] || 'F',
    returnFn: mRet?.[1] || 'H',
    branchFn: mBranch?.[1] || 'G',
    stepFn: mBranch?.[6] || 'E',
    collectFn: mCollect?.[1] || 'O',
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

function classifySV2Opcodes(src) {
  const helpers = discoverSV2Helpers(src);
  const opSemantics = {};

  // Locate main VM dispatch loop `while true do`
  const loopIdx = src.lastIndexOf('while true do');
  const loopSrc = loopIdx !== -1 ? src.slice(loopIdx) : src;

  const ifRe = /(?:else)?if\s+([A-Za-z_][A-Za-z0-9_]*)\s*==\s*(0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)\s*then\b/g;
  let m;
  while ((m = ifRe.exec(loopSrc)) !== null) {
    const id = parseLuaInt(m[2]);
    const body = extractIfBranchBody(loopSrc, m.index + m[0].length);
    if (!body) continue;
    if (body.includes(`${helpers.stepFn}(`) || body.includes(`${helpers.branchFn}(`) || body.includes(`${helpers.returnFn}(`)) {
      opSemantics[id] = classifySV2Handler(body, helpers);
    }
  }
  return opSemantics;
}

function classifySV2Handler(body, h) {
  const readReg = escapeRe(h.readRegFn);
  const writeReg = escapeRe(h.writeRegFn);
  const getfenv = escapeRe(h.getfenvFn);
  const callRe = new RegExp(`\\b${escapeRe(h.callFn)}\\s*\\(`);
  const retRe = new RegExp(`\\b${escapeRe(h.returnFn)}\\s*\\(`);
  const branchRe = new RegExp(`\\b${escapeRe(h.branchFn)}\\s*\\(`);

  // Fused supernodes have `.arguments` and multiple `do ... end` blocks
  if (body.includes('.arguments')) {
    return { op: 'FUSED' };
  }

  // Terminals & multi-branch control flow
  if (callRe.test(body)) {
    if (retRe.test(body) && /,\s*(?:0[xX]0*3|0[bB]0*11|3)\s*,/.test(body)) return { op: 'TAILCALL' };
    if (/\{n\s*=\s*(?:0[xX]0*2|0[bB]0*10|2)\b/.test(body)) return { op: 'CALL2' };
    return { op: 'CALL' };
  }
  if (retRe.test(body)) return { op: 'RETURN' };
  if (body.includes('.prepare1')) return { op: 'FORGPREP' };
  if (body.includes('.captures')) return { op: 'CLOSURE' };
  if (body.includes('listCursor')) return { op: 'SETLIST' };
  if (body.includes('.varargs')) return { op: 'GETVARARGS' };

  // TFORLOOP: `if ak~=nil then J(l,ai,ak); aj=ae[2] end`
  if (body.includes('~=nil') && new RegExp(`\\b${writeReg}\\s*\\(`).test(body)) {
    return { op: 'TFORLOOP' };
  }
  // Conditional jump: `if not aa[ah] then ai=ae[2] end` or `if aa[ah] then ai=ae[2] end`
  if (/\[(?:0[xXbB])?0*2\]/.test(body) && /\bif\s+not\b/.test(body)) return { op: 'JUMPIFNOT' };
  if (/\[(?:0[xXbB])?0*2\]/.test(body) && /\bif\s+[A-Za-z_0-9]+\[/.test(body)) return { op: 'JUMPIF' };

  // SELF: `aj = a(l, ah+1); ak = T.constantValues[ai+1] ... J(l, ah, ai)`
  if (body.includes('.constantValues[') && new RegExp(`\\b${writeReg}\\s*\\(`).test(body)) {
    return { op: 'SELF' };
  }

  // Upvalue write / read
  if (/\.closure\.b\[[^\]]+\]\.v\s*=/.test(body)) return { op: 'SETUPVAL' };
  if (body.includes('.closure.b[')) return { op: 'GETUPVAL' };

  // Global read
  if (new RegExp(`=\\s*${getfenv}\\([^)]*\\.fn\\)\\[`).test(body)) return { op: 'GETGLOBAL' };

  // Constant load
  if (body.includes('.constantValues[')) return { op: 'LOADK' };

  // Register write / read
  if (new RegExp(`\\b${writeReg}\\s*\\(`).test(body)) return { op: 'STORE_REG' };
  if (new RegExp(`=\\s*${readReg}\\s*\\(`).test(body)) return { op: 'LOAD_REG' };

  // Newtable
  if (/=\s*\{\}/.test(body)) return { op: 'NEWTABLE' };

  // Strip trailing branchFn call to inspect value expression
  const core = body.replace(new RegExp(`\\b${escapeRe(h.branchFn)}\\s*\\([\\s\\S]*$`), '');

  // LOADBOOL: `ah = ai ~= 0` (must check before NEQ!)
  if (/=\s*[A-Za-z_0-9]+\s*~=\s*(?:0[xXbB])?0+\b/.test(core)) return { op: 'LOADBOOL' };

  // LOADNIL: `ah = nil`
  if (/=\s*nil\b/.test(core)) return { op: 'LOADNIL' };

  // Unary ops (must check before GETTABLE because `ai = aa[aj]; ah = not ai` reads `aa[aj]` first!)
  if (/=\s*not\s+[A-Za-z_0-9]+/.test(core)) return { op: 'NOT' };
  if (/=\s*#\s*[A-Za-z_0-9]+/.test(core)) return { op: 'LEN' };
  if (/=\s*-\s*[A-Za-z_0-9]+/.test(core)) return { op: 'UNM' };

  // SETTABLE: `ai[aj] = ak`
  if (/\b[A-Za-z_0-9]+\[[A-Za-z_0-9]+\]\s*=\s*[A-Za-z_0-9]+\b/.test(core)) return { op: 'SETTABLE' };

  // Binary ops
  const mBin = core.match(/=\s*([A-Za-z_0-9]+)\s*(\.\.|\/\/|==|~=|<=|>=|<|>|\+|-|\*|\/|%|\^)\s*([A-Za-z_0-9]+)/);
  if (mBin) {
    const opMap = {
      '~=': 'NEQ', '==': 'EQ', '<=': 'LE', '>=': 'GE', '<': 'LT', '>': 'GT',
      '..': 'CONCAT', '//': 'IDIV', '+': 'ADD', '-': 'SUB', '*': 'MUL', '/': 'DIV', '%': 'MOD', '^': 'POW',
    };
    return { op: opMap[mBin[2]] || 'UNKNOWN' };
  }

  // GETTABLE: `ah = ai[aj]`
  if (/=\s*[A-Za-z_0-9]+\[[A-Za-z_0-9]+\]/.test(core)) return { op: 'GETTABLE' };

  // Pure JMP: just `G(l, ae[1], aa, nil)`
  if (branchRe.test(body)) return { op: 'JMP' };

  return { op: 'UNKNOWN' };
}

module.exports = { extractSV2Dynamic, classifySV2Opcodes, discoverSV2Helpers };
