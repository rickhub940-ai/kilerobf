// Dynamic SnowVeil V3 Extractor + Runtime Mock-VM Prober + Opcode Classifier

const { runInSandbox } = require('./sandbox');

// Minimal Lua JSON encoder injected at Stage 3 tail
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

function findSchemaTables(stage3Code) {
  // Match adjacent recipe + terminal tables first, or independently if separated by decoy blocks
  const mAdj = stage3Code.match(
    /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{(?:\s*\[[^\]]+\]\s*=\s*\{[\s\S]*?\}\s*,?)+\}\s*;\s*local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{(?:\s*\[[^\]]+\]\s*=\s*\{[\s\S]*?\}\s*,?)+\}/
  );
  if (mAdj) {
    return {
      recipesVar: mAdj[1],
      terminalsVar: mAdj[2],
      insertions: [{ pos: mAdj.index + mAdj[0].length, text: ` local __sv_recipes=${mAdj[1]}; local __sv_terminals=${mAdj[2]}; ` }],
    };
  }

  // Fallback: locate recipe table (nested {{...}}) and terminal table ({num, num}) independently
  const tblRe = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{(\s*\[[^\]]+\]\s*=\s*\{[\s\S]*?\}\s*,?)+\}/g;
  let recipesVar = null, recipesPos = -1;
  let terminalsVar = null, terminalsPos = -1;
  let m;
  while ((m = tblRe.exec(stage3Code)) !== null) {
    const body = m[0];
    if (!recipesVar && /=\s*\{\s*\{/.test(body) && /(?:true|false)/.test(body)) {
      recipesVar = m[1];
      recipesPos = m.index + m[0].length;
    } else if (!terminalsVar && /\[\s*(?:0[xXbB][0-9a-fA-F]+|\d+)\s*\]\s*=\s*\{\s*(?:0[xXbB][0-9a-fA-F]+|\d+)\s*,\s*(?:0[xXbB][0-9a-fA-F]+|\d+)\s*\}/.test(body)) {
      terminalsVar = m[1];
      terminalsPos = m.index + m[0].length;
    }
  }
  const insertions = [];
  if (recipesVar) insertions.push({ pos: recipesPos, text: ` local __sv_recipes=${recipesVar}; ` });
  if (terminalsVar) insertions.push({ pos: terminalsPos, text: ` local __sv_terminals=${terminalsVar}; ` });
  return { recipesVar, terminalsVar, insertions };
}

function extractSV3Dynamic(stage3Code) {
  // Locate the LAST closure-factory entry call `local P = gFn(1, {}, env)` regardless of decoy blocks after it
  const tailCalls = [
    ...stage3Code.matchAll(/local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(?:0[bBxX])?0*1\s*,\s*\{\s*\}\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\)/g)
  ];
  if (tailCalls.length === 0) {
    throw new Error('Could not locate SnowVeil V3 entry call');
  }
  const lastCall = tailCalls[tailCalls.length - 1];
  const gName = lastCall[1];

  // Dynamically locate the proto loader called inside `gName` (`local r = loader(z)`)
  const gRe = new RegExp(`${escapeRe(gName)}\\s*=\\s*function\\s*\\([^)]*\\)\\s*(?:local\\s+[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*\\()`);
  const mG = stage3Code.match(gRe);
  if (!mG) {
    throw new Error('Could not locate SnowVeil V3 proto loader function');
  }
  const loaderName = mG[1];

  const schemas = findSchemaTables(stage3Code);
  let head = stage3Code.slice(0, lastCall.index);
  // Apply schema table captures in reverse offset order so indices stay valid
  const sortedIns = schemas.insertions.filter(x => x.pos < lastCall.index).sort((a, b) => b.pos - a.pos);
  for (const ins of sortedIns) {
    head = head.slice(0, ins.pos) + ins.text + head.slice(ins.pos);
  }

  // Inject Mock-VM runtime prober + proto dumper at the VM scope tail
  const dumper = `
${LUA_JSON_HELPER}
local __protos = {}
local __raw_protos = {}
local __idx = 1
while true do
  local ok, p = pcall(${loaderName}, __idx)
  if not ok or p == nil then break end
  __raw_protos[#__raw_protos+1] = p
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
  local blocks = {}
  for _, tok in ipairs(p.order) do
    local b = p.blocks[tok]
    blocks[#blocks+1] = {
      token = tok,
      nextToken = b.nextToken,
      targetToken = b.targetToken,
      count = b.count,
      instructionCount = b.instructionCount,
      recipeCount = b.recipeCount,
      scratchBound = b.scratchBound,
      selectors = b.selectors,
      starts = b.starts,
      fields = b.fields,
      operandKinds = b.operandKinds,
      operands = b.operands,
      immediates = b.immediates
    }
  end
  __protos[#__protos+1] = {
    id = __idx - 1,
    params = p.params,
    max = p.max,
    entry = p.entry,
    vararg = p.vararg,
    captures = p.captures,
    cells = p.cells,
    constantCount = p.constantCount,
    consts = consts,
    blocks = blocks
  }
  __idx = __idx + 1
end

-- Runtime Mock-VM Prober: wraps proto loader and executes selectors with symbolic metamethod proxies
local __mock_traces = {}
local __orig_loader = ${loaderName}
local __mock_proto = nil
${loaderName} = function(id)
  if id == -999 then return __mock_proto end
  return __orig_loader(id)
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
    __call = function() __probe_logs[#__probe_logs+1] = "CALL"; return __mkSym("ret", "CALL") end,
  })
end

local __mock_env = setmetatable({}, {
  __index = function(_, k) __probe_logs[#__probe_logs+1] = "GETGLOBAL"; return __mkSym("G", k) end,
  __newindex = function() __probe_logs[#__probe_logs+1] = "SETGLOBAL" end
})

local function __mkUps()
  local ups = {}
  for i = 1, 32 do ups[i] = { v = __mkSym("UP", i) } end
  return ups
end

local __returnSel = nil
if __sv_terminals then
  for tsel, _ in pairs(__sv_terminals) do
    __probe_logs = {}
    __mock_proto = {
      params = 8, max = 32, entry = 1, vararg = true, captures = {}, cells = {},
      constantCount = 8,
      constantValues = { __mkSym("K", 1), __mkSym("K", 2), __mkSym("K", 3), __mkSym("K", 4), __mkSym("K", 5), __mkSym("K", 6), __mkSym("K", 7), __mkSym("K", 8) },
      order = { 1 },
      blocks = {
        [1] = {
          token = 1, nextToken = 999, targetToken = 998,
          count = 1, instructionCount = 1, recipeCount = 0, scratchBound = 0,
          selectors = { tsel }, starts = { 1 },
          fields = { 1, 2, 3, 4, 5, 6, 7, 8 },
          operandKinds = { 1, 1, 1, 1, 1, 1 },
          operands = { 1, 2, 3, 4, 5, 6 },
          immediates = { 1, 2, 3, 4, 5, 6 },
        }
      }
    }
    local fn = ${gName}(-999, __mkUps(), __mock_env)
    local ok, r1 = pcall(fn, __mkSym("R", 1), __mkSym("R", 2), __mkSym("R", 3), __mkSym("R", 4))
    __mock_traces[tostring(tsel)] = { ok = ok, logs = __probe_logs, ret = (type(r1) == "table" and r1.__sym) or nil }
    if ok and #__probe_logs == 0 and type(r1) == "table" and r1.__sym then
      __returnSel = tsel
    end
  end
end

if __returnSel and __sv_recipes then
  for rsel, rsteps in pairs(__sv_recipes) do
    if #rsteps == 1 then
      __probe_logs = {}
      __mock_proto = {
        params = 8, max = 32, entry = 1, vararg = true, captures = {}, cells = {},
        constantCount = 8,
        constantValues = { __mkSym("K", 1), __mkSym("K", 2), __mkSym("K", 3), __mkSym("K", 4), __mkSym("K", 5), __mkSym("K", 6), __mkSym("K", 7), __mkSym("K", 8) },
        order = { 1 },
        blocks = {
          [1] = {
            token = 1, nextToken = 999, targetToken = 998,
            count = 2, instructionCount = 2, recipeCount = 1, scratchBound = 8,
            selectors = { rsel, __returnSel }, starts = { 1, 1 },
            fields = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 1 },
            operandKinds = { 2, 1, 2, 1, 2, 1 },
            operands = { 1, 2, 3, 4, 5, 6 },
            immediates = { 1, 6, 2, 3, 4, 5 },
          }
        }
      }
      local fn = ${gName}(-999, __mkUps(), __mock_env)
      local ok = pcall(fn, __mkSym("R", 1), __mkSym("R", 2), __mkSym("R", 3), __mkSym("R", 4))
      __mock_traces[tostring(rsel)] = { ok = ok, logs = __probe_logs }
    end
  end
end

${loaderName} = __orig_loader

local __payload = {
  protos = __protos,
  recipes = __sv_recipes,
  terminals = __sv_terminals,
  mockTraces = __mock_traces
}
__js_capture_dump(__sv_to_json(__payload))
return nil
`;

  const res = runInSandbox(head + '\n' + dumper);
  if (!res.dumpResult) {
    throw new Error('Stage 3 dynamic extraction produced no dump');
  }
  const data = JSON.parse(res.dumpResult);
  const opSemantics = classifySV3Opcodes(stage3Code, data.recipes || {}, data.terminals || {}, data.mockTraces || {});
  return { ...data, opSemantics };
}

// Dynamically discover all randomized VM helper names from Stage 3 source (no hardcoded variable fallbacks)
function discoverVMHelpers(src) {
  const mRead = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]+\)\s*if\s+[A-Za-z_0-9]+\s*==\s*(?:0[xXbB])?0*1\s+then\s+return\s+[A-Za-z_0-9]+\[[A-Za-z_0-9]+\]\s*elseif\s+[A-Za-z_0-9]+\s*==\s*(?:0[xX]0*2|0[bB]0*10|2)\s+then\s+return\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/
  );
  const mWrite = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*if\s+\2\.cellregs\[\3\]\s*then\s+\2\.registers\[\3\]\.v\s*=\s*\4/
  );
  const mEnv =
    src.match(/=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*[A-Za-z_0-9]+\.fn\s*\)\s*\[/) ||
    src.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*[A-Za-z_0-9]+\.fn\s*\)\s*\[[^\]]+\]\s*=/) ||
    src.match(/,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*[A-Za-z_0-9]+\.fn\s*\)\s*\)/);
  const mStoreMulti = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*local\s+([A-Za-z_0-9]+)\s*=\s*\4\s*==\s*-\s*(?:0[xXbB])?0*1\b/
  );
  const mCall = src.match(
    /(?:local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*)\s*=\s*function)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*local\s+([A-Za-z_0-9]+)\s*=\s*[A-Za-z_0-9]+\[\4\]\s*if\s+\9\s+then\s+if\s*#\3\s*>=\s*(?:0[xX]0*4[eE]20|20000)/
  );
  const mRet = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*local\s+([A-Za-z_0-9]+)\s*=\s*\2\[#\2\];\s*\2\[#\2\]\s*=\s*nil\s+while\s+\4\.continuation\s*==\s*(?:0[xX]0*3|0[bB]0*11|3)\b/
  );
  const mCollect = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*if\s+\4\s*==\s*-\s*(?:0[xXbB])?0*1\s+then\s+\4\s*=\s*[A-Za-z_0-9]+\(\s*\2\.top\s*-\s*\3/
  );

  return {
    readOpFn: mRead?.[1] || null,
    readRegFn: mRead?.[2] || null,
    writeRegFn: mWrite?.[1] || null,
    getfenvFn: mEnv?.[1] || null,
    storeMultiFn: mStoreMulti?.[1] || null,
    callFn: mCall?.[1] || mCall?.[2] || null,
    returnFn: mRet?.[1] || null,
    collectFn: mCollect?.[1] || null,
  };
}

function escapeRe(s) {
  return s ? s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : '__NONE__';
}

// Classify every opcode handler combining Runtime Mock-VM traces + dynamic structural checks
function classifySV3Opcodes(src, recipes, terminals, mockTraces = {}) {
  const opSemantics = {};
  const helpers = discoverVMHelpers(src);
  const handlers = new Map();

  // 1. Scan `[<num>] = function(<params>)`
  const fnRe = /\[\s*(0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)\s*\]\s*=\s*function\s*\(([^)]*)\)/g;
  let m;
  while ((m = fnRe.exec(src)) !== null) {
    const id = parseLuaInt(m[1]);
    const params = m[2].split(',').map(s => s.trim()).filter(Boolean);
    if (params.length >= 5) {
      const body = extractLuaBlock(src, m.index + m[0].length);
      if (body) handlers.set(id, { params, body, source: 'table' });
    }
  }

  // 2. Scan `if <var> == <num> then` in VM dispatch loop
  const ifRe = /if\s+[A-Za-z_][A-Za-z0-9_]*\s*==\s*(0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)\s*then\b/g;
  while ((m = ifRe.exec(src)) !== null) {
    const id = parseLuaInt(m[1]);
    if (!handlers.has(id)) {
      const body = extractIfBranchBody(src, m.index + m[0].length);
      if (body && (body.includes('.fields') || body.includes('.nextToken'))) {
        handlers.set(id, { params: null, body, source: 'tree' });
      }
    }
  }

  for (const [id, info] of handlers.entries()) {
    const trace = mockTraces[String(id)] || null;
    if (terminals[id]) {
      opSemantics[id] = { kind: 'term', op: classifyTerminalBody(info.body, helpers, trace) };
    } else if (recipes[id]) {
      opSemantics[id] = { kind: 'recipe', steps: classifyRecipeBody(info.body, recipes[id].length, helpers, trace) };
    }
  }

  return opSemantics;
}

function parseLuaInt(tok) {
  if (/^0[xX]/.test(tok)) return parseInt(tok.slice(2), 16);
  if (/^0[bB]/.test(tok)) return parseInt(tok.slice(2), 2);
  return parseInt(tok, 10);
}

function extractLuaBlock(src, startIdx) {
  let depth = 1;
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
        depth--;
        if (depth === 0) return src.slice(startIdx, i);
      }
      i = j; continue;
    }
    i++;
  }
  return null;
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

function classifyTerminalBody(body, helpers, trace) {
  const logs = trace?.logs || [];
  const callRe = helpers.callFn ? new RegExp(`\\b${escapeRe(helpers.callFn)}\\s*\\(`) : null;
  const retRe = helpers.returnFn ? new RegExp(`\\b${escapeRe(helpers.returnFn)}\\s*\\(`) : null;
  const writeRe = helpers.writeRegFn ? new RegExp(`\\b${escapeRe(helpers.writeRegFn)}\\s*\\(`) : null;

  if (body.includes('.varargs')) return 'GETVARARGS';
  if (body.includes('.targetToken')) {
    // Numeric FORLOOP vs FORNPREP
    if (/<=\s*[A-Za-z_0-9]+\)\s*or\s*\(\s*not/.test(body)) {
      if (/\belse\s+[A-Za-z_0-9]+\.token\s*=/.test(body)) return 'FORNPREP';
      return 'FORLOOP';
    }
    if (body.includes('~=nil')) return 'TFORLOOP';
    if (body.includes('if not ')) return 'JUMPIFNOT';
    return 'JUMPIF';
  }
  if (logs.includes('CALL') || (callRe && callRe.test(body))) {
    if (trace?.ok || (retRe && retRe.test(body) && /,\s*(?:0[xX]0*3|0[bB]0*11|3)\s*,/.test(body))) return 'TAILCALL';
    if (/\{n\s*=\s*(?:0[xX]0*2|0[bB]0*10|2)\b/.test(body)) return 'CALL2';
    return 'CALL';
  }
  if (body.includes('.captures')) return 'CLOSURE';
  if (logs.some(l => l === 'SETTABLE') || body.includes('listCursor')) return 'SETLIST';
  if (body.includes('.prepare1')) return 'FORGPREP';
  if ((trace?.ok && trace?.ret) || (retRe && retRe.test(body))) return 'RETURN';
  if (logs.includes('GETTABLE') || (writeRe && writeRe.test(body) && /\[[A-Za-z_0-9]+\]/.test(body) && /==/.test(body))) return 'SELF';
  if (!body.includes('(')) return 'JMP';
  return 'UNKNOWN_TERM';
}

function classifyRecipeBody(body, nSteps, helpers, trace) {
  const stepBlocks = [];
  let i = 0;
  const n = body.length;
  let expectingDo = false;
  while (i < n) {
    const ch = body[i];
    if (ch === '"' || ch === "'") {
      i++;
      while (i < n && body[i] !== ch) { if (body[i] === '\\') i += 2; else i++; }
      i++; continue;
    }
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_') {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_]/.test(body[j])) j++;
      const w = body.slice(i, j);
      if (w === 'for' || w === 'while') expectingDo = true;
      else if (w === 'do') {
        if (expectingDo) {
          expectingDo = false;
        } else {
          const inner = extractLuaBlock(body, j);
          if (inner != null) {
            stepBlocks.push(inner);
            i = j + inner.length + 3;
            continue;
          }
        }
      }
      i = j; continue;
    }
    i++;
  }
  const blocksToParse = stepBlocks.length > 0 ? stepBlocks : [body];
  return blocksToParse.map((sb, idx) => classifyMicroStep(sb, helpers, blocksToParse.length === 1 ? trace : null, idx));
}

function classifyMicroStep(sb, helpers, trace) {
  const logs = trace?.logs || [];
  const readOp = escapeRe(helpers.readOpFn);
  const readReg = escapeRe(helpers.readRegFn);
  const writeReg = escapeRe(helpers.writeRegFn);
  const getfenv = escapeRe(helpers.getfenvFn);

  // Strip trailing standard writeback epilogue
  let core = sb;
  const ep1 = core.search(/\bif\s+[A-Za-z_0-9]+\[[^\]]+\]\s*==\s*(?:0[xXbB])?0*1\s+then\b/);
  if (ep1 !== -1) core = core.slice(0, ep1);
  const ep2 = core.search(/\blocal\s+[A-Za-z_0-9]+\s*=\s*[A-Za-z_0-9]+\[[^\]]+\]\s*;?\s*if\s+[A-Za-z_0-9]+\s*~=\s*(?:0[xXbB])?0+\s+then\b/);
  if (ep2 !== -1) core = core.slice(0, ep2);

  const readOpRe = helpers.readOpFn ? new RegExp(`\\b${readOp}\\([^)]*\\)`, 'g') : null;
  const readRegRe = helpers.readRegFn ? new RegExp(`=\\s*${readReg}\\(`) : null;
  const writeRegImmRe = helpers.writeRegFn ? new RegExp(`\\b${writeReg}\\([^,]+,\\s*[A-Za-z_0-9]+\\[[^\\]]+\\]\\s*,`) : null;
  const getGlobalCoreRe = helpers.getfenvFn ? new RegExp(`=\\s*${getfenv}\\([^)]*\\.fn\\)\\[`) : null;
  const setGlobalCoreRe = helpers.getfenvFn ? new RegExp(`\\b${getfenv}\\([^)]*\\.fn\\)\\[[^\\]]+\\]\\s*=`) : null;

  if (/\.cellregs\[.+\]\s*=\s*true\b/.test(core)) {
    return 'NEWCELL';
  }

  if (writeRegImmRe && writeRegImmRe.test(core)) {
    if (core.includes('.closure.b[')) return 'FUSED_GETUPVAL';
    if (getGlobalCoreRe && getGlobalCoreRe.test(core)) {
      if (readOpRe && readOpRe.test(core)) {
        readOpRe.lastIndex = 0;
        return 'FUSED_GETGLOBAL_Y';
      }
      return 'FUSED_GETGLOBAL_K';
    }
    if (helpers.readRegFn && helpers.writeRegFn) {
      const fusedGetTblRe = new RegExp(
        `=\\s*${readReg}\\([^)]*\\)\\s*[A-Za-z_0-9]+\\s*=\\s*[A-Za-z_0-9]+\\[.+\\]\\s*[A-Za-z_0-9]+\\s*=\\s*[A-Za-z_0-9]+\\[[A-Za-z_0-9]+\\]\\s*${writeReg}\\(`
      );
      if (fusedGetTblRe.test(core)) return 'FUSED_GETTABLE_K';
    }
    if (readRegRe && readRegRe.test(core)) {
      if (/=\s*-\s*[A-Za-z_0-9]+/.test(core)) return 'FUSED_UNM';
      if (/=\s*not\s+[A-Za-z_0-9]+/.test(core)) return 'FUSED_NOT';
      if (/=\s*#\s*[A-Za-z_0-9]+/.test(core)) return 'FUSED_LEN';
      return 'FUSED_MOVE';
    }
    if (readOpRe && readOpRe.test(core)) {
      readOpRe.lastIndex = 0;
      return 'FUSED_STORE_REG';
    }
    if (/~=\s*(?:0[xXbB])?0+\b/.test(core)) return 'FUSED_LOADBOOL';
    if (/=\s*\{\}/.test(core)) return 'FUSED_NEWTABLE';
    if (/\+\s*(?:0[xXbB])?0*1\s*\]/.test(core)) return 'FUSED_LOADK';
    return 'FUSED_LOADNIL';
  }
  if (/\.closure\.b\[.+\]\.v\s*=/.test(core)) {
    if (readOpRe && readOpRe.test(core)) {
      readOpRe.lastIndex = 0;
      return 'FUSED_STORE_UPVAL_Y';
    }
    return 'FUSED_STORE_UPVAL_R';
  }
  if (getGlobalCoreRe && getGlobalCoreRe.test(core)) {
    if (readOpRe && readOpRe.test(core)) {
      readOpRe.lastIndex = 0;
      return 'FUSED_GETGLOBAL_Y';
    }
    return 'FUSED_GETGLOBAL_K';
  }
  if (readOpRe) readOpRe.lastIndex = 0;
  if ((!readOpRe || !readOpRe.test(core)) && /\[[A-Za-z_0-9]+\]\s*=\s*[A-Za-z_0-9]+\b/.test(core)) {
    return 'FUSED_SETTABLE_K';
  }

  // Standard micro-op: consult Mock-VM trace first, then verify operator/direction from core
  if (readOpRe) readOpRe.lastIndex = 0;
  const yMatches = readOpRe ? [...core.matchAll(readOpRe)] : [];
  const yCount = yMatches.length;

  if (logs.includes('SETGLOBAL') || (setGlobalCoreRe && setGlobalCoreRe.test(core))) return 'SETGLOBAL';
  if (logs.includes('GETGLOBAL') || core.includes('.fn)')) return 'GETGLOBAL';
  if (/=\s*\{\}/.test(core)) return 'NEWTABLE';

  const afterY = yCount > 0
    ? core.slice(yMatches[yCount - 1].index + yMatches[yCount - 1][0].length)
    : core;

  if (yCount === 3 || logs.includes('SETTABLE')) return 'SETTABLE';
  if (yCount === 2) {
    const mOp = afterY.match(/=\s*([A-Za-z_0-9]+)\s*(\.\.|\/\/|==|~=|<=|>=|<|>|\+|-|\*|\/|%|\^)\s*([A-Za-z_0-9]+)/);
    if (mOp) {
      const opMap = {
        '~=': 'NEQ', '==': 'EQ', '<=': 'LE', '>=': 'GE', '<': 'LT', '>': 'GT',
        '..': 'CONCAT', '//': 'IDIV', '+': 'ADD', '-': 'SUB', '*': 'MUL', '/': 'DIV', '%': 'MOD', '^': 'POW'
      };
      return opMap[mOp[2]] || 'UNKNOWN_BINOP';
    }
    if (logs.includes('GETTABLE') || /=\s*[A-Za-z_0-9]+\[[A-Za-z_0-9]+\]/.test(afterY)) return 'GETTABLE';
  }
  if (yCount === 1) {
    if (logs.includes('NOT') || /=\s*not\s+[A-Za-z_0-9]+/.test(afterY)) return 'NOT';
    if (logs.includes('LEN') || /=\s*#\s*[A-Za-z_0-9]+/.test(afterY)) return 'LEN';
    if (logs.includes('UNM') || /=\s*-\s*[A-Za-z_0-9]+/.test(afterY)) return 'UNM';
    return 'MOVE_Y';
  }
  if (readRegRe && readRegRe.test(core)) return 'MOVE_REG';
  return 'UNKNOWN_STEP';
}

module.exports = { extractSV3Dynamic, classifySV3Opcodes, discoverVMHelpers };
