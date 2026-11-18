// Dynamic SnowVeil V3 & V2 Stage 3 Extractor + Opcode Classifier

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
    -- check array vs object
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

function extractSV3Dynamic(stage3Code) {
  // Locate closure factory `g` and proto loader `c` dynamically
  const mTail = stage3Code.match(/local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(?:0[bBxX])?0*1\s*,\s*\{\s*\}\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*;?\s*local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)\s*\)\s*return\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]+\)\s*$/);
  if (!mTail) {
    throw new Error('Could not locate SnowVeil V3 entry tail');
  }
  const gName = mTail[1];
  // Find `g = function(z, W, J) local r = c(z)`
  const gRe = new RegExp(`${gName}\\s*=\\s*function\\s*\\([^)]*\\)\\s*local\\s+[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*\\(`);
  const mG = stage3Code.match(gRe);
  if (!mG) {
    throw new Error('Could not locate SnowVeil V3 proto loader function');
  }
  const loaderName = mG[1];

  // Also locate recipe table `c` and terminal table `G` right before `local function n()`
  const mSchemas = stage3Code.match(/local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{(?:\s*\[[^\]]+\]\s*=\s*\{[\s\S]*?\}\s*,?)+\}\s*;\s*local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{(?:\s*\[[^\]]+\]\s*=\s*\{[\s\S]*?\}\s*,?)+\}/);
  let head = stage3Code.slice(0, mTail.index);
  if (mSchemas) {
    const insPos = mSchemas.index + mSchemas[0].length;
    head = head.slice(0, insPos) + ` local __sv_recipes=${mSchemas[1]}; local __sv_terminals=${mSchemas[2]}; ` + head.slice(insPos);
  }

  // Replace tail with dynamic dumper
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
local __payload = {
  protos = __protos,
  recipes = __sv_recipes,
  terminals = __sv_terminals
}
__js_capture_dump(__sv_to_json(__payload))
return nil
`;

  const res = runInSandbox(head + '\n' + dumper);
  if (!res.dumpResult) {
    throw new Error('Stage 3 dynamic extraction produced no dump');
  }
  const data = JSON.parse(res.dumpResult);
  const opSemantics = classifySV3Opcodes(stage3Code, data.recipes || {}, data.terminals || {});
  return { ...data, opSemantics };
}

// Dynamically discover all randomized VM helper names from Stage 3 source
function discoverVMHelpers(src) {
  const mRead = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]+\)\s*if\s+[A-Za-z_0-9]+\s*==\s*(?:0[xXbB])?0*1\s+then\s+return\s+[A-Za-z_0-9]+\[[A-Za-z_0-9]+\]\s*elseif\s+[A-Za-z_0-9]+\s*==\s*(?:0[xX]0*2|0[bB]0*10|2)\s+then\s+return\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/
  );
  const mWrite = src.match(
    /local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*\)\s*if\s+\2\.cellregs\[\3\]\s*then\s+\2\.registers\[\3\]\.v\s*=\s*\4/
  );
  const mEnv =
    src.match(/=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*[A-Za-z_0-9]+\.fn\s*\)\s*\[/) ||
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
    readOpFn: mRead?.[1] || 'y',
    readRegFn: mRead?.[2] || 'e',
    writeRegFn: mWrite?.[1] || 'F',
    getfenvFn: mEnv?.[1] || 'S',
    storeMultiFn: mStoreMulti?.[1] || 'H',
    callFn: mCall?.[1] || mCall?.[2] || 't',
    returnFn: mRet?.[1] || 'o',
    collectFn: mCollect?.[1] || 'h',
  };
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Dynamically parse every opcode handler from Stage 3 source and classify its exact semantics
function classifySV3Opcodes(src, recipes, terminals) {
  const opSemantics = {}; // opId -> { kind: 'recipe'|'term', steps: [...] | termType }
  const helpers = discoverVMHelpers(src);

  // Helper: extract handler bodies from `u = T({ [ID] = function(...) ... end, ... })`
  // and from `if aj == ID then ...` binary search tree
  const handlers = new Map(); // opId (number) -> { params: [...], body: string }

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
    if (terminals[id]) {
      opSemantics[id] = { kind: 'term', op: classifyTerminalBody(info.body, helpers) };
    } else if (recipes[id]) {
      opSemantics[id] = { kind: 'recipe', steps: classifyRecipeBody(info.body, recipes[id].length, helpers) };
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
  // Walk tokens tracking function/if/for/while/do vs end (for..do and while..do only have 1 end!)
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

function classifyTerminalBody(body, helpers) {
  const callRe = new RegExp(`\\b${escapeRe(helpers.callFn)}\\s*\\(`);
  const retRe = new RegExp(`\\b${escapeRe(helpers.returnFn)}\\s*\\(`);
  const writeRe = new RegExp(`\\b${escapeRe(helpers.writeRegFn)}\\s*\\(`);

  if (body.includes('.targetToken')) {
    if (body.includes('~=nil')) return 'TFORLOOP';
    if (body.includes('if not ')) return 'JUMPIFNOT';
    return 'JUMPIF';
  }
  if (callRe.test(body)) {
    if (retRe.test(body) && /,\s*(?:0[xX]0*3|0[bB]0*11|3)\s*,/.test(body)) return 'TAILCALL';
    if (/\{n\s*=\s*(?:0[xX]0*2|0[bB]0*10|2)\b/.test(body)) return 'CALL2';
    return 'CALL';
  }
  if (body.includes('.captures')) return 'CLOSURE';
  if (body.includes('listCursor')) return 'SETLIST';
  if (body.includes('.prepare1')) return 'FORGPREP';
  if (retRe.test(body)) return 'RETURN';
  if (writeRe.test(body) && /\[[A-Za-z_0-9]+\]/.test(body) && /==/.test(body)) return 'SELF';
  if (!body.includes('(')) return 'JMP';
  return 'UNKNOWN_TERM';
}

function classifyRecipeBody(body, nSteps, helpers) {
  // Split into `do ... end` micro-op steps (ignoring strings)
  const steps = [];
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

  for (const sb of blocksToParse) {
    steps.push(classifyMicroStep(sb, helpers));
  }
  return steps;
}

function classifyMicroStep(sb, helpers) {
  const readOp = escapeRe(helpers.readOpFn);
  const readReg = escapeRe(helpers.readRegFn);
  const writeReg = escapeRe(helpers.writeRegFn);
  const getfenv = escapeRe(helpers.getfenvFn);

  // Strip trailing standard writeback epilogue (`if ...==1 then writeReg(...)` / `local v=tbl[idx+2];if v~=0`)
  let core = sb;
  const ep1 = core.search(/\bif\s+[A-Za-z_0-9]+\[[^\]]+\]\s*==\s*(?:0[xXbB])?0*1\s+then\b/);
  if (ep1 !== -1) core = core.slice(0, ep1);
  const ep2 = core.search(/\blocal\s+[A-Za-z_0-9]+\s*=\s*[A-Za-z_0-9]+\[[^\]]+\]\s*;?\s*if\s+[A-Za-z_0-9]+\s*~=\s*(?:0[xXbB])?0+\s+then\b/);
  if (ep2 !== -1) core = core.slice(0, ep2);

  const readOpRe = new RegExp(`\\b${readOp}\\([^)]*\\)`, 'g');
  const readRegRe = new RegExp(`=\\s*${readReg}\\(`);
  const writeRegImmRe = new RegExp(`\\b${writeReg}\\([^,]+,\\s*[A-Za-z_0-9]+\\[[^\\]]+\\]\\s*,`);
  const getGlobalCoreRe = new RegExp(`=\\s*${getfenv}\\([^)]*\\.fn\\)\\[`);

  if (/\.cellregs\[.+\]\s*=\s*true\b/.test(core)) {
    return 'NEWCELL';
  }

  // Check if core itself writes directly via writeRegFn(...) or .closure.b[...].v = ... or table[K] = ...
  if (writeRegImmRe.test(core)) {
    if (core.includes('.closure.b[')) return 'FUSED_GETUPVAL';
    if (getGlobalCoreRe.test(core)) return 'FUSED_GETGLOBAL';
    const fusedGetTblRe = new RegExp(
      `=\\s*${readReg}\\([^)]*\\)\\s*[A-Za-z_0-9]+\\s*=\\s*[A-Za-z_0-9]+\\[.+\\]\\s*[A-Za-z_0-9]+\\s*=\\s*[A-Za-z_0-9]+\\[[A-Za-z_0-9]+\\]\\s*${writeReg}\\(`
    );
    if (fusedGetTblRe.test(core)) return 'FUSED_GETTABLE_K';
    if (readRegRe.test(core)) {
      if (/=\s*-\s*[A-Za-z_0-9]+/.test(core)) return 'FUSED_UNM';
      if (/=\s*not\s+[A-Za-z_0-9]+/.test(core)) return 'FUSED_NOT';
      if (/=\s*#\s*[A-Za-z_0-9]+/.test(core)) return 'FUSED_LEN';
      return 'FUSED_MOVE';
    }
    if (readOpRe.test(core)) {
      readOpRe.lastIndex = 0;
      return 'FUSED_STORE_REG';
    }
    if (/~=\s*(?:0[xXbB])?0+\b/.test(core)) return 'FUSED_LOADBOOL';
    if (/=\s*\{\}/.test(core)) return 'FUSED_NEWTABLE';
    if (/\+\s*(?:0[xXbB])?0*1\s*\]/.test(core)) return 'FUSED_LOADK';
    return 'FUSED_LOADNIL';
  }
  if (/\.closure\.b\[.+\]\.v\s*=/.test(core)) {
    return 'FUSED_STORE_UPVAL';
  }
  readOpRe.lastIndex = 0;
  if (!readOpRe.test(core) && /\[[A-Za-z_0-9]+\]\s*=\s*[A-Za-z_0-9]+\b/.test(core)) {
    return 'FUSED_SETTABLE_K';
  }

  // Standard micro-op: find computation after the last `readOpFn(...)` call
  readOpRe.lastIndex = 0;
  const yMatches = [...core.matchAll(readOpRe)];
  const yCount = yMatches.length;
  if (core.includes('.fn)')) return 'GETGLOBAL';
  if (/=\s*\{\}/.test(core)) return 'NEWTABLE';

  const afterY = yCount > 0
    ? core.slice(yMatches[yCount - 1].index + yMatches[yCount - 1][0].length)
    : core;

  if (yCount === 3) return 'SETTABLE';
  if (yCount === 2) {
    const mOp = afterY.match(/=\s*([A-Za-z_0-9]+)\s*(\.\.|\/\/|==|~=|<=|>=|<|>|\+|-|\*|\/|%|\^)\s*([A-Za-z_0-9]+)/);
    if (mOp) {
      const opMap = {
        '~=': 'NEQ', '==': 'EQ', '<=': 'LE', '>=': 'GE', '<': 'LT', '>': 'GT',
        '..': 'CONCAT', '//': 'IDIV', '+': 'ADD', '-': 'SUB', '*': 'MUL', '/': 'DIV', '%': 'MOD', '^': 'POW'
      };
      return opMap[mOp[2]] || 'UNKNOWN_BINOP';
    }
    if (/=\s*[A-Za-z_0-9]+\[[A-Za-z_0-9]+\]/.test(afterY)) return 'GETTABLE';
  }
  if (yCount === 1) {
    if (/=\s*not\s+[A-Za-z_0-9]+/.test(afterY)) return 'NOT';
    if (/=\s*#\s*[A-Za-z_0-9]+/.test(afterY)) return 'LEN';
    if (/=\s*-\s*[A-Za-z_0-9]+/.test(afterY)) return 'UNM';
    return 'MOVE_Y';
  }
  if (readRegRe.test(core)) return 'MOVE_REG';
  return 'UNKNOWN_STEP';
}

module.exports = { extractSV3Dynamic, classifySV3Opcodes, discoverVMHelpers };
