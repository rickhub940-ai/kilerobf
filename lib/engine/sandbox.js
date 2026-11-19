const fengari = require('fengari');
const { lua, lauxlib, lualib, to_luastring, to_jsstring } = fengari;
const { preprocessLuau } = require('./luau_compat');

const LUAU_PREAMBLE = `
local _raw_type = type
local _raw_tostring = tostring
local _types = setmetatable({}, { __mode = "k" })
local _typeofs = setmetatable({}, { __mode = "k" })
local _frozen = setmetatable({}, { __mode = "k" })
local _fn_envs = setmetatable({}, { __mode = "k" })
__sv_types = _types
__sv_typeofs = _typeofs

function type(v)
  return _types[v] or _raw_type(v)
end

function typeof(v)
  return _typeofs[v] or _types[v] or _raw_type(v)
end

function tostring(v)
  if _raw_type(v) == "number" and v == v and v ~= math.huge and v ~= -math.huge and math.floor(v) == v and math.abs(v) < 9007199254740992 then
    return string.format("%.0f", v)
  end
  return _raw_tostring(v)
end

-- table extensions
function table.create(count, val)
  local t = {}
  if val ~= nil then
    for i = 1, count do t[i] = val end
  end
  return t
end
function table.clone(t)
  local r = {}
  for k, v in pairs(t) do r[k] = v end
  return r
end
function table.freeze(t)
  _frozen[t] = true
  return t
end
function table.isfrozen(t)
  return _frozen[t] == true
end
function table.clear(t)
  for k in pairs(t) do t[k] = nil end
end
table.pack = table.pack or function(...)
  return { n = select("#", ...), ... }
end
table.unpack = table.unpack or unpack
table.find = table.find or function(t, val, init)
  for i = (init or 1), #t do
    if t[i] == val then return i end
  end
  return nil
end
table.move = table.move or function(a1, f, e, t, a2)
  a2 = a2 or a1
  if t <= f or a2 ~= a1 then
    for i = 0, e - f do a2[t + i] = a1[f + i] end
  else
    for i = e - f, 0, -1 do a2[t + i] = a1[f + i] end
  end
  return a2
end

math.clamp = math.clamp or function(x, lo, hi)
  if x < lo then return lo elseif x > hi then return hi end
  return x
end
math.round = math.round or function(x)
  if x >= 0 then return math.floor(x + 0.5) else return math.ceil(x - 0.5) end
end
math.sign = math.sign or function(x)
  if x > 0 then return 1 elseif x < 0 then return -1 end
  return 0
end

string.split = string.split or function(s, sep)
  sep = sep or ","
  local res = {}
  if sep == "" then
    for i = 1, #s do res[i] = string.sub(s, i, i) end
    return res
  end
  local start = 1
  while true do
    local i, j = string.find(s, sep, start, true)
    if not i then
      res[#res + 1] = string.sub(s, start)
      break
    end
    res[#res + 1] = string.sub(s, start, i - 1)
    start = j + 1
  end
  return res
end

task = task or {
  wait = function() return 0 end,
  spawn = function(fn, ...) if _raw_type(fn) == "function" then return fn(...) end end,
  defer = function(fn, ...) if _raw_type(fn) == "function" then return fn(...) end end,
  delay = function(_, fn, ...) if _raw_type(fn) == "function" then return fn(...) end end,
}
tick = tick or function() return os.clock() end
wait = wait or function() return 0 end

-- getfenv / setfenv for Lua 5.3
local _G_ref = _G
function getfenv(fn)
  if fn == nil or fn == 0 then return _G_ref end
  if _raw_type(fn) == "number" then
    local info = debug.getinfo(fn + 1, "f")
    if info and info.func then fn = info.func else return _G_ref end
  end
  if _fn_envs[fn] then return _fn_envs[fn] end
  local i = 1
  while true do
    local name, val = debug.getupvalue(fn, i)
    if not name then break end
    if name == "_ENV" then return val end
    i = i + 1
  end
  return _G_ref
end
function setfenv(fn, env)
  if _raw_type(fn) == "number" then
    if fn == 0 then return _G_ref end
    local info = debug.getinfo(fn + 1, "f")
    if info and info.func then fn = info.func else return fn end
  end
  _fn_envs[fn] = env
  local i = 1
  while true do
    local name = debug.getupvalue(fn, i)
    if not name then break end
    if name == "_ENV" then
      debug.setupvalue(fn, i, env)
      break
    end
    i = i + 1
  end
  return fn
end

local _raw_debug_getinfo = debug.getinfo
debug.info = function(a, b)
  if _raw_type(a) == "number" then a = a + 1 end
  local info = _raw_debug_getinfo(a, "fnSl")
  if not info then return nil end
  if b == "f" then return info.func end
  if b == "s" then return info.short_src end
  if b == "n" then return info.name end
  if b == "l" then return info.currentline end
  return info.func
end

function __luau_iter(v, ...)
  if _raw_type(v) == "table" then
    local mt = getmetatable(v)
    if mt then
      if mt.__iter then return mt.__iter(v) end
      if mt.__call then return v, ... end
    end
    local n = #v
    local i = 0
    local k = nil
    local in_hash = false
    return function()
      if not in_hash then
        i = i + 1
        if i <= n and v[i] ~= nil then
          return i, v[i]
        end
        in_hash = true
      end
      while true do
        local val
        k, val = next(v, k)
        if k == nil then return nil end
        if not (_raw_type(k) == "number" and k >= 1 and k <= n and math.floor(k) == k) then
          return k, val
        end
      end
    end
  end
  return v, ...
end

-- Roblox Math & UI Types
Vector2 = {}
local Vector2_mt
local function make_v2(x, y)
  local mag = math.sqrt(x*x + y*y)
  local v = { X = x or 0, Y = y or 0, x = x or 0, y = y or 0, Magnitude = mag }
  if mag > 0 then
    local u = { X = x / mag, Y = y / mag, x = x / mag, y = y / mag, Magnitude = 1 }
    u.Unit = u
    setmetatable(u, Vector2_mt)
    _types[u] = "userdata"
    _typeofs[u] = "Vector2"
    v.Unit = u
  else
    v.Unit = v
  end
  setmetatable(v, Vector2_mt)
  _types[v] = "userdata"
  _typeofs[v] = "Vector2"
  return v
end
local Vector2_methods = {
  Dot = function(self, o) return self.X * o.X + self.Y * o.Y end,
  Cross = function(self, o) return self.X * o.Y - self.Y * o.X end,
  Lerp = function(self, o, a) return make_v2(self.X + (o.X - self.X) * a, self.Y + (o.Y - self.Y) * a) end,
}
Vector2_mt = {
  __index = Vector2_methods,
  __add = function(a, b) return make_v2(a.X + b.X, a.Y + b.Y) end,
  __sub = function(a, b) return make_v2(a.X - b.X, a.Y - b.Y) end,
  __mul = function(a, b)
    if _raw_type(a) == "number" then return make_v2(a * b.X, a * b.Y) end
    if _raw_type(b) == "number" then return make_v2(a.X * b, a.Y * b) end
    return make_v2(a.X * b.X, a.Y * b.Y)
  end,
  __eq = function(a, b) return a.X == b.X and a.Y == b.Y end,
}
function Vector2.new(x, y)
  return make_v2((x or 0) + 0.0, (y or 0) + 0.0)
end

Color3 = {}
function Color3.new(r, g, b)
  local c = { R = r or 0, G = g or 0, B = b or 0 }
  _types[c] = "userdata"
  _typeofs[c] = "Color3"
  return c
end
function Color3.fromRGB(r, g, b) return Color3.new((r or 0)/255, (g or 0)/255, (b or 0)/255) end

Vector3 = {}
local Vector3_mt
local function make_v3(x, y, z)
  local mag = math.sqrt(x*x + y*y + z*z)
  local v = { X = x, Y = y, Z = z, x = x, y = y, z = z, Magnitude = mag }
  if mag > 0 then
    local ux, uy, uz = x / mag, y / mag, z / mag
    local u = { X = ux, Y = uy, Z = uz, x = ux, y = uy, z = uz, Magnitude = 1 }
    u.Unit = u
    setmetatable(u, Vector3_mt)
    _types[u] = "userdata"
    _typeofs[u] = "Vector3"
    v.Unit = u
  else
    v.Unit = v
  end
  setmetatable(v, Vector3_mt)
  _types[v] = "userdata"
  _typeofs[v] = "Vector3"
  return v
end
local Vector3_methods = {
  Dot = function(self, o) return self.X * o.X + self.Y * o.Y + self.Z * o.Z end,
  Cross = function(self, o)
    return make_v3(
      self.Y * o.Z - self.Z * o.Y,
      self.Z * o.X - self.X * o.Z,
      self.X * o.Y - self.Y * o.X
    )
  end,
  Lerp = function(self, o, alpha)
    return make_v3(
      self.X + (o.X - self.X) * alpha,
      self.Y + (o.Y - self.Y) * alpha,
      self.Z + (o.Z - self.Z) * alpha
    )
  end
}
Vector3_mt = {
  __index = Vector3_methods,
  __add = function(a, b) return make_v3(a.X + b.X, a.Y + b.Y, a.Z + b.Z) end,
  __sub = function(a, b) return make_v3(a.X - b.X, a.Y - b.Y, a.Z - b.Z) end,
  __mul = function(a, b)
    if _raw_type(a) == "number" then return make_v3(a * b.X, a * b.Y, a * b.Z) end
    if _raw_type(b) == "number" then return make_v3(a.X * b, a.Y * b, a.Z * b) end
    return make_v3(a.X * b.X, a.Y * b.Y, a.Z * b.Z)
  end,
  __eq = function(a, b) return a.X == b.X and a.Y == b.Y and a.Z == b.Z end
}
function Vector3.new(x, y, z)
  return make_v3((x or 0) + 0.0, (y or 0) + 0.0, (z or 0) + 0.0)
end

CFrame = {}
local CFrame_mt
local function make_cf(px, py, pz, r00, r01, r02, r10, r11, r12, r20, r21, r22)
  local cf = {
    X = px, Y = py, Z = pz,
    Position = make_v3(px, py, pz),
    RightVector = make_v3(r00, r10, r20),
    UpVector = make_v3(r01, r11, r21),
    LookVector = make_v3(-r02, -r12, -r22),
    _m = { px, py, pz, r00, r01, r02, r10, r11, r12, r20, r21, r22 }
  }
  setmetatable(cf, CFrame_mt)
  _types[cf] = "userdata"
  _typeofs[cf] = "CFrame"
  return cf
end
CFrame_mt = {
  __mul = function(a, b)
    local m = a._m
    if _typeofs[b] == "Vector3" then
      return make_v3(
        m[1] + m[4]*b.X + m[5]*b.Y + m[6]*b.Z,
        m[2] + m[7]*b.X + m[8]*b.Y + m[9]*b.Z,
        m[3] + m[10]*b.X + m[11]*b.Y + m[12]*b.Z
      )
    end
    local n = b._m
    local function dot(r, c)
      return m[3 + r*3 + 1]*n[3 + c] + m[3 + r*3 + 2]*n[6 + c] + m[3 + r*3 + 3]*n[9 + c]
    end
    return make_cf(
      m[1] + m[4]*n[1] + m[5]*n[2] + m[6]*n[3],
      m[2] + m[7]*n[1] + m[8]*n[2] + m[9]*n[3],
      m[3] + m[10]*n[1] + m[11]*n[2] + m[12]*n[3],
      dot(0,1), dot(0,2), dot(0,3),
      dot(1,1), dot(1,2), dot(1,3),
      dot(2,1), dot(2,2), dot(2,3)
    )
  end
}
function CFrame.fromEulerAnglesXYZ(rx, ry, rz)
  local cx, sx = math.cos(rx), math.sin(rx)
  local cy, sy = math.cos(ry), math.sin(ry)
  local cz, sz = math.cos(rz), math.sin(rz)
  return make_cf(
    0, 0, 0,
    cy*cz, -cy*sz, sy,
    cx*sz + cz*sx*sy, cx*cz - sx*sy*sz, -cy*sx,
    sx*sz - cx*cz*sy, cz*sx + cx*sy*sz, cx*cy
  )
end
CFrame.Angles = CFrame.fromEulerAnglesXYZ
function CFrame.new(x, y, z)
  return make_cf(x or 0, y or 0, z or 0, 1,0,0, 0,1,0, 0,0,1)
end

UDim = {}
function UDim.new(s, o)
  local u = { Scale = s or 0, Offset = o or 0 }
  _types[u] = "userdata"
  _typeofs[u] = "UDim"
  return u
end

UDim2 = {}
function UDim2.new(xs, xo, ys, yo)
  local u = { X = UDim.new(xs, xo), Y = UDim.new(ys, yo) }
  _types[u] = "userdata"
  _typeofs[u] = "UDim2"
  return u
end
function UDim2.fromOffset(xo, yo)
  return UDim2.new(0, xo, 0, yo)
end
function UDim2.fromScale(xs, ys)
  return UDim2.new(xs, 0, ys, 0)
end

Path2DControlPoint = {}
function Path2DControlPoint.new(pos, lt, rt)
  local cp = {
    Position = pos or UDim2.new(0,0,0,0),
    LeftTangent = lt or UDim2.new(0,0,0,0),
    RightTangent = rt or UDim2.new(0,0,0,0)
  }
  _types[cp] = "userdata"
  _typeofs[cp] = "Path2DControlPoint"
  return cp
end

Instance = {}
local function make_instance(cls)
  local obj = { ClassName = cls, _pts = {}, _children = {} }
  _types[obj] = "userdata"
  _typeofs[obj] = "Instance"
  function obj:IsA(c)
    if c == cls or c == "Instance" then return true end
    return false
  end
  function obj:Destroy() end
  if cls == "Path2D" then
    local function get_parent_size()
      local p = obj.Parent
      if p and p.Size then
        return p.Size.X.Offset, p.Size.Y.Offset
      end
      return 256, 256
    end
    local function cp_xy(cp, pw, ph)
      return cp.Position.X.Scale * pw + cp.Position.X.Offset,
             cp.Position.Y.Scale * ph + cp.Position.Y.Offset
    end
    local function lt_xy(cp, pw, ph)
      return cp.LeftTangent.X.Scale * pw + cp.LeftTangent.X.Offset,
             cp.LeftTangent.Y.Scale * ph + cp.LeftTangent.Y.Offset
    end
    local function rt_xy(cp, pw, ph)
      return cp.RightTangent.X.Scale * pw + cp.RightTangent.X.Offset,
             cp.RightTangent.Y.Scale * ph + cp.RightTangent.Y.Offset
    end
    function obj:SetControlPoints(pts)
      obj._pts = pts or {}
    end
    function obj:GetPositionOnCurve(t)
      local pts = obj._pts
      if #pts < 2 then return UDim2.new(0,0,0,0) end
      local pw, ph = get_parent_size()
      local p0, p1 = pts[1], pts[2]
      local b0x, b0y = cp_xy(p0, pw, ph)
      local b3x, b3y = cp_xy(p1, pw, ph)
      local rtx, rty = rt_xy(p0, pw, ph)
      local ltx, lty = lt_xy(p1, pw, ph)
      local b1x, b1y = b0x + rtx, b0y + rty
      local b2x, b2y = b3x + ltx, b3y + lty
      local u = 1 - t
      local x = u*u*u*b0x + 3*u*u*t*b1x + 3*u*t*t*b2x + t*t*t*b3x
      local y = u*u*u*b0y + 3*u*u*t*b1y + 3*u*t*t*b2y + t*t*t*b3y
      return UDim2.new(x / pw, 0, y / ph, 0)
    end
    function obj:GetTangentOnCurve(t)
      local pts = obj._pts
      if #pts < 2 then return make_v2(1, 0) end
      local pw, ph = get_parent_size()
      local p0, p1 = pts[1], pts[2]
      local b0x, b0y = cp_xy(p0, pw, ph)
      local b3x, b3y = cp_xy(p1, pw, ph)
      local rtx, rty = rt_xy(p0, pw, ph)
      local ltx, lty = lt_xy(p1, pw, ph)
      local b1x, b1y = b0x + rtx, b0y + rty
      local b2x, b2y = b3x + ltx, b3y + lty
      local u = 1 - t
      local dx = 3*u*u*(b1x - b0x) + 6*u*t*(b2x - b1x) + 3*t*t*(b3x - b2x)
      local dy = 3*u*u*(b1y - b0y) + 6*u*t*(b2y - b1y) + 3*t*t*(b3y - b2y)
      local mag = math.sqrt(dx*dx + dy*dy)
      if mag == 0 then return make_v2(1, 0) end
      return make_v2(dx / mag, dy / mag)
    end
    function obj:GetLength()
      return 100
    end
  end
  return obj
end
function Instance.new(cls)
  return make_instance(cls)
end

game = make_instance("DataModel")
workspace = make_instance("Workspace")
`;

function registerBit32(L) {
  const u32 = (L2, idx) => (Math.floor(lua.lua_tonumber(L2, idx)) >>> 0);
  const i32 = (L2, idx) => Math.trunc(lua.lua_tonumber(L2, idx));

  lua.lua_newtable(L);
  const methods = {
    band: (L2) => {
      const n = lua.lua_gettop(L2);
      let r = 0xFFFFFFFF >>> 0;
      for (let i = 1; i <= n; i++) r = (r & u32(L2, i)) >>> 0;
      lua.lua_pushnumber(L2, r);
      return 1;
    },
    bor: (L2) => {
      const n = lua.lua_gettop(L2);
      let r = 0;
      for (let i = 1; i <= n; i++) r = (r | u32(L2, i)) >>> 0;
      lua.lua_pushnumber(L2, r);
      return 1;
    },
    bxor: (L2) => {
      const n = lua.lua_gettop(L2);
      let r = 0;
      for (let i = 1; i <= n; i++) r = (r ^ u32(L2, i)) >>> 0;
      lua.lua_pushnumber(L2, r);
      return 1;
    },
    bnot: (L2) => { lua.lua_pushnumber(L2, (~u32(L2, 1)) >>> 0); return 1; },
    btest: (L2) => {
      const n = lua.lua_gettop(L2);
      let r = 0xFFFFFFFF >>> 0;
      for (let i = 1; i <= n; i++) r = (r & u32(L2, i)) >>> 0;
      lua.lua_pushboolean(L2, r !== 0);
      return 1;
    },
    lshift: (L2) => {
      const x = u32(L2, 1), disp = i32(L2, 2);
      let r = 0;
      if (disp >= 0 && disp < 32) r = (x << disp) >>> 0;
      else if (disp < 0 && disp > -32) r = (x >>> -disp) >>> 0;
      lua.lua_pushnumber(L2, r);
      return 1;
    },
    rshift: (L2) => {
      const x = u32(L2, 1), disp = i32(L2, 2);
      let r = 0;
      if (disp >= 0 && disp < 32) r = (x >>> disp) >>> 0;
      else if (disp < 0 && disp > -32) r = (x << -disp) >>> 0;
      lua.lua_pushnumber(L2, r);
      return 1;
    },
    arshift: (L2) => {
      const x = u32(L2, 1), disp = i32(L2, 2);
      let r;
      if (disp < 0) r = disp > -32 ? ((x << -disp) >>> 0) : 0;
      else if (disp >= 32) r = (x & 0x80000000) ? 0xFFFFFFFF : 0;
      else r = ((x | 0) >> disp) >>> 0;
      lua.lua_pushnumber(L2, r);
      return 1;
    },
    lrotate: (L2) => {
      const x = u32(L2, 1);
      const disp = ((i32(L2, 2) % 32) + 32) % 32;
      lua.lua_pushnumber(L2, disp === 0 ? x : (((x << disp) | (x >>> (32 - disp))) >>> 0));
      return 1;
    },
    rrotate: (L2) => {
      const x = u32(L2, 1);
      const disp = ((i32(L2, 2) % 32) + 32) % 32;
      lua.lua_pushnumber(L2, disp === 0 ? x : (((x >>> disp) | (x << (32 - disp))) >>> 0));
      return 1;
    },
    extract: (L2) => {
      const n = u32(L2, 1), f = i32(L2, 2), w = lua.lua_gettop(L2) >= 3 ? i32(L2, 3) : 1;
      const mask = w >= 32 ? 0xFFFFFFFF : ((1 << w) - 1);
      lua.lua_pushnumber(L2, ((n >>> f) & mask) >>> 0);
      return 1;
    },
    replace: (L2) => {
      const n = u32(L2, 1), v = u32(L2, 2), f = i32(L2, 3), w = lua.lua_gettop(L2) >= 4 ? i32(L2, 4) : 1;
      const mask = (w >= 32 ? 0xFFFFFFFF : ((1 << w) - 1)) << f;
      lua.lua_pushnumber(L2, ((n & ~mask) | ((v << f) & mask)) >>> 0);
      return 1;
    },
    countlz: (L2) => {
      const x = u32(L2, 1);
      lua.lua_pushnumber(L2, x === 0 ? 32 : Math.clz32(x));
      return 1;
    },
    countrz: (L2) => {
      const x = u32(L2, 1);
      if (x === 0) { lua.lua_pushnumber(L2, 32); return 1; }
      let c = 0, v = x;
      while ((v & 1) === 0) { v >>>= 1; c++; }
      lua.lua_pushnumber(L2, c);
      return 1;
    },
    byteswap: (L2) => {
      const x = u32(L2, 1);
      const r = (((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x >>> 8) & 0xFF00) | ((x >>> 24) & 0xFF)) >>> 0;
      lua.lua_pushnumber(L2, r);
      return 1;
    },
  };
  for (const [k, fn] of Object.entries(methods)) {
    lua.lua_pushjsfunction(L, fn);
    lua.lua_setfield(L, -2, to_luastring(k));
  }
  lua.lua_setglobal(L, to_luastring('bit32'));
}

function registerBuffer(L) {
  const bufs = new Map();
  let nextId = 1;

  function makeBufObj(L2, u8) {
    const id = nextId++;
    bufs.set(id, { u8, dv: new DataView(u8.buffer, u8.byteOffset, u8.byteLength) });
    lua.lua_newtable(L2);
    lua.lua_pushinteger(L2, id);
    lua.lua_setfield(L2, -2, to_luastring('_id'));
    // tag in __sv_types and __sv_typeofs
    lua.lua_getglobal(L2, to_luastring('__sv_types'));
    lua.lua_pushvalue(L2, -2);
    lua.lua_pushstring(L2, to_luastring('buffer'));
    lua.lua_settable(L2, -3);
    lua.lua_pop(L2, 1);

    lua.lua_getglobal(L2, to_luastring('__sv_typeofs'));
    lua.lua_pushvalue(L2, -2);
    lua.lua_pushstring(L2, to_luastring('buffer'));
    lua.lua_settable(L2, -3);
    lua.lua_pop(L2, 1);
    return 1;
  }

  function getBuf(L2, idx) {
    lua.lua_getfield(L2, idx, to_luastring('_id'));
    const id = lua.lua_tointeger(L2, -1);
    lua.lua_pop(L2, 1);
    return bufs.get(id);
  }

  lua.lua_newtable(L);
  const methods = {
    create: (L2) => {
      const sz = Math.trunc(lua.lua_tonumber(L2, 1));
      return makeBufObj(L2, new Uint8Array(sz));
    },
    fromstring: (L2) => {
      const raw = lua.lua_tostring(L2, 1);
      return makeBufObj(L2, new Uint8Array(raw));
    },
    tostring: (L2) => {
      const b = getBuf(L2, 1);
      lua.lua_pushlstring(L2, b.u8, b.u8.length);
      return 1;
    },
    len: (L2) => {
      const b = getBuf(L2, 1);
      lua.lua_pushnumber(L2, b.u8.length);
      return 1;
    },
    readu8: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2));
      lua.lua_pushnumber(L2, b.u8[off]);
      return 1;
    },
    readu16: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2));
      lua.lua_pushnumber(L2, b.dv.getUint16(off, true));
      return 1;
    },
    readu32: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2));
      lua.lua_pushnumber(L2, b.dv.getUint32(off, true) >>> 0);
      return 1;
    },
    readi8: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2));
      lua.lua_pushnumber(L2, b.dv.getInt8(off));
      return 1;
    },
    readi16: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2));
      lua.lua_pushnumber(L2, b.dv.getInt16(off, true));
      return 1;
    },
    readi32: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2));
      lua.lua_pushnumber(L2, b.dv.getInt32(off, true));
      return 1;
    },
    writeu8: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2)), v = Math.floor(lua.lua_tonumber(L2, 3));
      b.u8[off] = v & 0xFF;
      return 0;
    },
    writeu16: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2)), v = Math.floor(lua.lua_tonumber(L2, 3));
      b.dv.setUint16(off, v & 0xFFFF, true);
      return 0;
    },
    writeu32: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2)), v = Math.floor(lua.lua_tonumber(L2, 3)) >>> 0;
      b.dv.setUint32(off, v, true);
      return 0;
    },
    readf32: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2));
      lua.lua_pushnumber(L2, b.dv.getFloat32(off, true));
      return 1;
    },
    readf64: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2));
      lua.lua_pushnumber(L2, b.dv.getFloat64(off, true));
      return 1;
    },
    writef32: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2)), v = lua.lua_tonumber(L2, 3);
      b.dv.setFloat32(off, v, true);
      return 0;
    },
    writef64: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2)), v = lua.lua_tonumber(L2, 3);
      b.dv.setFloat64(off, v, true);
      return 0;
    },
    readstring: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2)), len = Math.trunc(lua.lua_tonumber(L2, 3));
      const sl = b.u8.subarray(off, off + len);
      lua.lua_pushlstring(L2, sl, sl.length);
      return 1;
    },
    writestring: (L2) => {
      const b = getBuf(L2, 1), off = Math.trunc(lua.lua_tonumber(L2, 2)), raw = lua.lua_tostring(L2, 3);
      const cnt = lua.lua_gettop(L2) >= 4 && !lua.lua_isnil(L2, 4) ? Math.trunc(lua.lua_tonumber(L2, 4)) : raw.length;
      b.u8.set(new Uint8Array(raw).subarray(0, cnt), off);
      return 0;
    },
    copy: (L2) => {
      const dst = getBuf(L2, 1);
      const dstOff = Math.trunc(lua.lua_tonumber(L2, 2));
      const src = getBuf(L2, 3);
      const srcOff = lua.lua_gettop(L2) >= 4 && !lua.lua_isnil(L2, 4) ? Math.trunc(lua.lua_tonumber(L2, 4)) : 0;
      const count = lua.lua_gettop(L2) >= 5 && !lua.lua_isnil(L2, 5) ? Math.trunc(lua.lua_tonumber(L2, 5)) : (src.u8.length - srcOff);
      dst.u8.set(src.u8.subarray(srcOff, srcOff + count), dstOff);
      return 0;
    },
    fill: (L2) => {
      const b = getBuf(L2, 1);
      const off = Math.trunc(lua.lua_tonumber(L2, 2));
      const val = Math.floor(lua.lua_tonumber(L2, 3)) & 0xFF;
      const count = lua.lua_gettop(L2) >= 4 && !lua.lua_isnil(L2, 4) ? Math.trunc(lua.lua_tonumber(L2, 4)) : (b.u8.length - off);
      b.u8.fill(val, off, off + count);
      return 0;
    },
  };
  for (const [k, fn] of Object.entries(methods)) {
    lua.lua_pushjsfunction(L, fn);
    lua.lua_setfield(L, -2, to_luastring(k));
  }
  lua.lua_setglobal(L, to_luastring('buffer'));
}

function registerStringPack(L) {
  function parseFmt(fmt) {
    const ops = [];
    let le = true;
    let i = 0;
    while (i < fmt.length) {
      const ch = fmt[i++];
      if (ch === ' ' || ch === '\t') continue;
      if (ch === '<') { le = true; continue; }
      if (ch === '>' || ch === '=') { le = ch === '=' ? true : false; continue; }
      if (ch === '!') {
        while (i < fmt.length && /\d/.test(fmt[i])) i++;
        continue;
      }
      if (ch === 'x') { ops.push({ op: 'x', size: 1, le }); continue; }
      if (ch === 'b' || ch === 'B') { ops.push({ op: ch, size: 1, le }); continue; }
      if (ch === 'h' || ch === 'H') { ops.push({ op: ch, size: 2, le }); continue; }
      if (ch === 'l' || ch === 'L') { ops.push({ op: ch, size: 8, le }); continue; }
      if (ch === 'j' || ch === 'J' || ch === 'T') { ops.push({ op: ch, size: 8, le }); continue; }
      if (ch === 'i' || ch === 'I') {
        let num = '';
        while (i < fmt.length && /\d/.test(fmt[i])) num += fmt[i++];
        const sz = num ? parseInt(num, 10) : 4;
        ops.push({ op: ch, size: sz, le });
        continue;
      }
      if (ch === 'f') { ops.push({ op: 'f', size: 4, le }); continue; }
      if (ch === 'd' || ch === 'n') { ops.push({ op: 'd', size: 8, le }); continue; }
      if (ch === 'z') { ops.push({ op: 'z', le }); continue; }
      if (ch === 'c') {
        let num = '';
        while (i < fmt.length && /\d/.test(fmt[i])) num += fmt[i++];
        ops.push({ op: 'c', size: num ? parseInt(num, 10) : 0, le });
        continue;
      }
      if (ch === 's') {
        let num = '';
        while (i < fmt.length && /\d/.test(fmt[i])) num += fmt[i++];
        ops.push({ op: 's', size: num ? parseInt(num, 10) : 8, le });
        continue;
      }
      throw new Error('Unsupported string.pack format char: ' + ch);
    }
    return ops;
  }

  function writeIntBytes(out, valNum, size, signed, le) {
    let v = BigInt(Math.trunc(valNum));
    if (signed && v < 0n) v = (1n << BigInt(size * 8)) + v;
    const bytes = new Array(size);
    for (let k = 0; k < size; k++) {
      bytes[le ? k : size - 1 - k] = Number(v & 0xFFn);
      v >>= 8n;
    }
    for (const b of bytes) out.push(b);
  }

  function readIntBytes(u8, pos, size, signed, le) {
    let v = 0n;
    for (let k = 0; k < size; k++) {
      const b = BigInt(u8[pos + (le ? k : size - 1 - k)]);
      v |= b << BigInt(k * 8);
    }
    if (signed) {
      const signBit = 1n << BigInt(size * 8 - 1);
      if (v & signBit) v -= (1n << BigInt(size * 8));
    }
    return Number(v);
  }

  lua.lua_getglobal(L, to_luastring('string'));

  lua.lua_pushjsfunction(L, (L2) => {
    const fmt = to_jsstring(lua.lua_tostring(L2, 1));
    const ops = parseFmt(fmt);
    const out = [];
    let argIdx = 2;
    const scratch = new ArrayBuffer(8);
    const dv = new DataView(scratch);
    const u8s = new Uint8Array(scratch);

    for (const item of ops) {
      const { op, size, le } = item;
      if (op === 'x') { out.push(0); continue; }
      if (op === 'b' || op === 'B') {
        const v = lua.lua_tonumber(L2, argIdx++);
        out.push(Math.trunc(v) & 0xFF);
      } else if (op === 'h' || op === 'H') {
        writeIntBytes(out, lua.lua_tonumber(L2, argIdx++), 2, op === 'h', le);
      } else if (op === 'i' || op === 'I' || op === 'l' || op === 'L' || op === 'j' || op === 'J' || op === 'T') {
        const signed = op === 'i' || op === 'l' || op === 'j';
        writeIntBytes(out, lua.lua_tonumber(L2, argIdx++), size, signed, le);
      } else if (op === 'f') {
        dv.setFloat32(0, lua.lua_tonumber(L2, argIdx++), le);
        for (let k = 0; k < 4; k++) out.push(u8s[k]);
      } else if (op === 'd') {
        dv.setFloat64(0, lua.lua_tonumber(L2, argIdx++), le);
        for (let k = 0; k < 8; k++) out.push(u8s[k]);
      } else if (op === 'c') {
        const raw = lua.lua_tostring(L2, argIdx++);
        for (let k = 0; k < size; k++) out.push(k < raw.length ? raw[k] : 0);
      } else if (op === 'z') {
        const raw = lua.lua_tostring(L2, argIdx++);
        for (let k = 0; k < raw.length; k++) out.push(raw[k]);
        out.push(0);
      } else if (op === 's') {
        const raw = lua.lua_tostring(L2, argIdx++);
        writeIntBytes(out, raw.length, size, false, le);
        for (let k = 0; k < raw.length; k++) out.push(raw[k]);
      }
    }
    const res = new Uint8Array(out);
    lua.lua_pushlstring(L2, res, res.length);
    return 1;
  });
  lua.lua_setfield(L, -2, to_luastring('pack'));

  lua.lua_pushjsfunction(L, (L2) => {
    const fmt = to_jsstring(lua.lua_tostring(L2, 1));
    const u8 = new Uint8Array(lua.lua_tostring(L2, 2));
    let pos = lua.lua_gettop(L2) >= 3 && !lua.lua_isnil(L2, 3) ? Math.trunc(lua.lua_tonumber(L2, 3)) : 1;
    if (pos < 0) pos = u8.length + pos + 1;
    pos = pos - 1; // 0-based
    const ops = parseFmt(fmt);
    let nret = 0;
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);

    for (const item of ops) {
      const { op, size, le } = item;
      if (op === 'x') { pos += 1; continue; }
      if (op === 'b') { lua.lua_pushnumber(L2, dv.getInt8(pos)); pos += 1; nret++; }
      else if (op === 'B') { lua.lua_pushnumber(L2, u8[pos]); pos += 1; nret++; }
      else if (op === 'h' || op === 'H') { lua.lua_pushnumber(L2, readIntBytes(u8, pos, 2, op === 'h', le)); pos += 2; nret++; }
      else if (op === 'i' || op === 'I' || op === 'l' || op === 'L' || op === 'j' || op === 'J' || op === 'T') {
        const signed = op === 'i' || op === 'l' || op === 'j';
        lua.lua_pushnumber(L2, readIntBytes(u8, pos, size, signed, le));
        pos += size; nret++;
      } else if (op === 'f') { lua.lua_pushnumber(L2, dv.getFloat32(pos, le)); pos += 4; nret++; }
      else if (op === 'd') { lua.lua_pushnumber(L2, dv.getFloat64(pos, le)); pos += 8; nret++; }
      else if (op === 'c') {
        const sl = u8.subarray(pos, pos + size);
        lua.lua_pushlstring(L2, sl, sl.length);
        pos += size; nret++;
      } else if (op === 'z') {
        let end = pos;
        while (end < u8.length && u8[end] !== 0) end++;
        const sl = u8.subarray(pos, end);
        lua.lua_pushlstring(L2, sl, sl.length);
        pos = end + 1; nret++;
      } else if (op === 's') {
        const len = readIntBytes(u8, pos, size, false, le);
        pos += size;
        const sl = u8.subarray(pos, pos + len);
        lua.lua_pushlstring(L2, sl, sl.length);
        pos += len; nret++;
      }
    }
    lua.lua_pushnumber(L2, pos + 1);
    return nret + 1;
  });
  lua.lua_setfield(L, -2, to_luastring('unpack'));

  lua.lua_pop(L, 1);
}

function setupVM(L, capturedLoads, dumpBox) {
  lualib.luaL_openlibs(L);
  registerBit32(L);
  registerStringPack(L);

  lua.lua_pushjsfunction(L, (L2) => {
    const raw = lua.lua_tostring(L2, 1);
    capturedLoads.push(to_jsstring(raw));
    return 0;
  });
  lua.lua_setglobal(L, to_luastring('__js_capture_load'));

  lua.lua_pushjsfunction(L, (L2) => {
    const raw = lua.lua_tostring(L2, 1);
    dumpBox.result = to_jsstring(raw);
    return 0;
  });
  lua.lua_setglobal(L, to_luastring('__js_capture_dump'));

  const loaderShim = `
${LUAU_PREAMBLE}
local _orig_load = load
function loadstring(s, chunkname)
  __js_capture_load(s)
  if _raw_type(s) == "string" and #s < 512 and _orig_load then
    local fn = _orig_load(s, chunkname)
    if fn then return fn end
  end
  return function() error("__SNOWVEIL_CAPTURED__", 0) end
end
load = loadstring
`;
  const st = lauxlib.luaL_dostring(L, to_luastring(loaderShim));
  if (st !== lua.LUA_OK) {
    throw new Error('Preamble error: ' + to_jsstring(lua.lua_tostring(L, -1)));
  }
  registerBuffer(L);
}

function runInSandbox(code) {
  const L = lauxlib.luaL_newstate();
  const capturedLoads = [];
  const dumpBox = { result: null };
  setupVM(L, capturedLoads, dumpBox);

  const processed = preprocessLuau(code);
  const status = lauxlib.luaL_dostring(L, to_luastring(processed));
  if (status !== lua.LUA_OK) {
    const rawErr = lua.lua_tostring(L, -1);
    const err = rawErr ? to_jsstring(rawErr) : '(nil error)';
    if (!err.includes('__SNOWVEIL_CAPTURED__') && capturedLoads.length === 0 && !dumpBox.result) {
      throw new Error('Lua runtime error: ' + err);
    }
  }

  return { capturedLoads, dumpResult: dumpBox.result };
}

module.exports = { runInSandbox, setupVM, registerBit32, registerBuffer, LUAU_PREAMBLE };
