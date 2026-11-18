# kilerobf

Dynamic **SnowVeil V3** Luau Deobfuscator & SVBG CFG Decompiler web workbench built with Next.js and Fengari.

## Features

- **Luau Compatibility Preprocessor** (`lib/engine/luau_compat.js`): Token-aware preprocessor converting Luau syntax (`0b`/`0x` literals, compound assignments `+=` / `..=`, generalized iteration, type annotations) into Lua 5.3.
- **Fengari Sandbox Unpacker** (`lib/engine/sandbox.js`): Emulates Luau/Roblox globals (`bit32`, `buffer`, `string.pack`, `table.freeze`, `Vector2/3`, `CFrame`, `UDim2`, `Color3`) and captures multi-stage `loadstring` / `load` payloads.
- **SnowVeil V3 Dynamic Extractor** (`lib/engine/sv3_extractor.js`): Extracts live protos, constants, CFG blocks, recipe schemas, and classifies micro-opcodes & terminals.
- **SVBG CFG Decompiler** (`lib/engine/sv3_decompiler.js`): Reconstructs control flow (dominators, loops, branches) and lifts IR back into readable Luau code.

## Local Development

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## API

- `POST /api/deobfuscate`
  - Body: `{ "source": "<obfuscated lua/luau>", "mode": "deobfuscate" | "unpack" }`
