const { runInSandbox } = require('./sandbox');
const { extractSV2Dynamic } = require('./sv2_extractor');
const { decompileSV2 } = require('./sv2_decompiler');
const { extractSV3Dynamic } = require('./sv3_extractor');
const { decompileSV3 } = require('./sv3_decompiler');

function isSV2VM(src) {
  return (
    /\.proto\b/.test(src) &&
    /\.entry\b/.test(src) &&
    (/liveState\b/.test(src) || /\.arena\b/.test(src) || /\.offsets\b/.test(src))
  );
}

function isSV3VM(src) {
  return (
    /\.entry\b/.test(src) &&
    !isSV2VM(src) &&
    ((/\.blocks\b/.test(src) && /\.selectors\b/.test(src)) ||
      (/\.proto\b/.test(src) && /\.closure\b/.test(src)))
  );
}

function detectSnowVeilVersion(source) {
  if (/SnowVeil\s+V3/.test(source) || isSV3VM(source)) return 'V3';
  if (/SnowVeil\s+v?2/.test(source) || isSV2VM(source)) return 'v2.0';
  return 'unknown';
}

function deobfuscateSnowVeil(source) {
  const t0 = Date.now();
  const stages = [];
  let current = source.replace(/^\uFEFF/, '');
  let detectedVersion = detectSnowVeilVersion(current);

  // Stage unpacking loop (max 6 stages)
  for (let s = 1; s <= 6; s++) {
    // Check if current source is V3 Stage 3 VM (invariant: .entry + .blocks/.selectors, no liveState/.arena/.offsets)
    if (isSV3VM(current)) {
      detectedVersion = 'V3';
      stages.push({ stage: s, type: 'V3 Stage 3 (SVBG CFG VM)', bytes: current.length });
      const ext = extractSV3Dynamic(current);
      const output = decompileSV3(ext);
      return {
        ok: true,
        version: 'SnowVeil V3',
        elapsedMs: Date.now() - t0,
        stages,
        stats: {
          protos: ext.protos.length,
          blocks: ext.protos.reduce((a, p) => a + p.blocks.length, 0),
          constants: ext.protos.reduce((a, p) => a + p.consts.length, 0),
          recipes: Object.keys(ext.recipes || {}).length,
          terminals: Object.keys(ext.terminals || {}).length,
          opcodesDecoded: Object.keys(ext.opSemantics).length
        },
        output
      };
    }

    // Check if current source is v2.0 Stage 2 / SSA CFG VM (invariant: .proto + .entry + liveState/.arena/.offsets)
    if (isSV2VM(current)) {
      detectedVersion = 'v2.0';
      stages.push({ stage: s, type: 'SSA CFG VM (liveState)', bytes: current.length });
      const ext = extractSV2Dynamic(current);
      const output = decompileSV2(ext);
      return {
        ok: true,
        version: 'SnowVeil SSA CFG',
        elapsedMs: Date.now() - t0,
        stages,
        stats: {
          protos: ext.protos.length,
          blocks: ext.protos.reduce((a, p) => a + (p.nodes || p.blocks || []).length, 0),
          constants: ext.protos.reduce((a, p) => a + p.consts.length, 0),
          recipes: 0,
          terminals: 0,
          opcodesDecoded: Object.keys(ext.opSemantics).length
        },
        output
      };
    }

    // Otherwise run current stage in sandbox to capture next `loadstring(...)` payload
    const res = runInSandbox(current);
    if (!res.capturedLoads || res.capturedLoads.length === 0) {
      throw new Error(`Stage ${s} did not yield a next payload (${res.error || 'no loadstring call captured'})`);
    }
    const nextPayload =
      res.capturedLoads.find(c => isSV3VM(c) || isSV2VM(c)) ||
      res.capturedLoads.reduce((a, b) => (b.length >= a.length ? b : a), '');
    stages.push({
      stage: s,
      type: s === 1 ? 'Stage 1 Loader' : `Stage ${s} Unpacker`,
      bytes: current.length,
      unpackedBytes: nextPayload.length
    });
    current = nextPayload.replace(/^\uFEFF/, '');
    const verAfter = detectSnowVeilVersion(current);
    if (verAfter !== 'unknown') detectedVersion = verAfter;
  }

  throw new Error('Exceeded maximum unpacking stages (6) without locating SnowVeil VM');
}

module.exports = { deobfuscateSnowVeil, detectSnowVeilVersion };
