const { runInSandbox } = require('./sandbox');
const { extractSV2Dynamic } = require('./sv2_extractor');
const { decompileSV2 } = require('./sv2_decompiler');
const { extractSV3Dynamic } = require('./sv3_extractor');
const { decompileSV3 } = require('./sv3_decompiler');

function detectSnowVeilVersion(source) {
  if (/SnowVeil\s+V3/.test(source) || (/\.proto\b/.test(source) && /\.closure\b/.test(source))) return 'V3';
  if (/SnowVeil\s+v?2/.test(source) || (/\.proto\b/.test(source) && /liveState\b/.test(source))) return 'v2.0';
  return 'unknown';
}

function deobfuscateSnowVeil(source) {
  const t0 = Date.now();
  const stages = [];
  let current = source;
  let detectedVersion = detectSnowVeilVersion(source);

  // Stage unpacking loop (max 4 stages)
  for (let s = 1; s <= 4; s++) {
    // Check if current source is V3 Stage 3 VM
    if (/\.proto\b/.test(current) && /\.entry\b/.test(current) && /\.closure\b/.test(current) && !/liveState\b/.test(current)) {
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

    // Check if current source is v2.0 Stage 2 / SSA CFG VM
    if (/\.proto\b/.test(current) && /\.entry\b/.test(current) && (/liveState\b/.test(current) || /\.arena\b/.test(current))) {
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
    const nextPayload = res.capturedLoads[res.capturedLoads.length - 1];
    stages.push({
      stage: s,
      type: s === 1 ? 'Stage 1 Loader' : `Stage ${s} Unpacker`,
      bytes: current.length,
      unpackedBytes: nextPayload.length
    });
    current = nextPayload;
    const verAfter = detectSnowVeilVersion(current);
    if (verAfter !== 'unknown') detectedVersion = verAfter;
  }

  throw new Error('Exceeded maximum unpacking stages (4) without locating SnowVeil VM');
}

module.exports = { deobfuscateSnowVeil, detectSnowVeilVersion };
