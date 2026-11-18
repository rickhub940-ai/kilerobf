import { NextResponse } from 'next/server';
import { createRequire } from 'module';

export const runtime = 'nodejs';
export const maxDuration = 60;

const require = createRequire(import.meta.url);
const { deobfuscateSnowVeil, detectSnowVeilVersion } = require('../../../lib/engine/deobfuscate');
const { runInSandbox } = require('../../../lib/engine/sandbox');

export async function GET() {
  return NextResponse.json({
    name: 'kilerobf',
    engine: 'SnowVeil V3 Dynamic Decompiler & Luau Sandbox',
    status: 'ready',
  });
}

export async function POST(request) {
  try {
    const body = await request.json();
    const source = typeof body?.source === 'string' ? body.source : '';
    const mode = body?.mode === 'unpack' ? 'unpack' : 'deobfuscate';

    if (!source.trim()) {
      return NextResponse.json(
        { ok: false, error: 'Please provide obfuscated Lua/Luau source code.' },
        { status: 400 }
      );
    }

    if (source.length > 5 * 1024 * 1024) {
      return NextResponse.json(
        { ok: false, error: 'Input exceeds 5 MB limit.' },
        { status: 413 }
      );
    }

    if (mode === 'unpack') {
      const t0 = Date.now();
      const stages = [];
      let current = source;
      for (let s = 1; s <= 4; s++) {
        const res = runInSandbox(current);
        if (!res.capturedLoads || res.capturedLoads.length === 0) {
          if (s === 1) {
            return NextResponse.json(
              { ok: false, error: 'No loadstring() or load() call captured in sandbox.' },
              { status: 422 }
            );
          }
          break;
        }
        const nextPayload = res.capturedLoads[res.capturedLoads.length - 1];
        stages.push({
          stage: s,
          type: `Stage ${s} Unpacker`,
          bytes: current.length,
          unpackedBytes: nextPayload.length,
        });
        current = nextPayload;
      }
      return NextResponse.json({
        ok: true,
        version: detectSnowVeilVersion(current) !== 'unknown'
          ? `Unpacked (${detectSnowVeilVersion(current)})`
          : 'Loadstring Unpacker',
        elapsedMs: Date.now() - t0,
        stages,
        stats: null,
        output: current,
      });
    }

    const result = deobfuscateSnowVeil(source);
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json(
      {
        ok: false,
        error: err?.message || 'Deobfuscation failed.',
      },
      { status: 422 }
    );
  }
}
