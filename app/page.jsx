'use client';

import { useState, useRef, useMemo } from 'react';
import {
  Terminal,
  Play,
  Copy,
  Check,
  Download,
  Upload,
  Trash2,
  Cpu,
  Layers,
  AlertTriangle,
  Sparkles,
  FileCode2,
  ShieldCheck,
  Loader2,
} from 'lucide-react';

const SAMPLE_LUAU = `-- Sample 2-Stage Luau Loader (uses 0b/0x literals, +=, and table.freeze)
local key = 0b0010_1010
key += 0x05
local bytes = { 112, 114, 105, 110, 116, 40, 34, 72, 101, 108, 108, 111, 32, 102, 114, 111, 109, 32, 107, 105, 108, 101, 114, 111, 98, 102, 33, 34, 41 }
local chars = {}
for i, b in table.freeze(bytes) do
  chars[i] = string.char(b)
end
local stage2 = "local msg = 'Unpacked with key=' .. tostring(" .. tostring(key) .. ")\\n" .. table.concat(chars)
loadstring(stage2)()
`;

function detectHint(src) {
  if (!src.trim()) return 'Idle';
  if (/SnowVeil\s+V3/.test(src) || (/\.proto\b/.test(src) && /\.closure\b/.test(src))) {
    return 'SnowVeil V3 Detected';
  }
  if (/SnowVeil\s+v?2/.test(src) || (/\.proto\b/.test(src) && /liveState\b/.test(src))) {
    return 'SnowVeil v2.0 Detected';
  }
  if (/\bloadstring\b|\bload\s*\(/.test(src)) {
    return 'Stage Loader Detected';
  }
  return 'Luau Source';
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export default function HomePage() {
  const [source, setSource] = useState('');
  const [mode, setMode] = useState('deobfuscate');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const hint = useMemo(() => detectHint(source), [source]);
  const inputLines = useMemo(() => (source ? source.split('\n').length : 0), [source]);
  const outputLines = useMemo(
    () => (result?.output ? result.output.split('\n').length : 0),
    [result]
  );

  async function runDeobfuscate(overrideSource, overrideMode) {
    const srcToRun = typeof overrideSource === 'string' ? overrideSource : source;
    const modeToRun = overrideMode || mode;
    if (!srcToRun.trim()) {
      setError('Paste obfuscated Lua/Luau code or upload a .lua file first.');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const res = await fetch('/api/deobfuscate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: srcToRun, mode: modeToRun }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setError(data.error || 'Deobfuscation failed.');
      } else {
        setResult(data);
      }
    } catch (e) {
      setError(e?.message || 'Network error while running deobfuscator.');
    } finally {
      setLoading(false);
    }
  }

  function handleLoadSample() {
    setSource(SAMPLE_LUAU);
    setMode('unpack');
    setError('');
    setResult(null);
  }

  function handleClear() {
    setSource('');
    setResult(null);
    setError('');
  }

  async function handleCopy() {
    if (!result?.output) return;
    await navigator.clipboard.writeText(result.output);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  function handleDownload() {
    if (!result?.output) return;
    const blob = new Blob([result.output], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'deobfuscated.lua';
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleFileRead(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = typeof ev.target?.result === 'string' ? ev.target.result : '';
      setSource(text);
      setError('');
    };
    reader.readAsText(file);
  }

  function handleKeyDown(e) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      runDeobfuscate();
    }
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand-group">
          <div className="brand-logo">
            <Terminal size={20} />
          </div>
          <div>
            <div className="brand-title">
              <h1>kilerobf</h1>
              <span className="badge badge-accent">SnowVeil V3 CFG</span>
              <span className="badge badge-cyan">Luau Sandbox</span>
            </div>
            <p className="brand-sub">
              Dynamic multi-stage Lua/Luau unpacker, SVBG CFG VM proto extractor &amp; structured decompiler
            </p>
          </div>
        </div>

        <div className="toolbar">
          <div className="mode-switch" role="group" aria-label="Decompiler Mode">
            <button
              type="button"
              className={`mode-btn ${mode === 'deobfuscate' ? 'active' : ''}`}
              onClick={() => setMode('deobfuscate')}
            >
              SnowVeil V3 Decompile
            </button>
            <button
              type="button"
              className={`mode-btn ${mode === 'unpack' ? 'active' : ''}`}
              onClick={() => setMode('unpack')}
            >
              Loadstring Unpack
            </button>
          </div>

          <button type="button" className="btn" onClick={handleLoadSample}>
            <Sparkles size={15} />
            Sample
          </button>

          <button
            type="button"
            className="btn"
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload size={15} />
            Upload .lua
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".lua,.luau,.txt"
            style={{ display: 'none' }}
            onChange={(e) => handleFileRead(e.target.files?.[0])}
          />

          <button type="button" className="btn" onClick={handleClear} disabled={!source && !result}>
            <Trash2 size={15} />
            Clear
          </button>

          <button
            type="button"
            className="btn btn-primary"
            onClick={() => runDeobfuscate()}
            disabled={loading}
          >
            {loading ? <Loader2 size={15} className="spin" /> : <Play size={15} />}
            {loading ? 'Processing...' : mode === 'unpack' ? 'Unpack' : 'Deobfuscate'}
          </button>
        </div>
      </header>

      {error && (
        <div className="error-banner" role="alert">
          <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{error}</span>
        </div>
      )}

      <section className="workbench">
        <div
          className={`pane ${dragOver ? 'drag-over' : ''}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            handleFileRead(e.dataTransfer.files?.[0]);
          }}
        >
          <div className="pane-header">
            <div className="pane-title">
              <FileCode2 size={16} color="#34d399" />
              <span>Input Source</span>
              <span className="badge">{hint}</span>
            </div>
            <div className="pane-meta">
              <span>{inputLines} lines</span>
              <span>•</span>
              <span>{formatBytes(source.length)}</span>
            </div>
          </div>

          <textarea
            className="code-area"
            value={source}
            onChange={(e) => setSource(e.target.value)}
            onKeyDown={handleKeyDown}
            spellCheck={false}
            placeholder={`-- Paste SnowVeil V3 obfuscated Luau script or drag & drop a .lua file here\n-- Shortcut: Ctrl+Enter / Cmd+Enter to run`}
          />
        </div>

        <div className="pane">
          <div className="pane-header">
            <div className="pane-title">
              <ShieldCheck size={16} color="#22d3ee" />
              <span>Decompiled Output</span>
              {result?.version && <span className="badge badge-accent">{result.version}</span>}
            </div>
            <div className="pane-meta">
              {result?.elapsedMs != null && <span>{result.elapsedMs} ms</span>}
              {result?.output && (
                <>
                  <span>•</span>
                  <span>{outputLines} lines</span>
                  <button type="button" className="btn" style={{ padding: '4px 9px', fontSize: '0.75rem' }} onClick={handleCopy}>
                    {copied ? <Check size={13} color="#34d399" /> : <Copy size={13} />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                  <button type="button" className="btn" style={{ padding: '4px 9px', fontSize: '0.75rem' }} onClick={handleDownload}>
                    <Download size={13} />
                    .lua
                  </button>
                </>
              )}
            </div>
          </div>

          {result?.output ? (
            <pre className="code-output">{result.output}</pre>
          ) : (
            <div className="empty-output">
              <Cpu size={34} color="#2c3750" />
              <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#8b98b1' }}>
                Ready to analyze &amp; decompile
              </div>
              <div style={{ fontSize: '0.78rem', maxWidth: 340, lineHeight: 1.5 }}>
                Paste a SnowVeil V3 script and click <strong>Deobfuscate</strong>, or test the
                sandbox with <strong>Sample</strong>.
              </div>
            </div>
          )}
        </div>
      </section>

      {result && (
        <section className="telemetry">
          <div className="card">
            <div className="card-title">
              <Layers size={15} color="#22d3ee" />
              Unpacking Stages ({result.stages?.length || 0})
            </div>
            <div className="stage-list">
              {(result.stages || []).map((st) => (
                <div key={st.stage} className="stage-item">
                  <div className="stage-name">
                    <span className="badge badge-cyan">S{st.stage}</span>
                    <span>{st.type}</span>
                  </div>
                  <div className="stage-bytes">
                    {formatBytes(st.bytes)}
                    {st.unpackedBytes != null ? ` → ${formatBytes(st.unpackedBytes)}` : ''}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-title">
              <Cpu size={15} color="#34d399" />
              VM &amp; CFG Telemetry
            </div>
            {result.stats ? (
              <div className="stats-grid">
                <div className="stat-box">
                  <div className="stat-label">Protos</div>
                  <div className="stat-value">{result.stats.protos}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">CFG Blocks</div>
                  <div className="stat-value">{result.stats.blocks}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Constants</div>
                  <div className="stat-value">{result.stats.constants}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Recipes</div>
                  <div className="stat-value">{result.stats.recipes}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Terminals</div>
                  <div className="stat-value">{result.stats.terminals}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Opcodes</div>
                  <div className="stat-value">{result.stats.opcodesDecoded}</div>
                </div>
              </div>
            ) : (
              <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Extracted raw payload from sandbox <code>loadstring</code> hooks in{' '}
                <strong>{result.elapsedMs} ms</strong>. Switch to{' '}
                <strong>SnowVeil V3 Decompile</strong> when targeting full SVBG CFG VM payloads.
              </div>
            )}
          </div>
        </section>
      )}

      <section className="pipeline-grid" aria-label="Deobfuscation Pipeline">
        <div className="pipeline-step">
          <h3>1. Luau Preprocessor</h3>
          <p>
            Token-aware Luau-to-Lua 5.3 lowering: strips type annotations, normalizes{' '}
            <code>0b</code>/<code>0x</code> floats, expands <code>+=</code>/<code>..=</code>, and
            rewrites generalized <code>for</code> loops.
          </p>
        </div>
        <div className="pipeline-step">
          <h3>2. Fengari VM Sandbox</h3>
          <p>
            Emulates Roblox/Luau APIs (<code>bit32</code>, <code>buffer</code>,{' '}
            <code>string.pack</code>, <code>Vector2/3</code>, <code>CFrame</code>) and hooks{' '}
            <code>loadstring</code> to unwrap multi-stage loaders.
          </p>
        </div>
        <div className="pipeline-step">
          <h3>3. Dynamic Proto Dumper</h3>
          <p>
            Intercepts Stage 3 VM initialization to dump live constants, basic blocks, recipe
            schemas, and classifies micro-opcodes &amp; terminals.
          </p>
        </div>
        <div className="pipeline-step">
          <h3>4. SVBG CFG Decompiler</h3>
          <p>
            Reconstructs dominators, natural loops, and conditional branches from lifted IR back
            into readable, structured Luau source code.
          </p>
        </div>
      </section>
    </main>
  );
}
