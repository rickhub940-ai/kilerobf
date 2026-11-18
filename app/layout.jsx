import './globals.css';

export const metadata = {
  title: 'kilerobf — SnowVeil V3 Luau Deobfuscator & Decompiler',
  description:
    'Dynamic Luau sandbox unpacker, SVBG CFG VM proto extractor, and structured Luau decompiler for SnowVeil V3.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
