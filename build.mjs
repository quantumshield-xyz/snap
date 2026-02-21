// QuantumShield Snap — Build script (esbuild)
import { build } from 'esbuild';

await build({
  entryPoints: ['src/index.js'],
  bundle: true,
  outfile: 'dist/bundle.js',
  format: 'cjs',
  platform: 'browser',
  target: 'es2022',
  minify: false,
  sourcemap: false,
  define: {
    'process.env.NODE_ENV': '"production"',
  },
});

console.log('[SNAP] Built dist/bundle.js');
