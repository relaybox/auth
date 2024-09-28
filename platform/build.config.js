const esbuild = require('esbuild');
const glob = require('glob');
const path = require('path');

const entryPattern = 'src/handlers/**/*.ts';
const entryPoints = glob.sync(entryPattern);

const externalDependencies = [
  'jsonwebtoken',
  'nodemailer',
  'otplib',
  'qrcode',
  'serverless-postgres',
  'unique-names-generator',
  'winston',
  'zod'
];

esbuild
  .build({
    entryPoints: entryPoints,
    bundle: true,
    outdir: 'build',
    outbase: '.',
    format: 'cjs',
    platform: 'node',
    target: 'node20',
    sourcemap: false,
    minify: true,
    splitting: false,
    entryNames: '[dir]/[name]',
    external: externalDependencies
  })
  .then(() => {
    console.log('Build succeeded.');
  })
  .catch((error) => {
    console.error('Build failed:', error);
    process.exit(1);
  });
