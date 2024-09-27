const esbuild = require('esbuild');
const glob = require('glob');
const path = require('path');

const entryPattern = 'src/handlers/**/*.ts';
const entryPoints = glob.sync(entryPattern);

const nodeBuiltIns = [
  'assert',
  'buffer',
  'child_process',
  'cluster',
  'crypto',
  'dgram',
  'dns',
  'domain',
  'events',
  'fs',
  'http',
  'https',
  'net',
  'os',
  'path',
  'punycode',
  'querystring',
  'readline',
  'stream',
  'string_decoder',
  'timers',
  'tls',
  'tty',
  'url',
  'util',
  'v8',
  'vm',
  'zlib'
];

const dependencies = [
  'jsonwebtoken',
  'nodemailer',
  'otplib',
  'qrcode',
  'serverless-postgres',
  'unique-names-generator',
  'winston',
  'zod'
];

const externalDependencies = [...dependencies, ...nodeBuiltIns];

esbuild
  .build({
    entryPoints: entryPoints,
    bundle: true,
    outdir: 'build',
    outbase: '.',
    format: 'cjs',
    platform: 'node',
    target: 'node16',
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
