const esbuild = require('esbuild');
const glob = require('glob');
const path = require('path');

const entryPattern = 'src/handlers/**/*.ts';
const entryPoints = glob.sync(entryPattern);

const nodeBuiltIns = ['crypto'];

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
