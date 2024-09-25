import { ChildProcessWithoutNullStreams, spawn } from 'child_process';
import killPort from 'kill-port';
import path from 'path';
import fs from 'fs';

const SLS_OFFLINE_LAMBDA_PORT = 30060;

const logFilePath = path.join(__dirname, 'src/tests/test.log');
const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });

let slsOfflineProcess: ChildProcessWithoutNullStreams | null;

export async function setup() {
  return new Promise<void>((resolve, reject) => {
    console.log('Waiting for Serverless Offline to start...');

    slsOfflineProcess = spawn('npm', ['run', 'test:prepare'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: true
    });

    slsOfflineProcess.stdout.pipe(logStream);

    // https://github.com/dherault/serverless-offline/issues/1330
    slsOfflineProcess.stderr.on('data', (data: any) => {
      const message = data.toString();

      if (message.includes('Server ready:')) {
        console.log('Serverless Offline is running');
        resolve();
      }
    });

    slsOfflineProcess.on('error', (error: any) => {
      console.error('Failed to start Serverless Offline:', error);
      reject(error);
    });

    slsOfflineProcess.on('close', (code: any) => {
      console.log(`Serverless Offline exited with code ${code}`);
      slsOfflineProcess = null;
    });
  });
}

export async function teardown() {
  if (slsOfflineProcess) {
    console.log('Stopping Serverless Offline...');

    fs.truncateSync(logFilePath, 0);

    killPort(SLS_OFFLINE_LAMBDA_PORT);

    return new Promise<void>((resolve) => {
      slsOfflineProcess?.on('exit', () => {
        console.log('Serverless Offline process exited');
        resolve();
      });
    });
  }
}
