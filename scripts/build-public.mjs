import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));

// 2단계 검증
if (config.step !== 2) {
  throw new Error('현재 단계 설정이 올바르지 않습니다. (step: 2 필요)');
}

// public 폴더 생성 보장
await mkdir(resolve(root, 'public'), { recursive: true });

// 배포 검증용 aleph.json 생성 (Vercel 배포 시 필수)
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(
    resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`,
    'utf8'
  );
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}