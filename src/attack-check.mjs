JavaScript
export async function runAttackChecks(config) {
  if (config.step !== 3) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  
  // 3단계: 무로그인 상태에서 /api/memos 요청 시 401 Unauthorized 반환 여부 점검
  const response = await fetch(new URL('/api/memos', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  
  const unauthorized = response.status === 401;

  return [{ 
    attackId: 'unauthorized-memo-access-blocked', 
    expected: '로그인되지 않은 상태에서의 /api/memos 요청이 401로 차단되는지 점검',
    observed: unauthorized ? '무로그인 /api/memos 접근이 401로 정상 차단됨 확인' : `예상치 못한 응답 상태 코드 (HTTP ${response.status})` 
  }];
}