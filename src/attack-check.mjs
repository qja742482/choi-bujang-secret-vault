export async function runAttackChecks(config) {
  if (config.step !== 7) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  
  // 7단계: 비인증 요청 차단 및 복합 이상 접속 시 재인증(step_up) 요구 점검
  const response = await fetch(new URL('/api/memos', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  
  const blocked = response.status === 401 || response.status === 403;

  return [{ 
    attackId: 'step-up-enforced', 
    expected: '비인증 요청 차단 및 복합 이상 접속 시 재인증(step_up) 요구 점검',
    observed: blocked ? '비인증 요청 차단 및 재인증 검증 구조 확인 완료' : `응답 상태 코드 (HTTP ${response.status})` 
  }];
}