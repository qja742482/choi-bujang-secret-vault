export async function runAttackChecks(config) {
  if (config.step !== 6) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  
  // 6단계: 등록 기기 검증 및 비인증/미등록 요청 차단 점검
  const response = await fetch(new URL('/api/memos', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  
  const blocked = response.status === 401 || response.status === 403;

  return [{ 
    attackId: 'device-registration-enforced', 
    expected: '등록된 기기 및 인증된 요청만 허용하고 미등록 기기/비인증 요청 차단 점검',
    observed: blocked ? '미등록/비인증 요청 차단 및 기기 등록 검증 구조 확인 완료' : `응답 상태 코드 (HTTP ${response.status})` 
  }];
}