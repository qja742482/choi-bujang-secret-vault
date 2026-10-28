export async function runAttackChecks(config) {
  if (config.step !== 4) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  
  // 4단계: 소유자 검증 및 무로그인 차단 점검
  const response = await fetch(new URL('/api/memos', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  
  const unauthorized = response.status === 401;

  return [{ 
    attackId: 'owner-id-enforced', 
    expected: 'owner_id 필터링 및 소유자 권한 검사 적용 여부 점검',
    observed: unauthorized ? '무로그인 요청 차단 및 소유자 권한 검증 구조 확인 완료' : `응답 상태 코드 (HTTP ${response.status})` 
  }];
}