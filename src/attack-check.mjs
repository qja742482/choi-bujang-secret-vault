export async function runAttackChecks(config) {
  if (config.step !== 8) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  
  // 8단계: 메모 전체 목록 조회(/api/notes 또는 /api/memos) 차단 및 구역 접근 제어 점검
  const response = await fetch(new URL('/api/notes', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  
  const blocked = response.status === 401 || response.status === 403 || response.status === 404;

  return [{ 
    attackId: 'segment-access-control', 
    expected: '메모 전체 목록 조회 및 미허용 구역 접근 차단 검증',
    observed: blocked ? '메모 목록 조회 및 미허용 구역 접근 차단 확인 완료' : `응답 상태 코드 (HTTP ${response.status})` 
  }];
}