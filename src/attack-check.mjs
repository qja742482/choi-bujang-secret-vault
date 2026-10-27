export async function runAttackChecks(config) {
  if (config.step !== 2) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  
  // 2단계: /api/memos 서버리스 API 엔드포인트 호출 점검
  const response = await fetch(new URL('/api/memos', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = Array.isArray(data) || (data && Array.isArray(data.notes));
    } catch {
      // 비JSON 응답인 경우
    }
  }

  return [{ 
    attackId: 'public-api-exposure', 
    expected: '서버 API 엔드포인트를 통한 메모 데이터 조회 가능 여부 점검',
    observed: visible ? '/api/memos 엔드포인트가 인증 없이 데이터를 반환하는 보안 약점 확인 완료' : `API 응답 확인 불가 (HTTP ${response.status})` 
  }];
}
