export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered',
  'step_up_required',
]);

export async function decide(request) {
  // 1. 기기 등록 여부 확인
  if (!request.deviceRegistered) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  const { path, method } = request;

  // 2. 반 공지(공지사항) 경로 규칙: GET(읽기)만 허용, 쓰기는 거부
  if (path && (path.startsWith('/api/public-notices') || path.startsWith('/public-notices'))) {
    if (method && method !== 'GET') {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'deny',
        reasonCode: 'public_notice_write_denied',
        ruleIds: ['starter.deny'],
      };
    }
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    };
  }

  // 3. 메모/자료 단건 조회 경로 규칙: /notes/:id 또는 /api/notes/:id 형태의 GET 요청 허용
  // 전체 목록 경로(예: /notes 또는 /api/notes 자체)나 쓰기 메소드는 거부
  if (path && (path.startsWith('/api/notes') || path.startsWith('/notes'))) {
    const cleanPath = path.replace(/^\/api/, ''); // /api/notes -> /notes
    const segments = cleanPath.replace(/^\/+/, '').split('/');
    
    // segments[0] === 'notes' 이고, 뒤에 정확히 하나의 ID가 존재하며, GET 요청인 경우 허용
    const isSingleIdGet = segments.length === 2 && segments[0] === 'notes' && segments[1].length > 0 && method === 'GET';

    if (!isSingleIdGet) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'deny',
        reasonCode: 'note_list_or_invalid_access_denied',
        ruleIds: ['starter.deny'],
      };
    }

    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    };
  }

  // 4. 강사 자료 및 기타 알 수 없는 경로는 모두 거부
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'unknown_route_denied',
    ruleIds: ['starter.deny'],
  };
}