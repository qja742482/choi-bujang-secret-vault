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

  // 2. 반 공지(공지사항) 경로 규칙: GET(읽기)만 허용, 쓰기(POST, PUT, PATCH, DELETE 등)는 엄격히 거부
  if (path && path.startsWith('/api/public-notices')) {
    // 하위 경로가 더 있거나 GET이 아닌 경우 거부
    const subPath = path.replace('/api/public-notices', '').replace(/^\/+/, '');
    if (subPath.length > 0 || (method && method !== 'GET')) {
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

  // 3. 메모 경로 규칙: 오직 GET /api/notes/:id (ID가 정확히 존재하는 단건 조회)만 허용
  // 전체 목록(/api/notes 또는 /api/notes/)이나 다른 깊이의 경로는 거부
  if (path && path.startsWith('/api/notes')) {
    const subPath = path.replace('/api/notes', '').replace(/^\/+/, '');
    const segments = subPath ? subPath.split('/') : [];
    
    // 정확히 하나의 ID 세그먼트만 있고, 메소드가 GET인 경우만 허용
    const isSingleIdGet = segments.length === 1 && segments[0].length > 0 && method === 'GET';

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