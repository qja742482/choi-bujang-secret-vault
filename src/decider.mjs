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

  // 2. 강사 자료 경로 거부
  if (path && path.startsWith('/api/instructor')) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'instructor_material_denied',
      ruleIds: ['starter.deny'],
    };
  }

  // 3. 반 공지 (공지사항) 경로 규칙: GET(읽기)만 허용, 쓰기 요청은 거부
  if (path && path.startsWith('/api/public-notices')) {
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

  // 4. 메모 경로 규칙: ID가 포함된 개별 조회(GET /api/notes/:id)만 허용, 전체 목록은 거부
  if (path && path.startsWith('/api/notes')) {
    const subPath = path.replace('/api/notes', '').replace(/^\/+/, '');
    const hasId = subPath.length > 0 && !subPath.includes('/');

    if (!hasId || (method && method !== 'GET')) {
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

  // 5. 알 수 없는 경로는 거부
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'unknown_route_denied',
    ruleIds: ['starter.deny'],
  };
}