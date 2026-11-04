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

  // 2. 7단계 재확인 규칙: 낯선 접속(복합 이상 접속) 시 step_up 요구
  if (request.suspicious && !request.stepUpVerified) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required_for_suspicious_access',
      ruleIds: ['step_up_required'],
    };
  }

  const { path, method } = request;

  // 3. 공지사항 경로: GET(읽기)만 허용, 쓰기는 거부
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

  // 4. 메모/자료 단건 조회 경로 허용 (ID 형식 제한 없음, 목록인 /api/notes 또는 /notes 자체만 거부)
  if (path && (path.startsWith('/api/notes') || path.startsWith('/notes'))) {
    // 정확히 목록 경로 자체인 경우(예: /api/notes 또는 /notes 또는 뒤에 슬래시만 있는 경우)는 거부
    const isExactListPath = path === '/api/notes' || path === '/api/notes/' || path === '/notes' || path === '/notes/';

    if (isExactListPath || method !== 'GET') {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'deny',
        reasonCode: 'note_list_or_invalid_access_denied',
        ruleIds: ['starter.deny'],
      };
    }

    // 그 외 단건 조회 GET 요청은 모두 허용 (ID 형식 제한 없음)
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    };
  }

  // 5. 그 외 알 수 없는 경로는 모두 거부
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'unknown_route_denied',
    ruleIds: ['starter.deny'],
  };
}