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

  // 2. 7단계 핵심: signals/recentEvents 기반 낯선 접속 판단 및 stepUp 검증
  // (stepUp이 완료된 요청이 아니고, signals나 recentEvents에 이상 징후가 있으면 step_up 필요)
  const isStepUpVerified = Boolean(request.stepUp?.verified || request.stepUpVerified);
  const hasSuspiciousSignals = Boolean(
    (request.signals && request.signals.length > 0) ||
    (request.recentEvents && request.recentEvents.length > 0) ||
    request.suspicious
  );

  if (hasSuspiciousSignals && !isStepUpVerified) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required_for_suspicious_access',
      ruleIds: ['step_up_required'],
    };
  }

  const { path, method } = request;

  // 3. 반 공지(공지사항) 경로: GET만 허용, 쓰기는 거부
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

  // 4. 메모/자료 단건 조회 경로 (/api/notes/... 및 /notes/...)
  // ID 형식(UUID 등)을 제한하지 않고 단건 읽기(GET)는 허용, 목록 조회(/notes, /api/notes) 및 쓰기는 거부
  if (path && (path.startsWith('/api/notes') || path.startsWith('/notes'))) {
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

    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    };
  }

  // 5. 강사 자료 및 기타 알 수 없는 경로는 모두 거부
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'unknown_route_denied',
    ruleIds: ['starter.deny'],
  };
}