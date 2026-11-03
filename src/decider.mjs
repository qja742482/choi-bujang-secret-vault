// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 7단계 규칙: 등록한 기기이되, 평소와 다른 복합 이상 패턴이 감지되면 step_up(추가 인증) 요구
export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered',
  'step_up_required', // 7단계 규칙 추가
]);

export async function decide(request) {
  // 1. 기기가 등록되지 않은 경우 거부
  if (!request.deviceRegistered) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 2. 복합 이상 패턴 감지 (signals의 위험 요소 또는 recentEvents의 risk_signal 확인)
  const isForeignOrUnusual = request.signals && (request.signals.region === 'foreign' || request.signals.network === 'unusual' || request.signals.hour === 3);
  const hasRiskEvents = request.recentEvents && request.recentEvents.some(event => event.kind === 'risk_signal' || event.count > 10);

  if (isForeignOrUnusual || hasRiskEvents) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 3. 정상적인 요청인 경우 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}