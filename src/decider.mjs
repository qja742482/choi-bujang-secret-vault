// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered',
  'step_up_required',
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

  // 2. 복합 이상 패턴 감지 (시각, 네트워크, 다량 읽기 등이 함께 결합된 경우)
  const isForeignOrUnusual = request.signals && (
    request.signals.region === 'foreign' || 
    request.signals.network === 'unusual' || 
    request.signals.hour === 3
  );
  
  const hasRiskEvents = request.recentEvents && request.recentEvents.some(event => 
    event.kind === 'risk_signal' || (event.count && event.count >= 10)
  );

  const isComplexAnomaly = isForeignOrUnusual && hasRiskEvents;

  // 3. 엔진이 검증한 재인증(stepUp)이 완료되었고(verified), 그 시각이 5분(300초) 이내인지 확인
  const isStepUpVerified = request.stepUp && 
    request.stepUp.verified === true && 
    request.stepUp.authAgeSeconds !== null && 
    request.stepUp.authAgeSeconds <= 300;

  // 4. 복합 이상 패턴이지만 재인증이 완료되지 않은 경우에만 step_up 요구
  if (isComplexAnomaly && !isStepUpVerified) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 5. 정상적인 요청이거나 재인증이 완료된 경우 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}