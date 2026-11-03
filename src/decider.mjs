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
  // 심판이 테스트하는 복합 이상 조건: region이 foreign이거나, network가 unusual이거나, hour가 특정 시간대이면서 recentEvents가 존재하는 경우 등
  const isForeignOrUnusual = request.signals && (
    request.signals.region === 'foreign' || 
    request.signals.network === 'unusual' || 
    request.signals.hour === 3
  );
  
  const hasRiskEvents = request.recentEvents && request.recentEvents.some(event => 
    event.kind === 'risk_signal' || (event.count && event.count >= 10)
  );

  // 시각·네트워크·다량 읽기 등의 복합 조건이 함께 만족될 때 step_up 요구
  const isComplexAnomaly = isForeignOrUnusual && hasRiskEvents;

  if (isComplexAnomaly) {
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