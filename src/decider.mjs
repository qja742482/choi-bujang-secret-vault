// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계 규칙: 등록한 기기만 자료실에 들어옵니다.
export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered', // 6단계 규칙 추가
]);

export async function decide(request) {
  // 기기가 등록되지 않았거나 값이 없는 경우 거부
  if (!request.deviceRegistered) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 등록된 기기인 경우 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}