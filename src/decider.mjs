// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기
// 6단계: 등록된 기기만 허용하고 미등록 기기는 device_not_registered로 거부합니다.

export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered',
]);

export async function decide(request) {
  // 기기가 등록되어 있는지 확인 (true일 때만 허용)
  if (request.deviceRegistered === true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    };
  }

  // 미등록 기기이거나 값이 없는 경우 거부
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'device_not_registered',
    ruleIds: ['device_registered'],
  };
}