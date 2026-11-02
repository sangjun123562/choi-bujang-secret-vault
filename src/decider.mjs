// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기
// 6단계: 기기 등록 여부 검증
// 7단계: 복합 이상 징후 감지 시 추가 인증(step_up) 요구

export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered',
  'step_up_anomaly',
]);

export async function decide(request) {
  // 1. 미등록 기기 차단 (6단계 규칙 유지)
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 2. 이미 추가 인증을 마친 상태인지 확인
  const isStepUpVerified = request.stepUp && request.stepUp.verified === true;

  // 3. 복합 이상 징후 검사 (신호 출처, 네트워크/시간/최근 위험 사건)
  const signals = request.signals || {};
  const recentEvents = Array.isArray(request.recentEvents) ? request.recentEvents : [];
  
  const hasRiskEvent = recentEvents.some(
    (ev) => ev.kind === 'risk_signal' || ev.count >= 10
  );
  const isSuspiciousContext =
    signals.network === 'unusual' ||
    (typeof signals.hour === 'number' && (signals.hour < 6 || signals.hour >= 23)) ||
    (signals.region && signals.region !== 'local' && signals.region !== 'unknown');

  // 이상 징후가 감지되었는데 아직 재인증을 거치지 않은 경우 step_up 요구
  if ((hasRiskEvent || isSuspiciousContext) && !isStepUpVerified) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'suspicious_activity',
      ruleIds: ['step_up_anomaly'],
    };
  }

  // 4. 정상 접속 또는 재인증 완료 시 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}