// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기
// 6단계: 기기 등록 여부 검증
// 7단계: 시각 + 낯선 네트워크 + 다량 읽기 복합 이상 징후 시 추가 인증 요구

export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered',
  'step_up_required',
]);

export async function decide(request) {
  // 1. 미등록 기기 차단 (기존 6단계 규칙 유지)
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 2. 이미 추가 인증을 완료한 요청이면 허용
  const isStepUpVerified = request.stepUp && request.stepUp.verified === true;

  // 3. 복합 조건 검사: 시각 + 낯선 네트워크 + 다량 읽기
  const signals = request.signals || {};
  const recentEvents = Array.isArray(request.recentEvents) ? request.recentEvents : [];

  // (1) 평소와 다른 시각
  const isSuspiciousHour = typeof signals.hour === 'number' && (signals.hour < 6 || signals.hour >= 23);

  // (2) 낯선 네트워크
  const isUnusualNetwork = signals.network === 'unusual';

  // (3) 다량 읽기 (최근 위험/요청 사건 카운트 확인)
  const isBulkRead = recentEvents.some(
    (ev) => (ev.kind === 'risk_signal' || ev.kind === 'read' || ev.count >= 10)
  );

  // 세 가지 신호가 "모두 함께" 충족되고, 아직 추가 인증 전일 때만 step_up 판정
  if (isSuspiciousHour && isUnusualNetwork && isBulkRead && !isStepUpVerified) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 4. 정상 접속 또는 단순 단일 신호는 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}