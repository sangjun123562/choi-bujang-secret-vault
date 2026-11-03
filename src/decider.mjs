// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기
// 6단계: 기기 등록 여부 검증
// 7단계: 복합 이상 징후 시 step_up_required 요구
// 8단계: 구역별 마이크로세그멘테이션 (메모 단건만 허용, 공지 읽기만 허용, 강사 자료 및 목록 거부)

export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered',
  'step_up_required',
  'zone_announcements_write_deny',
  'zone_instructor_deny',
  'zone_notes_list_deny',
  'zone_allowed',
]);

export async function decide(request) {
  // 1. 미등록 기기 차단 (6단계 규칙)
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  const service = (request.service || '').toLowerCase();
  const method = (request.method || '').toUpperCase();
  const route = (request.route || '').trim();
  const path = (request.path || '').trim();

  // 2. 강사 자료 구역: 학생 판정기에서는 무조건 거부
  if (
    service.includes('instructor') ||
    route.includes('instructor') ||
    path.includes('instructor')
  ) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'instructor_zone_denied',
      ruleIds: ['zone_instructor_deny'],
    };
  }

  // 3. 반 공지 구역: 읽기(GET)만 허용, 쓰기/수정/삭제는 거부
  if (
    service.includes('announcement') ||
    route.includes('announcement') ||
    path.includes('announcement')
  ) {
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'deny',
        reasonCode: 'announcements_read_only',
        ruleIds: ['zone_announcements_write_deny'],
      };
    }
    // GET 요청은 아래 이상 징후 검사 후 허용
  }

  // 4. 학생 메모/노트 구역: ID가 있는 단건 경로만 허용, 전체 목록 경로는 거부
  if (
    service === 'notes' ||
    service === 'memos' ||
    route.includes('/notes') ||
    route.includes('/memos') ||
    path.includes('/notes') ||
    path.includes('/memos')
  ) {
    // ID가 없는 전체 목록 경로 (예: route === 'GET /notes', path === '/notes') 거부
    const isListRoute =
      route === 'GET /notes' ||
      route === 'GET /memos' ||
      path === '/notes' ||
      path === '/memos' ||
      path === '/notes/' ||
      path === '/memos/';

    if (isListRoute) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'deny',
        reasonCode: 'notes_list_denied',
        ruleIds: ['zone_notes_list_deny'],
      };
    }
  }

  // 5. 복합 이상 징후 검사 (7단계 규칙)
  const isStepUpVerified = request.stepUp && request.stepUp.verified === true;
  const signals = request.signals || {};
  const recentEvents = Array.isArray(request.recentEvents) ? request.recentEvents : [];

  const isSuspiciousHour =
    typeof signals.hour === 'number' && (signals.hour < 6 || signals.hour >= 23);
  const isUnusualNetwork = signals.network === 'unusual';
  const isBulkRead = recentEvents.some(
    (ev) => ev.kind === 'risk_signal' || ev.kind === 'read' || ev.count >= 10
  );

  if (isSuspiciousHour && isUnusualNetwork && isBulkRead && !isStepUpVerified) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 6. 정상 구역 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['zone_allowed'],
  };
}