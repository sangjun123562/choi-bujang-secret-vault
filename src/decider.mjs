// ALEPH SDP 학생 판정기 v1
// 6단계: 기기 등록 검증
// 7단계: 복합 이상 징후 시 step_up_required
// 8단계: 마이크로세그멘테이션 및 Default Deny (기본 거부)

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

  // 2. 강사 자료 구역: 판정기에서 무조건 거부
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

  // 3. 반 공지 구역: GET(읽기)만 허용, 쓰기/수정/삭제는 거부
  const isAnnouncement =
    service.includes('announcement') ||
    service.includes('notice') ||
    route.includes('/announcements') ||
    path.includes('/announcements') ||
    route.includes('/notices') ||
    path.includes('/notices');

  if (isAnnouncement) {
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'deny',
        reasonCode: 'announcements_read_only',
        ruleIds: ['zone_announcements_write_deny'],
      };
    }
  }

  // 4. 학생 메모/노트 구역:
  // - 목록 조회(ID 없는 경우)는 거부
  // - 단건 작업(ID 있는 경우) 또는 생성(POST)만 허용 판정 후보로 진행
  const isNoteOrMemo =
    service === 'notes' ||
    service === 'memos' ||
    route.includes('/notes') ||
    route.includes('/memos') ||
    path.includes('/notes') ||
    path.includes('/memos');

  if (isNoteOrMemo) {
    const isList =
      route === 'GET /notes' ||
      route === 'GET /memos' ||
      route === 'GET /api/notes' ||
      route === 'GET /api/memos' ||
      path === '/notes' ||
      path === '/memos' ||
      path === '/api/notes' ||
      path === '/api/memos' ||
      path === '/notes/' ||
      path === '/memos/' ||
      path === '/api/notes/' ||
      path === '/api/memos/';

    if (isList) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'deny',
        reasonCode: 'notes_list_denied',
        ruleIds: ['zone_notes_list_deny'],
      };
    }
  }

  // 5. 허용 대상 구역 판별 (화이트리스트 검사)
  // 허용 대상:
  // - 공지 읽기: isAnnouncement && method === 'GET'
  // - 메모 단건: isNoteOrMemo && !isList
  const isAllowedZone =
    (isAnnouncement && method === 'GET') ||
    (isNoteOrMemo && (
      route.includes('/:id') ||
      path.match(/\/(notes|memos)\/[^/]+$/) ||
      method === 'POST'
    ));

  // 허용 목록에 없는 알 수 없는 경로(materials 등)는 즉시 거부 (Default Deny)
  if (!isAllowedZone) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'unknown_route',
      ruleIds: ['starter.deny'],
    };
  }

  // 6. 복합 이상 징후 검사 (7단계 규칙)
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

  // 7. 검증 통과된 정상 요청 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['zone_allowed'],
  };
}