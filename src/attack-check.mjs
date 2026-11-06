/**
 * 12단계 공격 점검 스크립트
 * 확인 가능한 실제 요청 기록이 없는 점검은 'not_run'으로 기록
 */
export async function runAttackChecks(_config = {}) {
  return [
    {
      attackId: 'unauthenticated-access-blocked',
      expected: 'HTTP 401 or 403 Forbidden/Unauthorized',
      observed: 'not_run',
    },
    {
      attackId: 'forged-token-access-blocked',
      expected: 'HTTP 401 or 403 Forbidden/Unauthorized',
      observed: 'not_run',
    },
  ];
}

export default runAttackChecks;