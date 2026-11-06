/**
 * 12단계 공격 점검 스크립트
 * bundle.mjs 규격: { attackId, expected, observed } 형태의 배열 반환
 * 실제 요청 기록이 확인되지 않으면 'not_run'으로 설정
 */
export async function runAttackChecks(config = {}) {
  const targetUrl = (config.publicAppUrl || '').replace(/\/+$/, '');
  const apiUrl = targetUrl ? `${targetUrl}/api/memos` : '';

  const results = [];

  // 점검 1: 토큰 없이 보호 API 요청 시 401/403 차단 여부
  try {
    if (!apiUrl) throw new Error('no_target_url');
    const unauthRes = await fetch(apiUrl, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    results.push({
      attackId: 'unauthenticated-access-blocked',
      expected: 'HTTP 401 or 403 Forbidden/Unauthorized',
      observed: unauthRes.status ? `HTTP ${unauthRes.status}` : 'not_run',
    });
  } catch (_) {
    results.push({
      attackId: 'unauthenticated-access-blocked',
      expected: 'HTTP 401 or 403 Forbidden/Unauthorized',
      observed: 'not_run',
    });
  }

  // 점검 2: 위조된 토큰으로 보호 API 요청 시 차단 여부
  try {
    if (!apiUrl) throw new Error('no_target_url');
    const fakeTokenRes = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer invalid.forged.jwt-token',
        'Accept': 'application/json',
      },
    });
    results.push({
      attackId: 'forged-token-access-blocked',
      expected: 'HTTP 401 or 403 Forbidden/Unauthorized',
      observed: fakeTokenRes.status ? `HTTP ${fakeTokenRes.status}` : 'not_run',
    });
  } catch (_) {
    results.push({
      attackId: 'forged-token-access-blocked',
      expected: 'HTTP 401 or 403 Forbidden/Unauthorized',
      observed: 'not_run',
    });
  }

  return results;
}

export default runAttackChecks;