/**
 * 3단계 공격 점검 스크립트
 * bundle.mjs 규격: { attackId, expected, observed } 형태의 배열 반환
 */
export async function runAttackChecks(config = {}) {
  const targetUrl = (config.publicAppUrl || '').replace(/\/+$/, '');
  const apiUrl = `${targetUrl}/api/memos`;

  const results = [];

  // 점검 1: 토큰 없이 보호 API 요청 시 401/403 차단 여부
  try {
    const unauthRes = await fetch(apiUrl, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    results.push({
      attackId: 'unauthenticated-access-blocked',
      expected: 'HTTP 401 or 403 Forbidden/Unauthorized',
      observed: `HTTP ${unauthRes.status} received`,
    });
  } catch (error) {
    results.push({
      attackId: 'unauthenticated-access-blocked',
      expected: 'HTTP 401 or 403 Forbidden/Unauthorized',
      observed: `Network request error: ${error.message.slice(0, 100)}`,
    });
  }

  // 점검 2: 위조된 토큰으로 보호 API 요청 시 차단 여부
  try {
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
      observed: `HTTP ${fakeTokenRes.status} received`,
    });
  } catch (error) {
    results.push({
      attackId: 'forged-token-access-blocked',
      expected: 'HTTP 401 or 403 Forbidden/Unauthorized',
      observed: `Network request error: ${error.message.slice(0, 100)}`,
    });
  }

  return results;
}

export default runAttackChecks;