/**
 * 3단계 공격 점검 스크립트
 * 비로그인 또는 위조 토큰을 통한 보호 API 접근을 차단하는지 검증합니다.
 */
export async function runAttackCheck({ appUrl, sampleMarker } = {}) {
  const targetUrl = (appUrl || '').replace(/\/+$/, '');
  const apiUrl = `${targetUrl}/api/memos`;

  // 1. 토큰 없이 요청 시 차단 (401 또는 403 응답 여부 확인)
  try {
    const unauthRes = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json'
      }
    });

    if (unauthRes.status !== 401 && unauthRes.status !== 403) {
      return {
        passed: false,
        reason: `비인증 요청에 대해 401 또는 403이 아닌 ${unauthRes.status} 상태 코드를 반환했습니다.`
      };
    }
  } catch (error) {
    return {
      passed: false,
      reason: `비인증 보호 API 요청 중 오류 발생: ${error.message}`
    };
  }

  // 2. 위조된/잘못된 Bearer 토큰 요청 시 차단
  try {
    const fakeTokenRes = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer invalid.forged.jwt-token',
        'Accept': 'application/json'
      }
    });

    if (fakeTokenRes.status !== 401 && fakeTokenRes.status !== 403) {
      return {
        passed: false,
        reason: `위조 토큰 요청에 대해 401 또는 403이 아닌 ${fakeTokenRes.status} 상태 코드를 반환했습니다.`
      };
    }
  } catch (error) {
    return {
      passed: false,
      reason: `위조 토큰 API 요청 중 오류 발생: ${error.message}`
    };
  }

  return {
    passed: true,
    summary: '비로그인 및 위조 토큰에 대한 3단계 접근 차단 점검을 통과했습니다.'
  };
}

export default runAttackCheck;