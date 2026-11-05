// 9단계: 슬라이딩 윈도우 기반 도플갱어 폭주 조회 탐지기
// 10분(600,000ms) 구간 내同一 사용자의 GET 요청이 120건을 초과할 때 propose_revocation 제안

const WINDOW_MS = 10 * 60 * 1000; // 10분 = 600,000밀리초
const BURST_LIMIT = 120; // 120건까지는 허용, 121건부터 의심

export function detect(events) {
  if (!Array.isArray(events)) {
    throw new TypeError('invalid_detection_events');
  }

  // 1. 사용자(sub)별로 GET 요청 사건의 타임스탬프(ms)를 모음
  const userTimestamps = new Map();

  for (const event of events) {
    if (!event || event.method !== 'GET') continue;
    const sub = event.identity?.sub;
    if (!sub || typeof event.at !== 'string') continue;

    const time = Date.parse(event.at);
    if (Number.isNaN(time)) continue;

    if (!userTimestamps.has(sub)) {
      userTimestamps.set(sub, []);
    }
    userTimestamps.get(sub).push(time);
  }

  // 2. 각 사용자별로 10분 슬라이딩 윈도우 검사
  for (const [sub, times] of userTimestamps.entries()) {
    times.sort((a, b) => a - b);

    let left = 0;
    for (let right = 0; right < times.length; right++) {
      // 10분(600,000ms) 범위를 벗어난 이전 사건은 윈도우에서 제외
      while (times[right] - times[left] > WINDOW_MS) {
        left++;
      }

      // 현재 10분 윈도우 [left ... right]에 포함된 사건 수
      const countInWindow = right - left + 1;

      // 120건을 초과(121건 이상)하면 즉시 권한 회수 제안
      if (countInWindow > BURST_LIMIT) {
        return {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          subject: sub,
        };
      }
    }
  }

  // 120건 이하이거나 이상 징후가 없으면 관찰(정상) 유지
  return { action: 'observe' };
}