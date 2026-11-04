export async function detect(events) {
  // 1. 이벤트별로 at, method, identity.sub만 추출하여 불필요한 속성 읽기 방지
  const sanitizedEvents = (events || []).map(e => ({
    at: e.at,
    method: e.method,
    sub: e.identity?.sub
  }));

  // 사용자별/시간순 정렬 및 10분(600,000ms) 내 GET 요청 120건 초과(121건 이상) 탐지
  const userEventsMap = {};
  for (const ev of sanitizedEvents) {
    if (!ev.sub || ev.method !== 'GET') continue;
    if (!userEventsMap[ev.sub]) userEventsMap[ev.sub] = [];
    userEventsMap[ev.sub].push(new Date(ev.at).getTime());
  }

  for (const sub of Object.keys(userEventsMap)) {
    const times = userEventsMap[sub].sort((a, b) => a - b);
    for (let i = 0; i < times.length; i++) {
      let count = 0;
      const windowStart = times[i];
      const windowEnd = windowStart + 10 * 60 * 1000; // 10분
      
      for (let j = i; j < times.length; j++) {
        if (times[j] >= windowStart && times[j] <= windowEnd) {
          count++;
        }
      }

      if (count > 120) {
        return {
          action: "propose_revocation",
          reasonCode: "burst_read",
          subject: sub
        };
      }
    }
  }

  return {
    action: "observe"
  };
}