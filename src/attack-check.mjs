export function runAttackCheck(events) {
  // 9단계 폭주(Burst Read) 공격 검증 로직
  const userEventsMap = {};
  for (const ev of (events || [])) {
    const sub = ev.identity?.sub;
    if (!sub || ev.method !== 'GET') continue;
    if (!userEventsMap[sub]) userEventsMap[sub] = [];
    userEventsMap[sub].push(new Date(ev.at).getTime());
  }

  for (const sub of Object.keys(userEventsMap)) {
    const times = userEventsMap[sub].sort((a, b) => a - b);
    for (let i = 0; i < times.length; i++) {
      let count = 0;
      const windowStart = times[i];
      const windowEnd = windowStart + 10 * 60 * 1000;
      
      for (let j = i; j < times.length; j++) {
        if (times[j] >= windowStart && times[j] <= windowEnd) {
          count++;
        }
      }

      if (count > 120) {
        return {
          detected: true,
          reasonCode: 'burst_read',
          subject: sub
        };
      }
    }
  }

  return { detected: false };
}