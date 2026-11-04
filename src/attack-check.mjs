export function runAttackChecks(events) {
  // events가 배열이 아니거나 객체/단일 값일 경우 안전하게 배열로 변환
  let eventList = [];
  if (Array.isArray(events)) {
    eventList = events;
  } else if (events && typeof events === 'object') {
    if (Array.isArray(events.events)) {
      eventList = events.events;
    } else {
      eventList = [events];
    }
  }

  const userEventsMap = {};
  for (const ev of eventList) {
    const sub = ev?.identity?.sub;
    if (!sub || ev?.method !== 'GET') continue;
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