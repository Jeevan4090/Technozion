const text = value => typeof value === "string" ? value.trim() : "";

export function eventPriority(event) {
  const name = text(event.title || event.name || event["Event Name"]);
  const club = text(event.club || event.clubName || event.societyName || event["Club Name"]);
  if (/^sdc\s*games$/i.test(name)) return 0;
  if (/^arcade$/i.test(name) && /robotics/i.test(club)) return 1;
  if (/^smash\s*karts?$/i.test(name)) return 2;
  if (/\bcses?\b|computer\s+science(?:\s+and\s+engineering)?\s+society/i.test(club) || /^cses\b/i.test(name)) return 3;
  if (/^venture\s*vortex$/i.test(name)) return 4;
  if (/^warangal\s+trading\s+ring/i.test(name)) return 5;
  return 6;
}

export function compareEvents(a, b) {
  return eventPriority(a) - eventPriority(b) || Number(Boolean(text(b.imgsrc || b.poster || b.image))) - Number(Boolean(text(a.imgsrc || a.poster || a.image)));
}

export const orderEvents = events => [...events].sort(compareEvents);
