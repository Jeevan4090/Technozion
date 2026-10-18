// ─── Fee Constants ────────────────────────────────────────────────────────────
export const GATE_FEE_PER_MEMBER = 100;
export const COMPETITION_FEE_PER_EVENT = 500;

// ─── Normalizers & Helpers ───────────────────────────────────────────────────
export function normalizeStudentType(type) {
  if (!type) return "external";
  const normalized = String(type).trim().toLowerCase();
  return normalized === "nitw" ? "nitw" : "external";
}

export function countExternalParticipants({ isNitwLead = false, members = [], teamSize = 4 } = {}) {
  let count = isNitwLead ? 0 : 1;

  const validMembers = members
    .filter((m) => m && m.name && String(m.name).trim().length > 0)
    .slice(0, Math.max(0, teamSize - 1));

  for (const member of validMembers) {
    if (normalizeStudentType(member.studentType) !== "nitw") {
      count += 1;
    }
  }

  return Math.min(count, teamSize);
}

// Alias for backwards-compatibility across the app
export const getChargeableGateMembers = countExternalParticipants;

// ─── Event Categorization ────────────────────────────────────────────────────
export function groupRegistrationEvents(events = []) {
  const competitions = [];
  const games = [];
  const other = [];

  for (const ev of events) {
    const type = String(ev.eventType || ev.category || "").toLowerCase();
    if (type.includes("competition")) {
      competitions.push(ev);
    } else if (type.includes("game")) {
      games.push(ev);
    } else {
      other.push(ev);
    }
  }

  return [
    { key: "competitions", label: "Competitions", events: competitions },
    { key: "games", label: "Games & Activities", events: games },
    { key: "other", label: "Demonstrations & Other Events", events: other },
  ];
}

// ─── Fee Computation ─────────────────────────────────────────────────────────
export function computeRegistrationFee({
  isNitwLead = false,
  members = [],
  selectedEventIds = [],
  events = [],
  teamSize = 4,
} = {}) {
  const chosenEvents = (events || []).filter((e) =>
    (selectedEventIds || []).includes(e._id || e.slug)
  );

  const competitionEvents = chosenEvents.filter((e) =>
    String(e.eventType || e.category || "").toLowerCase().includes("competition")
  );
  const competitionCount = competitionEvents.length;

  const externalCount = countExternalParticipants({
    isNitwLead,
    members,
    teamSize,
  });

  // Teams made up only of NITW students pay nothing, whatever the team size or events
  if (externalCount === 0) {
    return {
      total: 0,
      mode: "exempt",
      competitionCount,
      externalCount: 0,
      requiresPayment: false,
    };
  }

  if (competitionCount > 0) {
  const total = externalCount === 0
    ? 0
    : Math.min(competitionCount * COMPETITION_FEE_PER_EVENT, 2000);
    return {
      total,
      mode: "competition",
      competitionCount,
      externalCount,
      requiresPayment: total > 0,
    };
  }

  // Gate fee: ₹100 per external participant (capped at ₹2000)
  const total = Math.min(externalCount * GATE_FEE_PER_MEMBER, 2000);
  return {
    total,
    mode: "gate",
    competitionCount: 0,
    externalCount,
    requiresPayment: total > 0,
  };
}
