/**
 * Uniglade Bus Partner API v1 - MOCK SERVER
 * Built from "Bus Integration and Reference Manual" (Partner API v1, 09 Sep 2026).
 *
 * Purpose: let you build and test your integration BEFORE you receive real
 * credentials. Everything is stored in memory and resets when you restart.
 * Anything marked "ASSUMPTION" is something the manual does not state.
 */
const express = require('express');
const crypto = require('crypto');

// ---------------------------------------------------------------- config
const PORT = process.env.PORT || 3000;
const OFFER_SECRET = process.env.OFFER_SECRET || 'mock-offer-signing-secret';
// Shared secret used for X-Payment-Signature. Uniglade gives you the real one.
const PAYMENT_SECRET = process.env.PAYMENT_CONFIRMATION_SECRET || 'mock-payment-confirmation-secret';
const TICKET_DELAY_MS = Number(process.env.TICKET_DELAY_MS || 3000); // ticket_processing -> ticketed
const RATE_LIMIT_PER_MIN = Number(process.env.RATE_LIMIT_PER_MIN || 120); // ASSUMPTION: real limits given privately
const TOKEN_TTL_SECONDS = 900; // manual: expiresIn 900
const OFFER_TTL_MS = 30 * 60 * 1000; // ASSUMPTION
const SUPPORTED_CURRENCIES = ['USD']; // ASSUMPTION: real list given privately

const ALL_SCOPES = ['search:read', 'booking:create', 'booking:read', 'booking:update',
  'payment:create', 'payment:read', 'ticket:read', 'booking:cancel', 'report:read'];

// Demo partners. Replace with your real credentials when you move to the real API.
const CLIENTS = {
  'demo-partner': { secret: 'demo-secret', scopes: ALL_SCOPES },
  'limited-partner': { secret: 'limited-secret', scopes: ['search:read'] }, // for testing 403
  'other-partner': { secret: 'other-secret', scopes: ALL_SCOPES }, // for testing 404 on other partner's data
};

const LOCATIONS = [
  { locationId: 'harare', name: 'Harare', countryCode: 'ZW' },
  { locationId: 'bulawayo', name: 'Bulawayo', countryCode: 'ZW' },
  { locationId: 'mutare', name: 'Mutare', countryCode: 'ZW' },
  { locationId: 'gweru', name: 'Gweru', countryCode: 'ZW' },
  { locationId: 'masvingo', name: 'Masvingo', countryCode: 'ZW' },
  { locationId: 'victoria-falls', name: 'Victoria Falls', countryCode: 'ZW' },
  { locationId: 'beitbridge', name: 'Beitbridge', countryCode: 'ZW' },
  { locationId: 'johannesburg', name: 'Johannesburg', countryCode: 'ZA' },
  { locationId: 'lusaka', name: 'Lusaka', countryCode: 'ZM' },
];
const OPERATORS = ['Example Bus', 'Sample Coaches'];
const DEPARTURES = [{ h: 6, op: 0 }, { h: 8, op: 0 }, { h: 14, op: 1 }];
const SEAT_LETTERS = ['A', 'B', 'C', 'D'];
const ROWS = 10; // 40 seats

// ---------------------------------------------------------------- state
const tokens = new Map();        // token -> {clientId, scopes, exp}
const idem = new Map();          // clientId|key -> {hash, status, body}
const bookings = new Map();      // bookingId -> booking
const payments = new Map();      // paymentId -> payment
const takenSeats = new Map();    // journeyKey -> Set(seatId)
const rate = new Map();          // clientId -> {count, windowStart}
let seq = 0;
const nextId = (p) => `${p}_${Date.now().toString(36).toUpperCase()}${(++seq).toString().padStart(3, '0')}`;
let reqCounter = 120;

// ---------------------------------------------------------------- helpers
const b64u = (s) => Buffer.from(s).toString('base64url');
const hmac = (secret, data) => crypto.createHmac('sha256', secret).update(data).digest('hex');
const money = (n) => Math.round(n * 100) / 100;

function signOffer(payload) {
  const body = b64u(JSON.stringify(payload));
  return `${body}.${hmac(OFFER_SECRET, body)}`;
}
function verifyOffer(offerId) {
  if (typeof offerId !== 'string' || !offerId.includes('.')) return null;
  const [body, sig] = offerId.split('.');
  const good = hmac(OFFER_SECRET, body);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (Date.now() > p.exp) return null;
    return p;
  } catch { return null; }
}

function fareFor(origin, destination) {
  // deterministic price 15..90 USD per pair, symmetric
  const key = [origin, destination].sort().join('|');
  const h = crypto.createHash('md5').update(key).digest()[0];
  return 15 + (h % 76);
}
function journeyKey(p) { return `${p.o}|${p.d}|${p.dep}|${p.op}`; }
function preTaken(key) {
  // deterministic pseudo-random ~55% of seats already taken
  const set = new Set();
  for (let r = 1; r <= ROWS; r++) for (const l of SEAT_LETTERS) {
    const h = crypto.createHash('md5').update(key + r + l).digest()[0];
    if (h % 100 < 55) set.add(`${r}${l}`);
  }
  return set;
}
function seatsTaken(key) {
  if (!takenSeats.has(key)) takenSeats.set(key, preTaken(key));
  return takenSeats.get(key);
}
function buildSeatMap(p, mode) {
  const taken = seatsTaken(journeyKey(p));
  const seats = [];
  for (let r = 1; r <= ROWS; r++) SEAT_LETTERS.forEach((l, c) => {
    const id = `${r}${l}`;
    seats.push({ seatId: id, label: id, row: r, column: c + 1,
      status: taken.has(id) ? 'unavailable' : 'available', seatClass: 'Standard' });
  });
  const available = seats.filter((s) => s.status === 'available');
  const map = { status: 'available', availableCount: available.length, totalCount: seats.length };
  if (mode === 'full') map.seats = available; // manual: "full: available seats and normalized layout"
  return map;
}

// ---------------------------------------------------------------- responses
function ok(res, data, status = 200) {
  res.status(status).json({ success: true, data, requestId: res.locals.requestId });
}
function fail(res, status, code, message) {
  res.status(status).json({ success: false, error: { code, message }, requestId: res.locals.requestId });
}
class ApiError extends Error { constructor(s, c, m) { super(m); this.s = s; this.c = c; } }
const bad = (m) => new ApiError(400, 'INVALID_REQUEST', m);

// ---------------------------------------------------------------- app
const app = express();
app.use((req, res, next) => { res.locals.requestId = `req_${++reqCounter}`; res.setHeader('X-Request-ID', res.locals.requestId); next(); });
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '1mb', verify: (req, _res, buf) => { req.rawBody = buf.toString(); } }));
app.use((err, req, res, next) => { // bad JSON
  if (err.type === 'entity.parse.failed') return fail(res, 400, 'INVALID_REQUEST', 'Request body is not valid JSON');
  next(err);
});

// 2.1 token
app.post('/auth/token', (req, res) => {
  const { grant_type, client_id, client_secret } = req.body || {};
  if (grant_type !== 'client_credentials') return fail(res, 400, 'INVALID_REQUEST', 'grant_type must be client_credentials');
  const c = CLIENTS[client_id];
  if (!c || c.secret !== client_secret) return fail(res, 401, 'UNAUTHORIZED', 'Invalid client credentials');
  const accessToken = crypto.randomBytes(24).toString('hex');
  tokens.set(accessToken, { clientId: client_id, scopes: c.scopes, exp: Date.now() + TOKEN_TTL_SECONDS * 1000 });
  ok(res, { accessToken, tokenType: 'Bearer', expiresIn: TOKEN_TTL_SECONDS });
});

// auth + rate limit + scope + idempotency middleware factory
function guard(scope, { write = false } = {}) {
  return (req, res, next) => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    const t = m && tokens.get(m[1]);
    if (!t || Date.now() > t.exp) return fail(res, 401, 'UNAUTHORIZED', 'Access token is missing, invalid or expired');
    // rate limit
    const r = rate.get(t.clientId) || { count: 0, windowStart: Date.now() };
    if (Date.now() - r.windowStart > 60000) { r.count = 0; r.windowStart = Date.now(); }
    r.count++; rate.set(t.clientId, r);
    if (r.count > RATE_LIMIT_PER_MIN) return fail(res, 429, 'RATE_LIMITED', 'The request limit was exceeded');
    if (!t.scopes.includes(scope)) return fail(res, 403, 'FORBIDDEN', `Missing required scope: ${scope}`);
    req.client = t.clientId;
    if (!write) return next();
    const key = req.headers['idempotency-key'];
    if (!key) return fail(res, 400, 'INVALID_REQUEST', 'Idempotency-Key header is required');
    const hash = crypto.createHash('sha256').update(req.method + req.path + (req.rawBody || '')).digest('hex');
    const id = `${t.clientId}|${key}`;
    const prev = idem.get(id);
    if (prev) {
      if (prev.hash !== hash) return fail(res, 409, 'IDEMPOTENCY_CONFLICT', 'Idempotency-Key was reused for a different request');
      return res.status(prev.status).json(prev.body); // safe replay
    }
    // capture SUCCESSFUL responses for replay (ASSUMPTION: failed requests do not burn the key)
    const json = res.json.bind(res);
    res.json = (body) => { if (res.statusCode < 400) idem.set(id, { hash, status: res.statusCode, body }); return json(body); };
    next();
  };
}
const wrap = (fn) => (req, res, next) => { try { fn(req, res); } catch (e) { next(e); } };

// 3.2 locations
app.get('/buses/locations', guard('search:read'), wrap((req, res) => {
  const q = String(req.query.query || '').toLowerCase();
  const limit = Math.max(1, Math.min(200, Number(req.query.limit) || 50));
  ok(res, LOCATIONS.filter((l) => !q || l.name.toLowerCase().includes(q) || l.locationId.includes(q)).slice(0, limit));
}));

function findLocation(v) {
  const s = String(v || '').toLowerCase();
  return LOCATIONS.find((l) => l.locationId === s || l.name.toLowerCase() === s);
}

// 3.3 search
app.get('/buses/search', guard('search:read'), wrap((req, res) => {
  const q = req.query;
  for (const f of ['origin', 'destination', 'departureDate']) if (!q[f]) throw bad(`${f} is required`);
  const o = findLocation(q.origin); const d = findLocation(q.destination);
  if (!o) throw bad('origin is not a supported location');
  if (!d) throw bad('destination is not a supported location');
  if (o.locationId === d.locationId) throw bad('origin and destination must differ');
  const dateOk = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s));
  if (!dateOk(q.departureDate)) throw bad('departureDate must be YYYY-MM-DD');
  if (q.returnDate && !dateOk(q.returnDate)) throw bad('returnDate must be YYYY-MM-DD');
  const currency = (q.currency || 'USD').toUpperCase();
  if (!SUPPORTED_CURRENCIES.includes(currency)) throw bad(`currency ${currency} is not supported`);
  const mode = q.includeSeatMaps || 'summary';
  if (!['none', 'summary', 'full'].includes(mode)) throw bad('includeSeatMaps must be none, summary or full');
  const num = (v, def) => (v === undefined ? def : Number(v));
  const pax = { adults: num(q.adults, 1), children: num(q.children, 0), seniors: num(q.seniors, 0), students: num(q.students, 0) };
  for (const [k, v] of Object.entries(pax)) if (!Number.isInteger(v) || v < 0) throw bad(`${k} must be a non-negative integer`);
  const total = pax.adults + pax.children + pax.seniors + pax.students;
  if (total < 1) throw bad('At least one passenger is required');

  const build = (from, to, date) => DEPARTURES.map((dep) => {
    const departure = new Date(`${date}T00:00:00Z`); departure.setUTCHours(dep.h);
    const arrival = new Date(departure.getTime() + 6 * 3600 * 1000);
    const payload = { o: from.locationId, d: to.locationId, dep: departure.toISOString(), op: OPERATORS[dep.op],
      amt: fareFor(from.locationId, to.locationId), cur: currency, pax: total, exp: Date.now() + OFFER_TTL_MS };
    const offer = {
      offerId: signOffer(payload),
      operator: { name: payload.op, logo_url: 'https://example.invalid/assets/logo' },
      origin: { name: from.name, city: { name: from.name } },
      destination: { name: to.name },
      departureTime: payload.dep, arrivalTime: arrival.toISOString(),
      amount: money(payload.amt), currency, seatSelectionAvailable: true,
    };
    if (mode !== 'none') offer.seatMap = buildSeatMap(payload, mode);
    return offer;
  });
  ok(res, {
    searchId: nextId('search'), status: 'success',
    results: build(o, d, q.departureDate),
    returnResults: q.returnDate ? build(d, o, q.returnDate) : [],
  });
}));

// 3.4 seat map refresh
app.get('/buses/offers/:offerId/seat-map', guard('search:read'), wrap((req, res) => {
  const p = verifyOffer(req.params.offerId);
  if (!p) throw bad('offerId is invalid or expired');
  const mode = req.query.mode || 'summary';
  if (!['summary', 'full'].includes(mode)) throw bad('mode must be summary or full');
  ok(res, { offerId: req.params.offerId, seatMap: { ...buildSeatMap(p, mode), source: 'live' } });
}));

// ---- bookings
const FORBIDDEN_FIELDS = ['price', 'amount', 'paymentStatus', 'cost', 'markup', 'commission', 'status'];
const view = (b) => ({
  bookingId: b.bookingId, externalReference: b.externalReference, status: b.status,
  paymentStatus: b.paymentStatus, ticketStatus: b.ticketStatus, amount: b.amount, currency: b.currency,
  passengers: b.passengers.map((p) => ({ name: `${p.firstName} ${p.lastName}`, seatNumber: p.seatNumber })),
  createdAt: b.createdAt, updatedAt: b.updatedAt, expiresAt: null,
});
function event(b, type) { b.events.push({ type, at: new Date().toISOString() }); b.updatedAt = new Date().toISOString(); }
function mine(req, id) {
  const b = bookings.get(id);
  if (!b || b.client !== req.client) throw new ApiError(404, 'NOT_FOUND', 'The resource does not exist or is not visible to the client');
  return b;
}

// 4.1 create booking
app.post('/bookings', guard('booking:create', { write: true }), wrap((req, res) => {
  const body = req.body || {};
  for (const f of FORBIDDEN_FIELDS) if (f in body) throw bad(`${f} must not be submitted; Uniglade calculates it`);
  for (const f of ['externalReference', 'offerId', 'travelDate', 'currency']) if (!body[f]) throw bad(`${f} is required`);
  const c = body.contact || {};
  for (const f of ['firstName', 'lastName', 'email', 'phone']) if (!c[f]) throw bad(`contact.${f} is required`);
  if (!Array.isArray(body.passengers) || body.passengers.length < 1) throw bad('passengers must be a non-empty array');
  body.passengers.forEach((p, i) => {
    for (const f of ['firstName', 'lastName']) if (!p[f]) throw bad(`passengers[${i}].${f} is required`);
    for (const f of FORBIDDEN_FIELDS) if (f in p) throw bad(`passengers[${i}].${f} must not be submitted`);
  });
  const offer = verifyOffer(body.offerId);
  if (!offer) throw bad('offerId is invalid or expired; copy it exactly from a current search response');
  if (body.currency !== offer.cur) throw bad(`currency must match the offer (${offer.cur})`);
  if (offer.dep.slice(0, 10) !== body.travelDate) throw bad('travelDate does not match the offer');
  if (body.passengers.length !== offer.pax) throw bad(`passenger count (${body.passengers.length}) must match the search request (${offer.pax})`);
  for (const b of bookings.values()) if (b.client === req.client && b.externalReference === body.externalReference)
    throw new ApiError(409, 'BOOKING_STATE_CONFLICT', 'externalReference already used'); // ASSUMPTION: error code
  // seats (final availability check)
  const taken = seatsTaken(journeyKey(offer));
  const chosen = body.passengers.map((p) => p.seatNumber).filter(Boolean);
  if (chosen.length !== body.passengers.length) throw bad('seatNumber is required for every passenger on this journey');
  if (new Set(chosen).size !== chosen.length) throw bad('seatNumber values must be unique');
  for (const s of chosen) if (taken.has(s)) throw new ApiError(422, 'SEAT_UNAVAILABLE', `Seat ${s} is no longer available`);
  for (const s of chosen) if (!/^(10|[1-9])[A-D]$/.test(s)) throw bad(`Seat ${s} does not exist`);
  chosen.forEach((s) => taken.add(s));
  const now = new Date().toISOString();
  const b = {
    bookingId: nextId('booking'), client: req.client, externalReference: body.externalReference,
    offer, contact: c, passengers: body.passengers.map((p) => ({ ...p })), passengersFinalized: false,
    status: 'payment_pending', paymentStatus: 'pending', ticketStatus: 'not_issued',
    amount: money(offer.amt * body.passengers.length), currency: offer.cur,
    createdAt: now, updatedAt: now, events: [], ticket: null, paymentId: null,
  };
  bookings.set(b.bookingId, b); event(b, 'booking_created');
  ok(res, view(b), 201);
}));

// 4.2 get booking
app.get('/bookings/:id', guard('booking:read'), wrap((req, res) => ok(res, view(mine(req, req.params.id)))));

// 4.3 passenger requirements
app.get('/bookings/:id/passenger-requirements', guard('booking:read'), wrap((req, res) => {
  const b = mine(req, req.params.id);
  ok(res, { bookingId: b.bookingId, passengerRequirements: { knownAt: 'search', fields: [
    { key: 'gender', required: true, type: 'selection', options: ['female', 'male'] },
    { key: 'dob', required: true, type: 'date', options: [] },
  ] } });
}));

// 4.4 update passengers
app.post('/bookings/:id/passengers', guard('booking:update', { write: true }), wrap((req, res) => {
  const b = mine(req, req.params.id);
  if (['cancelled', 'ticketed', 'ticket_processing'].includes(b.status))
    throw new ApiError(409, 'BOOKING_STATE_CONFLICT', `Passengers cannot be updated while booking is ${b.status}`);
  const body = req.body || {};
  if (!Array.isArray(body.passengers) || body.passengers.length !== b.passengers.length)
    throw bad(`passengers must contain exactly ${b.passengers.length} passenger(s)`);
  const answer = (p, key, alt) => {
    const qa = p.questionAnswers;
    if (qa && !Array.isArray(qa) && qa[key] !== undefined) return qa[key];
    if (qa && Array.isArray(qa.answers)) { const a = qa.answers.find((x) => x.key === key); if (a) return a.value; }
    return p[alt];
  };
  const updated = body.passengers.map((p, i) => {
    const ctx = `passengers[${i}]`;
    for (const f of ['firstName', 'lastName']) if (!p[f]) throw bad(`${ctx}.${f} is required`);
    const gender = answer(p, 'gender', 'gender');
    const dob = answer(p, 'dob', 'dateOfBirth');
    if (!['female', 'male'].includes(gender)) throw bad(`${ctx}: gender is required (female or male)`);
    if (!dob || !/^\d{4}-\d{2}-\d{2}$/.test(dob) || isNaN(Date.parse(dob))) throw bad(`${ctx}: dob is required (YYYY-MM-DD)`);
    const seat = p.seatNumber || b.passengers[i].seatNumber;
    if (seat !== b.passengers[i].seatNumber) throw bad(`${ctx}.seatNumber cannot be changed here`);
    return { ...b.passengers[i], ...p, seatNumber: seat, gender, dateOfBirth: dob };
  });
  b.passengers = updated;
  if (body.contact) b.contact = { ...b.contact, ...body.contact };
  b.passengersFinalized = true; event(b, 'passengers_completed');
  ok(res, view(b));
}));

// 4.5 optional seat endpoints
app.get('/bookings/:id/seats', guard('booking:read'), wrap((req, res) => {
  const b = mine(req, req.params.id);
  ok(res, { bookingId: b.bookingId, seats: b.passengers.map((p) => p.seatNumber) });
}));
app.post('/bookings/:id/seats', guard('booking:update', { write: true }), wrap((req, res) => {
  mine(req, req.params.id);
  // ASSUMPTION: manual says this is optional and may return SEAT_UPDATE_UNAVAILABLE; HTTP status not stated.
  throw new ApiError(409, 'SEAT_UPDATE_UNAVAILABLE', 'Seat changes are not available for this journey; use the seat chosen at booking creation');
}));

// 5.1 initiate payment
app.post('/bookings/:id/payment', guard('payment:create', { write: true }), wrap((req, res) => {
  const b = mine(req, req.params.id);
  if (b.status !== 'payment_pending') throw new ApiError(409, 'BOOKING_STATE_CONFLICT', `Cannot initiate payment while booking is ${b.status}`);
  const { method, externalPaymentReference } = req.body || {};
  if (!method) throw bad('method is required');
  if (!externalPaymentReference) throw bad('externalPaymentReference is required');
  const p = { paymentId: nextId('payment'), bookingId: b.bookingId, status: 'pending', amount: b.amount, currency: b.currency,
    method, externalPaymentReference };
  payments.set(p.paymentId, p); b.paymentId = p.paymentId; event(b, 'payment_initiated');
  ok(res, { paymentId: p.paymentId, bookingId: b.bookingId, status: 'pending', amount: p.amount, currency: p.currency }, 202);
}));

// 5.2 payment confirmation
app.post('/bookings/:id/payment-confirmation', guard('payment:create', { write: true }), wrap((req, res) => {
  const b = mine(req, req.params.id);
  const sig = req.headers['x-payment-signature'];
  if (!sig) throw bad('X-Payment-Signature header is required');
  const { paymentId, externalPaymentReference, amount, currency } = req.body || {};
  for (const [k, v] of Object.entries({ paymentId, externalPaymentReference, amount, currency })) if (v === undefined) throw bad(`${k} is required`);
  // Canonical string: compact JSON, keys in this exact order
  const canonical = JSON.stringify({ paymentId, externalPaymentReference, amount, currency });
  const expected = hmac(PAYMENT_SECRET, canonical);
  const sigOk = typeof sig === 'string' && sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig.toLowerCase()), Buffer.from(expected));
  if (!sigOk) throw new ApiError(401, 'UNAUTHORIZED', 'X-Payment-Signature is invalid'); // ASSUMPTION: status/code
  const p = payments.get(paymentId);
  if (!p || p.bookingId !== b.bookingId) throw bad('paymentId does not belong to this booking');
  if (p.externalPaymentReference !== externalPaymentReference) throw bad('externalPaymentReference does not match the initiated payment');
  if (Number(amount) !== p.amount || currency !== p.currency) throw bad(`amount/currency must match the booking (${p.amount} ${p.currency})`);
  if (!b.passengersFinalized) throw new ApiError(409, 'PASSENGERS_NOT_FINALIZED', 'Submit passenger details before confirming payment'); // ASSUMPTION: HTTP 409
  if (p.status === 'confirmed') return ok(res, { paymentId, bookingId: b.bookingId, status: b.status, paymentStatus: 'confirmed', ticketStatus: b.ticketStatus, amount: p.amount, currency: p.currency });
  if (b.status !== 'payment_pending') throw new ApiError(409, 'BOOKING_STATE_CONFLICT', `Cannot confirm payment while booking is ${b.status}`);
  p.status = 'confirmed'; b.paymentStatus = 'confirmed'; b.status = 'ticket_processing'; event(b, 'payment_confirmed');
  setTimeout(() => { // simulate asynchronous ticketing
    if (b.status !== 'ticket_processing') return;
    b.status = 'ticketed'; b.ticketStatus = 'issued';
    const ref = `TM-TICKET-${b.bookingId.slice(-6)}`;
    b.ticket = { reference: ref, status: 'issued', tickets: b.passengers.map((pp, i) => ({
      ticketNumber: `${ref}-${i + 1}`, passengerName: `${pp.firstName} ${pp.lastName}`, seatNumber: pp.seatNumber,
      route: `${LOCATIONS.find((l) => l.locationId === b.offer.o).name} - ${LOCATIONS.find((l) => l.locationId === b.offer.d).name}`,
      departure: b.offer.dep, arrival: new Date(Date.parse(b.offer.dep) + 6 * 3600 * 1000).toISOString() })) };
    event(b, 'ticket_issued');
  }, TICKET_DELAY_MS);
  ok(res, { paymentId, bookingId: b.bookingId, status: 'ticket_processing', paymentStatus: 'confirmed', ticketStatus: 'not_issued', amount: p.amount, currency: p.currency });
}));

// 5.3 payment status
app.get('/payments/:paymentId', guard('payment:read'), wrap((req, res) => {
  const p = payments.get(req.params.paymentId);
  const b = p && bookings.get(p.bookingId);
  if (!b || b.client !== req.client) throw new ApiError(404, 'NOT_FOUND', 'The resource does not exist or is not visible to the client');
  ok(res, { paymentId: p.paymentId, bookingId: b.bookingId, status: b.status, paymentStatus: b.paymentStatus,
    ticketStatus: b.ticketStatus, amount: p.amount, currency: p.currency });
}));

// 6.1 ticket
app.get('/bookings/:id/ticket', guard('ticket:read'), wrap((req, res) => {
  const b = mine(req, req.params.id);
  if (!b.ticket) throw new ApiError(409, 'BOOKING_STATE_CONFLICT', `Ticket not issued yet (booking status: ${b.status}). Poll GET /bookings/{id} first.`); // ASSUMPTION
  ok(res, { bookingId: b.bookingId, ticketStatus: 'issued', ticket: b.ticket });
}));

// 7.1 cancel
app.post('/bookings/:id/cancel', guard('booking:cancel', { write: true }), wrap((req, res) => {
  const b = mine(req, req.params.id);
  if (b.status === 'cancelled') throw new ApiError(409, 'BOOKING_STATE_CONFLICT', 'Booking is already cancelled');
  if (!(req.body || {}).reason) throw bad('reason is required');
  const paid = b.paymentStatus === 'confirmed';
  b.status = 'cancelled'; if (paid) b.paymentStatus = 'refund_pending';
  const taken = seatsTaken(journeyKey(b.offer)); b.passengers.forEach((p) => taken.delete(p.seatNumber));
  event(b, 'booking_cancelled');
  ok(res, { bookingId: b.bookingId, externalReference: b.externalReference, status: b.status,
    paymentStatus: b.paymentStatus, ticketStatus: b.ticketStatus });
}));

// 8.1 reports
app.get('/reports/bookings', guard('report:read'), wrap((req, res) => {
  const { from, until, status } = req.query;
  const page = Math.max(1, Number(req.query.page) || 1);
  const limit = Math.max(1, Math.min(200, Number(req.query.limit) || 50));
  let list = [...bookings.values()].filter((b) => b.client === req.client);
  if (from) list = list.filter((b) => b.createdAt.slice(0, 10) >= from);
  if (until) list = list.filter((b) => b.createdAt.slice(0, 10) <= until);
  if (status) list = list.filter((b) => b.status === status);
  ok(res, { page, limit, total: list.length, bookings: list.slice((page - 1) * limit, page * limit).map(view) });
}));
// 8.2 transactions
app.get('/bookings/:id/transactions', guard('report:read'), wrap((req, res) => {
  const b = mine(req, req.params.id);
  ok(res, { bookingId: b.bookingId, events: b.events });
}));

// ---------------------------------------------------------------- errors
app.use((req, res) => fail(res, 404, 'NOT_FOUND', `No route for ${req.method} ${req.path}`));
app.use((err, req, res, _next) => {
  if (err instanceof ApiError) return fail(res, err.s, err.c, err.message);
  console.error(err);
  fail(res, 503, 'SERVICE_UNAVAILABLE', 'Uniglade is temporarily unavailable');
});

if (require.main === module) app.listen(PORT, () => console.log(`Uniglade mock API listening on http://localhost:${PORT}`));
module.exports = { app, hmac, PAYMENT_SECRET };
