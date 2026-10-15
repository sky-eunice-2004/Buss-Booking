
const crypto = require('crypto');
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const CLIENT_ID = process.env.CLIENT_ID || 'demo-partner';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'demo-secret';
const PAYMENT_SECRET = process.env.PAYMENT_SECRET || 'mock-payment-confirmation-secret';
const TRAVEL_DATE = process.env.TRAVEL_DATE || new Date(Date.now() + 14 * 864e5).toISOString().slice(0, 10);
const RUN = Date.now().toString(36); // keeps references unique between runs

let token = null, tokenExpiresAt = 0;

async function getToken() {
  if (token && Date.now() < tokenExpiresAt - 60000) return token; // refresh 1 min early
  const r = await fetch(`${BASE_URL}/auth/token`, { method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET }) });
  const j = await r.json();
  if (!j.success) throw new Error(`Token failed: ${JSON.stringify(j)}`);
  token = j.data.accessToken; tokenExpiresAt = Date.now() + j.data.expiresIn * 1000;
  return token;
}

async function api(method, path, { body, idemKey, headers = {} } = {}) {
  const h = { Authorization: `Bearer ${await getToken()}`, Accept: 'application/json',
    'X-Request-ID': crypto.randomUUID(), ...headers };
  if (body) h['Content-Type'] = 'application/json';
  if (idemKey) h['Idempotency-Key'] = idemKey;
  const r = await fetch(BASE_URL + path, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json();
  return { status: r.status, ...j };
}

// HMAC-SHA256 over compact JSON with keys in EXACTLY this order (manual section 5.2)
function paymentSignature({ paymentId, externalPaymentReference, amount, currency }) {
  const canonical = JSON.stringify({ paymentId, externalPaymentReference, amount, currency });
  return crypto.createHmac('sha256', PAYMENT_SECRET).update(canonical).digest('hex');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log(`  PASS  ${name}`); } else { failed++; console.log(`  FAIL  ${name}`, extra ? JSON.stringify(extra) : ''); }
}

(async () => {
  console.log(`Base URL: ${BASE_URL}   Travel date: ${TRAVEL_DATE}\n`);

  console.log('1. Locations');
  const loc = await api('GET', '/buses/locations?query=harare&limit=20');
  check('locations returns Harare', loc.success && loc.data[0].locationId === 'harare', loc);

  console.log('2. Search');
  const noDate = await api('GET', '/buses/search?origin=Harare&destination=Bulawayo');
  check('missing departureDate -> 400 INVALID_REQUEST', noDate.status === 400 && noDate.error.code === 'INVALID_REQUEST', noDate);
  const s = await api('GET', `/buses/search?origin=Harare&destination=Bulawayo&departureDate=${TRAVEL_DATE}&adults=1&currency=USD&includeSeatMaps=full`);
  check('search succeeds with offers', s.success && s.data.results.length > 0, s);
  const offer = s.data.results[0];
  console.log(`     offer: ${offer.operator.name} ${offer.departureTime} ${offer.amount} ${offer.currency}, ${offer.seatMap.availableCount} seats free`);

  console.log('3. Seat map refresh (do this right before booking)');
  const sm = await api('GET', `/buses/offers/${encodeURIComponent(offer.offerId)}/seat-map?mode=full`);
  check('seat map returns seats', sm.success && sm.data.seatMap.seats.length > 0, sm);
  const seat = sm.data.seatMap.seats[0].seatId;

  console.log('4. Create booking');
  const ref = `PARTNER-ORDER-${RUN}`;
  const bookingBody = { externalReference: ref, offerId: offer.offerId, travelDate: TRAVEL_DATE, currency: 'USD',
    contact: { firstName: 'John', lastName: 'Doe', email: 'john.doe@example.com', phone: '+263771234567' },
    passengers: [{ firstName: 'John', lastName: 'Doe', age: 35, seatNumber: seat }] };
  const noKey = await api('POST', '/bookings', { body: bookingBody });
  check('missing Idempotency-Key -> 400', noKey.status === 400, noKey);
  const withPrice = await api('POST', '/bookings', { body: { ...bookingBody, amount: 1 }, idemKey: `${ref}-p` });
  check('submitting price is rejected -> 400', withPrice.status === 400, withPrice);
  const b = await api('POST', '/bookings', { body: bookingBody, idemKey: ref });
  check('booking created (201, payment_pending)', b.status === 201 && b.data.status === 'payment_pending', b);
  const retry = await api('POST', '/bookings', { body: bookingBody, idemKey: ref });
  check('same key + same body replays safely', retry.status === 201 && retry.data.bookingId === b.data.bookingId, retry);
  const conflict = await api('POST', '/bookings', { body: { ...bookingBody, externalReference: ref + 'x' }, idemKey: ref });
  check('same key + different body -> 409 IDEMPOTENCY_CONFLICT', conflict.status === 409 && conflict.error.code === 'IDEMPOTENCY_CONFLICT', conflict);
  const taken = await api('POST', '/bookings', { body: { ...bookingBody, externalReference: ref + '2' }, idemKey: ref + '2' });
  check('booking the same seat again -> 422 SEAT_UNAVAILABLE', taken.status === 422 && taken.error.code === 'SEAT_UNAVAILABLE', taken);
  const id = b.data.bookingId;

  console.log('5. Passenger requirements + details');
  const req = await api('GET', `/bookings/${id}/passenger-requirements`);
  check('requirements list gender + dob', req.success && req.data.passengerRequirements.fields.length === 2, req);
  const paymentRef = `PARTNER-PAY-${RUN}`;
  // Payment initiated first only to prove PASSENGERS_NOT_FINALIZED below
  const pay = await api('POST', `/bookings/${id}/payment`, { body: { method: 'bank_transfer', externalPaymentReference: paymentRef }, idemKey: `PAY-${RUN}` });
  check('payment initiated (202, pending)', pay.status === 202 && pay.data.status === 'pending', pay);
  const conf0 = { paymentId: pay.data.paymentId, externalPaymentReference: paymentRef, amount: pay.data.amount, currency: pay.data.currency };
  const early = await api('POST', `/bookings/${id}/payment-confirmation`, { body: conf0, idemKey: `CONF0-${RUN}`, headers: { 'X-Payment-Signature': paymentSignature(conf0) } });
  check('confirming before passengers -> PASSENGERS_NOT_FINALIZED', early.error && early.error.code === 'PASSENGERS_NOT_FINALIZED', early);
  const upd = await api('POST', `/bookings/${id}/passengers`, { idemKey: `PAX-${RUN}`, body: {
    passengers: [{ firstName: 'John', lastName: 'Doe', age: 35, seatNumber: seat, phone: '+263771234567', gender: 'male',
      dateOfBirth: '1990-01-01', idType: 'passport', idNumber: 'P1234567',
      questionAnswers: { gender: 'male', dob: '1990-01-01', id_type: 'passport', id_number: 'P1234567' } }],
    contact: { firstName: 'John', lastName: 'Doe', email: 'john.doe@example.com', phone: '+263771234567', optInMarketing: false } } });
  check('passengers accepted', upd.success, upd);

  console.log('6. Confirm payment (only after you have really received the money)');
  const badSig = await api('POST', `/bookings/${id}/payment-confirmation`, { body: conf0, idemKey: `CONF-BAD-${RUN}`, headers: { 'X-Payment-Signature': 'deadbeef' } });
  check('wrong signature rejected', !badSig.success, badSig);
  const conf = await api('POST', `/bookings/${id}/payment-confirmation`, { body: conf0, idemKey: `CONF-${RUN}`, headers: { 'X-Payment-Signature': paymentSignature(conf0) } });
  check('payment confirmed -> ticket_processing/ticketed', conf.success && ['ticket_processing', 'ticketed'].includes(conf.data.status), conf);

  console.log('7. Poll booking status with backoff, then fetch ticket');
  const notYet = await api('GET', `/bookings/${id}/ticket`);
  if (conf.data.status === 'ticket_processing') check('ticket not ready yet -> 409 (poll booking first)', notYet.status === 409, notYet);
  let status = conf.data.status, wait = 500;
  for (let i = 0; i < 12 && status !== 'ticketed'; i++) { await sleep(wait); wait = Math.min(wait * 2, 4000); status = (await api('GET', `/bookings/${id}`)).data.status; }
  check('booking reaches ticketed', status === 'ticketed', { status });
  const t = await api('GET', `/bookings/${id}/ticket`);
  check('ticket issued with ticket number', t.success && t.data.ticket.tickets[0].ticketNumber, t);
  const ps = await api('GET', `/payments/${pay.data.paymentId}`);
  check('payment status confirmed', ps.success && ps.data.paymentStatus === 'confirmed', ps);

  console.log('8. Reports');
  const rep = await api('GET', `/reports/bookings?from=${new Date().toISOString().slice(0, 10)}&status=ticketed&page=1&limit=50`);
  check('report lists the booking', rep.success && rep.data.bookings.some((x) => x.bookingId === id), rep);
  const tx = await api('GET', `/bookings/${id}/transactions`);
  check('transactions list events', tx.success && tx.data.events.length >= 3, tx);

  console.log('9. Cancel');
  const c = await api('POST', `/bookings/${id}/cancel`, { body: { reason: 'customer_request' }, idemKey: `CANCEL-${RUN}` });
  check('cancelled with refund_pending', c.success && c.data.status === 'cancelled' && c.data.paymentStatus === 'refund_pending', c);

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
