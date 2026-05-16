// worker.js — TavernOS submission handler
//
// Routes:
//   POST /api/apply  → trial application
//   POST /api/loop   → stay-in-the-loop signup
//   * (anything else) → falls through to static assets (the /apply page, etc.)
//
// Bindings (set in wrangler.toml):
//   SUBMISSIONS    — KV namespace (durable storage)
//   ASSETS         — static asset binding
//   NOTIFY_EMAIL   — vars: where notifications go (default: dan@tavernos.ai)
//   CALENDLY_URL   — vars: Calendly link, swap when live
//   RESEND_API_KEY — secret: when set, emails send; when unset, they log and skip
//
// Changelog:
//   - SEC-4: every Worker response is now wrapped by applyHeaders() to set
//     8 security headers — Strict-Transport-Security (1-year HSTS with
//     includeSubDomains), Content-Security-Policy (10 directives including
//     strict default-src / frame-ancestors 'none' / form-action 'self' /
//     object-src 'none', with Google Fonts allowlisted in style-src and
//     font-src), X-Content-Type-Options: nosniff, X-Frame-Options: DENY,
//     Referrer-Policy: strict-origin-when-cross-origin, Permissions-Policy
//     (camera / microphone / geolocation / payment / usb / interest-cohort
//     all disabled), Cross-Origin-Opener-Policy: same-origin, Cross-Origin-
//     Resource-Policy: same-origin. The CSP uses 'unsafe-inline' on both
//     script-src and style-src as a closed-alpha compromise — 4 of 5 site
//     pages currently have inline <script> blocks (real form handlers, not
//     trivial) and all 5 have inline <style> blocks. Future hardening:
//     refactor pages to externalize inline scripts/styles and tighten the
//     CSP to remove 'unsafe-inline'.
//   - SEC-6 fold: scrubbed full-submission PII from the two KV-write-failure
//     console.error calls (handleApply ~line 124, handleLoop ~line 198).
//     Previous behavior logged the entire submission object on KV failure,
//     including name / email / role / task body / cf country & city for
//     applications and email / userAgent for loop signups. New behavior
//     logs the error message plus a minimal { id, email } or { email }
//     traceability tuple. Surfaced by SEC-6 audit (s45-b).
//   - Removed two TODO-flagged diagnostic blocks in sendEmail() that logged
//     the Resend API key fingerprint (length + first 4 + last 2 chars) and
//     the Resend response body (up to 500 chars) on every email send. Both
//     were left over from debugging a Resend connectivity issue that has
//     since been resolved. Cloudflare logs are no longer leaking either
//     fingerprint material or response payloads.
//   - SEC-3 hardening: name field is now stripped of CR/LF/Unicode line
//     separators (U+2028, U+2029) at intake. This closes a low-severity
//     header injection vector where a crafted name containing newlines
//     could in principle inject headers into the notification email's
//     subject line ([apply] {name} — {role}). The other potentially-
//     header-bound user input (email) was already validated by EMAIL_RE
//     which rejects whitespace, so no change needed there.

const FROM = 'dan@tavernos.ai';
const REPLY_TO = 'dan@tavernos.ai';
const DEFAULT_NOTIFY = 'dan@tavernos.ai';
const DEFAULT_CALENDLY = 'https://calendly.com/dan-tavernos/30min';

const ALLOWED_ROLES = new Set([
  'Operations / COO',
  'Consultant or advisor',
  'Agency or studio owner',
  'Sales or revenue ops',
  'In-house team lead',
  'Founder / CEO',
  'Other',
]);
const ALLOWED_SCALES = new Set(['', '1–2', '3–5', '6–10', '11+']);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default {
  async fetch(request, env, ctx) {
    return applyHeaders(await handle(request, env, ctx));
  },
};

async function handle(request, env, ctx) {
  const url = new URL(request.url);

  if (url.pathname === '/api/apply' && request.method === 'POST') {
    return handleApply(request, env, ctx);
  }
  if (url.pathname === '/api/loop' && request.method === 'POST') {
    return handleLoop(request, env, ctx);
  }
  // Anything else → static assets (the /apply page, /access, etc.)
  return env.ASSETS.fetch(request);
}

// ── Security headers (SEC-4) ───────────────────────────────────────────

const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join('; ');

const PERMISSIONS_POLICY = [
  'camera=()',
  'microphone=()',
  'geolocation=()',
  'payment=()',
  'usb=()',
  'interest-cohort=()',
].join(', ');

function applyHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', PERMISSIONS_POLICY);
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');
  headers.set('Content-Security-Policy', CSP);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// ── /api/apply ─────────────────────────────────────────────────────────

async function handleApply(request, env, ctx) {
  const isJson = (request.headers.get('content-type') || '').includes('application/json');

  let data;
  try {
    data = isJson
      ? await request.json()
      : Object.fromEntries(await request.formData());
  } catch (err) {
    return badRequest(isJson, 'Could not read submission.');
  }

  // Honeypot — silent success if filled
  if (str(data.website)) {
    return ok(isJson, { name: '' });
  }

  const name = stripCRLF(data.name).slice(0, 200);
  const email = str(data.email).slice(0, 320).toLowerCase();
  const role = str(data.role).slice(0, 100);
  const task = str(data.task).slice(0, 5000);
  const scale = str(data.scale).slice(0, 20);

  const errors = [];
  if (!name) errors.push('name');
  if (!email || !EMAIL_RE.test(email)) errors.push('email');
  if (!role || !ALLOWED_ROLES.has(role)) errors.push('role');
  if (!task) errors.push('task');
  if (scale && !ALLOWED_SCALES.has(scale)) errors.push('scale');

  if (errors.length) {
    return badRequest(isJson, 'Some fields need attention.', errors);
  }

  const id = 'app_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  const submittedAt = new Date().toISOString();
  const submission = {
    type: 'apply',
    id,
    submittedAt,
    name,
    email,
    role,
    task,
    scale: scale || null,
    userAgent: request.headers.get('user-agent') || '',
    cf: {
      country: request.cf?.country || null,
      city: request.cf?.city || null,
    },
  };

  // KV first — the durable record. If this fails, log it but keep going;
  // the notification email is still useful and the data is in worker logs.
  try {
    await env.SUBMISSIONS.put(
      `apply:${submittedAt}:${id}`,
      JSON.stringify(submission)
    );
  } catch (err) {
    // SEC-6: log error + traceability tuple only, not the full submission.
    console.error('KV write failed (apply)', err?.message || err, { id, email });
  }

  // Emails fire-and-forget so the user gets their response immediately.
  ctx.waitUntil(sendApplyEmails(submission, env));

  return ok(isJson, submission);
}

async function sendApplyEmails(submission, env) {
  const calendlyUrl = env.CALENDLY_URL || DEFAULT_CALENDLY;
  const notifyEmail = env.NOTIFY_EMAIL || DEFAULT_NOTIFY;
  const firstName = (submission.name.split(/\s+/)[0] || '').trim();
  const greeting = firstName ? `Hey ${firstName},` : 'Hey there,';
  const byDay = dayInTwoDays();

  // 1. Confirmation to applicant
  await sendEmail(env, {
    from: FROM,
    to: submission.email,
    replyTo: REPLY_TO,
    subject: 'Got it — your TavernOS application',
    text: confirmationText({ greeting, byDay, calendlyUrl }),
    html: confirmationHtml({ greeting, byDay, calendlyUrl }),
  });

  // 2. Notification to Dan — Reply-To is the applicant's email,
  //    so hitting reply in Gmail goes straight to them.
  await sendEmail(env, {
    from: FROM,
    to: notifyEmail,
    replyTo: submission.email,
    subject: `[apply] ${submission.name} — ${submission.role}`,
    text: notificationText(submission),
  });
}

// ── /api/loop ──────────────────────────────────────────────────────────

async function handleLoop(request, env, ctx) {
  const isJson = (request.headers.get('content-type') || '').includes('application/json');

  let data;
  try {
    data = isJson
      ? await request.json()
      : Object.fromEntries(await request.formData());
  } catch (err) {
    return badRequest(isJson, 'Could not read submission.');
  }

  if (str(data.website)) {
    return ok(isJson, {});
  }

  const email = str(data.email).slice(0, 320).toLowerCase();
  if (!email || !EMAIL_RE.test(email)) {
    return badRequest(isJson, 'Valid email needed.', ['email']);
  }

  const submittedAt = new Date().toISOString();
  const submission = {
    type: 'loop',
    submittedAt,
    email,
    userAgent: request.headers.get('user-agent') || '',
  };

  try {
    await env.SUBMISSIONS.put(
      `loop:${submittedAt}:${email}`,
      JSON.stringify(submission)
    );
  } catch (err) {
    // SEC-6: log error + traceability tuple only, not the full submission.
    console.error('KV write failed (loop)', err?.message || err, { email });
  }

  ctx.waitUntil(sendEmail(env, {
    from: FROM,
    to: env.NOTIFY_EMAIL || DEFAULT_NOTIFY,
    replyTo: email,
    subject: `[loop] ${email}`,
    text: `${email}\n\n—\nSubmitted: ${submittedAt}`,
  }));

  return ok(isJson, submission);
}

// ── Resend ─────────────────────────────────────────────────────────────

async function sendEmail(env, msg) {
  if (!env.RESEND_API_KEY) {
    console.log('RESEND_API_KEY not set — would have sent:', JSON.stringify({
      to: msg.to,
      subject: msg.subject,
    }));
    return null;
  }

  // Log the call without exposing payload or key material. The metadata
  // (recipient + subject) is in the KV record already; this just confirms
  // the send actually fired.
  console.log(`Calling Resend: to=${msg.to} subject="${msg.subject}"`);

  const body = {
    from: msg.from,
    to: [msg.to],
    subject: msg.subject,
    text: msg.text,
  };
  if (msg.html) body.html = msg.html;
  if (msg.replyTo) body.reply_to = msg.replyTo;

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    // Only log the response on failure. On success, no payload reaches
    // Cloudflare logs. On failure, we log the body so you can debug — by
    // definition something is already broken at that point.
    if (!res.ok) {
      const responseText = await res.text();
      console.error(`Resend ${res.status}: ${responseText} | from=${msg.from} to=${msg.to} subject=${msg.subject}`);
    }
    return res;
  } catch (err) {
    console.error('Resend fetch threw', err && err.message ? err.message : err);
    return null;
  }
}

// ── Response helpers ───────────────────────────────────────────────────

function ok(isJson, payload) {
  if (isJson) {
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  return new Response(htmlConfirmationPage(payload), {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function badRequest(isJson, message, fields) {
  if (isJson) {
    return new Response(JSON.stringify({ ok: false, error: message, fields: fields || [] }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  return new Response(htmlErrorPage(message), {
    status: 400,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function str(v) { return (v == null ? '' : String(v)).trim(); }

// Strip CR, LF, and Unicode line separators (U+2028, U+2029) from any
// user-submitted string that may end up in an email header field.
// Superset of str(): same null-safe coercion + .trim(), plus the CRLF
// substitution. Routes a 'Hacker\r\nBcc: x@evil.com' submission to
// 'Hacker Bcc: x@evil.com' before it can become a malformed header.
function stripCRLF(s) {
  return String(s == null ? '' : s).replace(/[\r\n\u2028\u2029]+/g, ' ').trim();
}

function dayInTwoDays() {
  const d = new Date();
  d.setDate(d.getDate() + 2);
  return d.toLocaleDateString('en-US', { weekday: 'long' });
}

// ── Email bodies ───────────────────────────────────────────────────────

function confirmationText({ greeting, byDay, calendlyUrl }) {
  return `${greeting}

Your application landed. I'll write back within 48 hours to find a time for a 30-minute install call.

What that looks like: we get the system on your laptop, walk through the task you described, let it run. No demo deck, no pitch — you'll be using it.

If you want to grab a slot directly: ${calendlyUrl}

A couple of things worth knowing:

- Trials run in waves. If your task fits the current cohort, we can start this week. If not, I'll be straight about timing.
- Two weeks, on your laptop, my API key. You bring real work.

If you don't hear from me by ${byDay}, reply to this email — it didn't get to me.

— Dan

dan@tavernos.ai · tavernos.ai
`;
}

function confirmationHtml({ greeting, byDay, calendlyUrl }) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Got it — your TavernOS application</title></head>
<body style="margin:0;padding:24px;background:#F2EBDD;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#0E1A2B;line-height:1.55;font-size:16px;">
  <div style="max-width:520px;margin:0 auto;">
    <p style="margin:0 0 18px;">${escHtml(greeting)}</p>
    <p style="margin:0 0 18px;">Your application landed. I'll write back within 48 hours to find a time for a 30-minute install call.</p>
    <p style="margin:0 0 18px;">What that looks like: we get the system on your laptop, walk through the task you described, let it run. No demo deck, no pitch &mdash; you'll be using it.</p>
    <p style="margin:0 0 24px;">If you want to grab a slot directly: <a href="${escAttr(calendlyUrl)}" style="color:#1F7A78;text-decoration:underline;">${escHtml(calendlyUrl)}</a></p>
    <p style="margin:0 0 8px;">A couple of things worth knowing:</p>
    <ul style="margin:0 0 24px;padding-left:20px;">
      <li style="margin-bottom:6px;">Trials run in waves. If your task fits the current cohort, we can start this week. If not, I'll be straight about timing.</li>
      <li>Two weeks, on your laptop, my API key. You bring real work.</li>
    </ul>
    <p style="margin:0 0 28px;">If you don't hear from me by ${escHtml(byDay)}, reply to this email &mdash; it didn't get to me.</p>
    <p style="margin:0 0 4px;">&mdash; Dan</p>
    <p style="margin:0;font-family:'SF Mono',Menlo,Monaco,Consolas,monospace;font-size:12px;color:#2A3A52;">
      <a href="mailto:dan@tavernos.ai" style="color:#2A3A52;text-decoration:underline;">dan@tavernos.ai</a> &middot; tavernos.ai
    </p>
  </div>
</body></html>`;
}

function notificationText(s) {
  const scaleSuffix = s.scale ? ` · ${s.scale}` : '';
  const locLine = s.cf?.country ? `From: ${s.cf.city ? s.cf.city + ', ' : ''}${s.cf.country}\n` : '';
  return `${s.name}
${s.email}
${s.role}${scaleSuffix}

Task:
${s.task}

—
Submitted: ${s.submittedAt}
ID: ${s.id}
${locLine}`;
}

// ── No-JS fallback pages ───────────────────────────────────────────────

function htmlConfirmationPage(submission) {
  const firstName = submission.name ? String(submission.name).split(/\s+/)[0] : '';
  const heading = firstName ? `Got it, ${escHtml(firstName)}.` : 'Got it.';
  const byDay = dayInTwoDays();
  return brandedShell({
    title: 'Got it — TavernOS',
    body: `
      <h1>${heading}</h1>
      <p>Your application is in. I'll email you within 48 hours to find a time for a 30-minute install call.</p>
      <p>If you don't hear back by <strong>${escHtml(byDay)}</strong>, reply to the confirmation email &mdash; it didn't get to me.</p>
      <p class="meta">&mdash; Dan</p>
    `,
  });
}

function htmlErrorPage(message) {
  return brandedShell({
    title: 'Hmm — TavernOS',
    body: `
      <h1>Hmm.</h1>
      <p>${escHtml(message)}</p>
      <p><a href="/apply">Back to the application</a></p>
    `,
  });
}

function brandedShell({ title, body }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escHtml(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif&family=IBM+Plex+Sans:wght@400;500&family=IBM+Plex+Mono:wght@400&display=swap" rel="stylesheet">
<style>
  body { margin:0; background:#F2EBDD; color:#0E1A2B; font-family:'IBM Plex Sans',system-ui,sans-serif; font-size:16px; line-height:1.55; }
  .wrap { max-width:520px; margin:0 auto; padding:64px 24px; }
  .card { background:#0F1115; color:#EFE8D8; border-radius:10px; padding:32px 24px; box-shadow:0 14px 44px -14px rgba(14,26,43,0.28); }
  h1 { font-family:'Instrument Serif',Georgia,serif; font-weight:400; font-size:32px; margin:0 0 16px; line-height:1.15; }
  p { margin:0 0 14px; font-size:15px; }
  .meta { font-family:'IBM Plex Mono',monospace; font-size:12px; color:#B8AE97; margin-top:24px; padding-top:20px; border-top:1px solid #2A2E36; }
  a { color:#5BE3D7; }
</style>
</head>
<body><div class="wrap"><div class="card">${body}</div></div></body>
</html>`;
}

function escHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
}
function escAttr(s) { return escHtml(s); }
