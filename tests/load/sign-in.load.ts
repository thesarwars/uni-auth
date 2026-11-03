/**
 * The sign-in load test (auth-plan.md section 12.2, part 8): concurrent members signing in with
 * a password through the whole redirect flow, against the real Hydra and a running login
 * application, timed step by step against NFR-1 (p95 < 300 ms, p99 < 800 ms per response).
 *
 *   npm run build && LOG_LEVEL=warn node dist/main.js          # the login application, built
 *   npm run load:sign-in                                       # VUS=20 DURATION=60 by default
 *
 * Each virtual user is its own member, so the per-identifier throttle never trips. A step that
 * follows redirects is timed as a whole and divided by its hops, so the per-response figure is
 * an average over the hops of that step. Exits non-zero on any error or a missed target.
 */
import { performance } from 'node:perf_hooks';
import {
  APP,
  HYDRA,
  authorizeUrl,
  browser,
  claims,
  exchange,
  formFields,
  pkce,
} from '../support/browser';
import { closeMembers, createMember, type Member } from '../support/members';

const VUS = Number(process.env.VUS ?? 20);
const DURATION_S = Number(process.env.DURATION ?? 60);
const P95_MS = 300;
const P99_MS = 800;

// A request that hangs counts as an error rather than stalling its virtual user.
const plainFetch = globalThis.fetch;
globalThis.fetch = (input, init) =>
  plainFetch(input, { ...init, signal: init?.signal ?? AbortSignal.timeout(15_000) });

type Step = 'authorize' | 'identify' | 'password' | 'to client' | 'token' | 'refresh';
const timings = new Map<Step, number[]>();
const errors: string[] = [];
let signIns = 0;

async function timed<T>(step: Step, hops: (r: T) => number, work: () => Promise<T>): Promise<T> {
  const t0 = performance.now();
  const r = await work();
  const per = (performance.now() - t0) / Math.max(1, hops(r));
  const list = timings.get(step) ?? [];
  for (let i = 0; i < Math.max(1, hops(r)); i += 1) list.push(per);
  timings.set(step, list);
  return r;
}

/** Follows redirects like the browser helper, counting the hops. */
async function follow(b: ReturnType<typeof browser>, url: string) {
  let current = url;
  for (let hops = 1; hops <= 12; hops += 1) {
    const hop = await b.get(current);
    if (!hop.location) return { url: current, hop, hops };
    if (!hop.location.startsWith(HYDRA) && !hop.location.startsWith(APP)) {
      return { url: hop.location, hop, hops };
    }
    current = hop.location;
  }
  throw new Error('too many redirects');
}

async function signIn(m: Member): Promise<void> {
  const b = browser();
  const { verifier, challenge } = pkce();
  const first = await timed(
    'authorize',
    (r) => r.hops,
    () => follow(b, authorizeUrl(challenge)),
  );
  if (!first.url.startsWith(`${APP}/login?`)) throw new Error(`authorize landed on ${first.url}`);
  const id = await timed(
    'identify',
    () => 1,
    () =>
      b.post(`${APP}/login`, {
        ...formFields(first.hop.html),
        action: 'identify',
        identifier: m.email,
      }),
  );
  const pw = await timed(
    'password',
    () => 1,
    () =>
      b.post(`${APP}/login`, { ...formFields(id.html), action: 'password', password: m.password }),
  );
  if (pw.status !== 303) throw new Error(`password answered ${pw.status}`);
  const back = await timed(
    'to client',
    (r) => r.hops,
    () => follow(b, pw.location!),
  );
  const code = new URL(back.url).searchParams.get('code');
  if (!code) throw new Error(`no code: ${back.url}`);
  const t = await timed(
    'token',
    () => 1,
    () => exchange(code, verifier),
  );
  if (t.status !== 200 || !claims(t.body.access_token).sid) throw new Error(`token ${t.status}`);
  const r = await timed(
    'refresh',
    () => 1,
    () =>
      fetch(`${HYDRA}/oauth2/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: 'gsn-web',
          refresh_token: t.body.refresh_token,
        }).toString(),
      }),
  );
  if (r.status !== 200) throw new Error(`refresh ${r.status}`);
  signIns += 1;
}

const pct = (sorted: number[], p: number) =>
  sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)] ?? 0;

async function main(): Promise<void> {
  const ready = await fetch(`${APP}/ready`).catch(() => null);
  if (!ready?.ok) throw new Error(`the login application is not ready at ${APP}`);
  const members: Member[] = [];
  for (let i = 0; i < VUS; i += 1) members.push(await createMember());
  console.log(`${VUS} members signing in for ${DURATION_S}s ...`);

  const until = Date.now() + DURATION_S * 1000;
  const progress = setInterval(
    () => console.log(`  ... ${signIns} sign-ins, ${errors.length} errors`),
    10_000,
  );
  const started = performance.now();
  await Promise.all(
    members.map(async (m) => {
      while (Date.now() < until) {
        await signIn(m).catch((err: Error) => errors.push(err.message));
      }
    }),
  );
  clearInterval(progress);
  const seconds = (performance.now() - started) / 1000;
  await closeMembers();

  const rows: string[][] = [['step', 'responses', 'p50 ms', 'p95 ms', 'p99 ms', 'max ms']];
  const all: number[] = [];
  for (const [step, list] of timings) {
    const s = [...list].sort((a, b) => a - b);
    all.push(...s);
    rows.push([step, String(s.length), ...[50, 95, 99, 100].map((p) => pct(s, p).toFixed(0))]);
  }
  all.sort((a, b) => a - b);
  rows.push([
    'every response',
    String(all.length),
    ...[50, 95, 99, 100].map((p) => pct(all, p).toFixed(0)),
  ]);
  const width = rows[0]!.map((_, i) => Math.max(...rows.map((r) => r[i]!.length)));
  for (const r of rows) console.log(r.map((c, i) => c.padEnd(width[i]!)).join('  '));
  console.log(
    `\n${signIns} sign-ins in ${seconds.toFixed(1)}s: ${(signIns / seconds).toFixed(1)}/s, ` +
      `${(all.length / seconds).toFixed(0)} responses/s, ${errors.length} errors`,
  );
  for (const e of [...new Set(errors)].slice(0, 5)) console.log(`  error: ${e}`);

  const missed = [
    errors.length > 0 && `${errors.length} errors`,
    pct(all, 95) >= P95_MS && `p95 ${pct(all, 95).toFixed(0)} ms >= ${P95_MS}`,
    pct(all, 99) >= P99_MS && `p99 ${pct(all, 99).toFixed(0)} ms >= ${P99_MS}`,
  ].filter(Boolean);
  console.log(missed.length ? `\nFAIL  ${missed.join('; ')}` : '\nPASS  NFR-1 held, no errors');
  process.exit(missed.length ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
