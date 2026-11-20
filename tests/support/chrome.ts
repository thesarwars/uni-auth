import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * A real Chrome, headless, driven over the DevTools protocol: for the checks that need a page
 * laid out - contrast as drawn, reflow at 320px, focus moved by the Tab key. Nothing to install:
 * it uses the Chrome on the machine (CHROME_PATH, or the usual places), and the suite skips these
 * checks when there is none.
 */

const CANDIDATES = [
  process.env.CHROME_PATH,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
].filter((p): p is string => !!p);

export const chromePath = (): string | null => CANDIDATES.find((p) => existsSync(p)) ?? null;

export interface Chrome {
  send<T = any>(method: string, params?: Record<string, unknown>): Promise<T>;
  /** Calls `handler` with each event of that name, until the returned function is called. */
  on(method: string, handler: (params: any) => void): () => void;
  /** The next event of that name, or an error after `ms`. */
  once<T = any>(method: string, ms?: number): Promise<T>;
  evaluate<T = any>(expression: string): Promise<T>;
  close(): Promise<void>;
}

export async function launchChrome(): Promise<Chrome> {
  const path = chromePath();
  if (!path) throw new Error('No Chrome found; set CHROME_PATH');
  const dir = mkdtempSync(join(tmpdir(), 'uni-auth-chrome-'));
  const port = 9400 + Math.floor(Math.random() * 400);
  const proc: ChildProcess = spawn(
    path,
    [
      '--headless=new',
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      '--hide-scrollbars',
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${dir}`,
      'about:blank',
    ],
    { stdio: 'ignore' },
  );

  let targets: { type: string; webSocketDebuggerUrl: string }[] = [];
  for (let i = 0; i < 100 && !targets.some((t) => t.type === 'page'); i++) {
    await new Promise((r) => setTimeout(r, 100));
    try {
      targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
    } catch {
      // not listening yet
    }
  }
  const page = targets.find((t) => t.type === 'page');
  if (!page) {
    proc.kill();
    throw new Error('Chrome did not start');
  }
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true });
    ws.addEventListener('error', reject, { once: true });
  });
  let id = 0;
  const waiting = new Map<number, (msg: any) => void>();
  const listeners = new Set<{ method: string; handler: (params: any) => void }>();
  ws.addEventListener('message', (e) => {
    const msg = JSON.parse(String(e.data));
    if (msg.id && waiting.has(msg.id)) {
      waiting.get(msg.id)!(msg);
      waiting.delete(msg.id);
    } else if (msg.method) {
      for (const l of [...listeners]) if (l.method === msg.method) l.handler(msg.params);
    }
  });
  const on = (method: string, handler: (params: any) => void) => {
    const l = { method, handler };
    listeners.add(l);
    return () => void listeners.delete(l);
  };
  const once = <T>(method: string, ms = 15_000) =>
    new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        off();
        reject(new Error(`timed out waiting for ${method}`));
      }, ms);
      const off = on(method, (p) => {
        clearTimeout(timer);
        off();
        resolve(p);
      });
    });

  const send = <T>(method: string, params: Record<string, unknown> = {}) =>
    new Promise<T>((resolve, reject) => {
      const n = ++id;
      waiting.set(n, (msg) =>
        msg.error ? reject(new Error(`${method}: ${msg.error.message}`)) : resolve(msg.result),
      );
      ws.send(JSON.stringify({ id: n, method, params }));
    });
  const evaluate = async <T>(expression: string) => {
    const r = await send<{ result: { value: T }; exceptionDetails?: { text: string } }>(
      'Runtime.evaluate',
      { expression, awaitPromise: true, returnByValue: true },
    );
    if (r.exceptionDetails) throw new Error(`evaluate: ${JSON.stringify(r.exceptionDetails)}`);
    return r.result.value;
  };

  return {
    send,
    on,
    once,
    evaluate,
    async close() {
      ws.close();
      proc.kill();
      await new Promise((r) => setTimeout(r, 200));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
