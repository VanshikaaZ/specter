import { createHash, timingSafeEqual } from 'node:crypto';
import { supabaseAdmin } from '@/lib/supabase';

// Context a monitored scan carries through to /run, so the alert can say
// what changed. Manual scans from the UI pass none and never alert.
export interface MonitorContext {
  source: 'github-push' | 'cron';
  commitSha?: string;
  commitMessage?: string;
  pusher?: string;
  ref?: string;
}

// How long the start route waits for /run to accept the trigger before moving on
const TRIGGER_WAIT_MS = 3000;

const isProd = () => process.env.NODE_ENV === 'production';

/**
 * Shared secret for the start → run hop. Returns null when production has no
 * INTERNAL_SECRET, so callers fail closed instead of using a public default.
 * Development keeps a fallback so local runs work without configuration.
 */
export function getInternalSecret(): string | null {
  const secret = process.env.INTERNAL_SECRET;
  if (secret) return secret;
  return isProd() ? null : 'specter-internal';
}

/** Constant-time string compare. Hashing first hides length differences. */
export function safeEqual(a: string | null | undefined, b: string): boolean {
  if (typeof a !== 'string') return false;
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

/**
 * Origin that /run is called on, which also receives x-internal-secret. The
 * request's own origin comes from the Host header, so it is attacker-controlled
 * and only used outside production.
 */
export function appOrigin(requestOrigin?: string): string {
  const configured = process.env.NEXT_PUBLIC_APP_URL?.trim().replace(/\/+$/, '');
  if (configured) return configured;
  if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`;
  if (!isProd()) return requestOrigin || 'http://localhost:3000';
  return 'https://specter-seven.vercel.app';
}

/**
 * Creates a scan row and triggers /run for it. Always a fresh scan: callers
 * that want the 6h cache check it themselves before calling this.
 */
export async function createAndRunScan(
  owner: string,
  repo: string,
  origin: string,
  monitor?: MonitorContext,
): Promise<{ scanId: string } | { error: string }> {
  // Checked before the insert so a misconfigured server leaves no orphan row
  const internalSecret = getInternalSecret();
  if (!internalSecret) {
    console.error('INTERNAL_SECRET is not set in production; refusing to start a scan');
    return { error: 'Server misconfigured' };
  }

  const normalizedUrl = `https://github.com/${owner}/${repo}`.toLowerCase();

  const { data: scan, error } = await supabaseAdmin
    .from('scans')
    .insert({ repo_url: normalizedUrl, repo_owner: owner, repo_name: repo, status: 'scanning' })
    .select()
    .single();

  if (error || !scan) {
    console.error('Supabase insert failed:', error);
    return { error: error?.message ?? 'Failed to create scan' };
  }

  // Trigger the run route — AWAITED with a short timeout.
  // This guarantees the request actually leaves before this function
  // terminates. We don't wait for the full scan, just for /run to
  // accept the trigger (it runs the real work independently afterward).
  try {
    const res = await fetch(`${origin}/api/scan/${scan.id}/run`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-internal-secret': internalSecret,
      },
      body: JSON.stringify({ monitor: monitor ?? null }),
      signal: AbortSignal.timeout(TRIGGER_WAIT_MS),
    });
    // fetch does not throw on an HTTP error, so a rejected trigger (wrong
    // INTERNAL_SECRET, 500 from /run) has to be checked for explicitly.
    if (!res.ok) console.error(`Run route rejected scan ${scan.id}: HTTP ${res.status}`);
  } catch (err) {
    const timedOut = err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');
    if (timedOut) {
      // Expected: /run does the whole scan inside this request, which takes far
      // longer than we wait. Not an error; it keeps running and the client polls.
      console.debug(`Run route for scan ${scan.id} still working after ${TRIGGER_WAIT_MS} ms (expected)`);
    } else {
      // Real failure to reach /run (connection refused, DNS, wrong origin).
      // The scan row exists and will stay "scanning"; this line is how we
      // catch that in Vercel logs.
      console.error('Failed to trigger run route:', err);
    }
    // Don't fail the whole request either way: the frontend polls the row.
  }

  return { scanId: scan.id };
}
