import type { FastifyReply } from 'fastify';
import type {} from '@fastify/view'; // reply.view(): Nest registers the plugin in setViewEngine
import { env } from '../config/env';

/** Values every page's layout reads. */
export interface PageBase {
  title: string;
  providerName: string;
}

const base = (title: string): PageBase => ({ title, providerName: env.PROVIDER_NAME });

/**
 * Renders a page. Every page here belongs to one sign-in attempt and carries a challenge or a
 * CSRF token, so none of them is ever cached (auth-plan.md section 7.4).
 */
export function render(
  reply: FastifyReply,
  template: string,
  title: string,
  data: Record<string, unknown> = {},
  status = 200,
): FastifyReply {
  return reply
    .status(status)
    .header('cache-control', 'no-store')
    .view(template, { ...base(title), ...data });
}

/**
 * The error screen (section 7.2). It explains and links home; it never redirects back to the
 * client, because a request that failed validation is exactly the one whose redirect cannot be
 * trusted.
 */
export function renderError(
  reply: FastifyReply,
  status: number,
  heading: string,
  detail: string,
): FastifyReply {
  return render(reply, 'error', heading, { heading, detail }, status);
}

/** A 303, so the browser follows a form POST with a GET. */
export function redirect(reply: FastifyReply, to: string): FastifyReply {
  return reply.status(303).header('cache-control', 'no-store').redirect(to, 303);
}
