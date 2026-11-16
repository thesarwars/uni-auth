import { Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { redirect } from '../common/pages';
import { Challenge, confirmSubject, parse } from '../flows/login.controller';
import { SignIn, type Seen } from '../flows/sign-in.service';
import { HydraAdmin } from '../hydra/hydra-admin.service';
import { IdentityRepository } from '../identity/identity.repository';
import { Passkeys } from './passkeys.service';

const Form = z.object({
  login_challenge: Challenge,
  credential: z.string().min(2).max(40_000),
});

/** The passkey ceremony a login challenge's screens share: the identifier and password screens. */
export const signInFlow = (challenge: string): string => `login:${challenge}`;

/**
 * Signing in with a passkey and nothing else (account-plan.md AC-D5): the identifier screen
 * offers the member's passkeys through the browser's autofill, and a "Sign in with a passkey"
 * button (public/webauthn.js). A passkey checked with the member's fingerprint, face or PIN is
 * two factors by itself, so the sign-in is aal2 and skips the second step.
 */
@Controller('login/passkey')
export class PasskeySignInController {
  constructor(
    private readonly hydra: HydraAdmin,
    private readonly identities: IdentityRepository,
    private readonly passkeys: Passkeys,
    private readonly signIn: SignIn,
  ) {}

  /** navigator.credentials.get options, with a challenge for this sign-in. */
  @Get('options')
  async options(@Query('login_challenge') raw: unknown, @Res() reply: FastifyReply) {
    const challenge = parse(Challenge, raw);
    const options = await this.passkeys.signInOptions(signInFlow(challenge));
    return reply.header('cache-control', 'no-store').send(options);
  }

  @Post()
  async submit(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const form = parse(Form, body);
    const challenge = form.login_challenge;
    const done = await this.signIn.finished(challenge);
    if (done) {
      await redirect(reply, done);
      return;
    }
    const request = await this.hydra.getLogin(challenge);
    const seen: Seen = { ip: req.ip, userAgent: req.headers['user-agent'] ?? null };
    // "Confirm it's you" for one member: only their passkey confirms it.
    const confirming = confirmSubject(request);
    const used = await this.passkeys.verifySignIn(signInFlow(challenge), form.credential, {
      identityId: confirming ?? undefined,
      requireUserVerification: true,
    });

    if ('reason' in used) {
      if (used.reason !== 'invalid') {
        await this.identities.event({
          kind: 'sign_in',
          outcome: 'failure',
          identityId: used.identityId,
          clientId: request.client.client_id,
          credentialKind: 'passkey',
          detail: {
            reason: used.reason === 'suspended' ? 'suspended' : 'passkey_refused',
            ...(used.reason === 'refused' ? { why: used.why } : {}),
          },
          ...seen,
        });
      }
      await redirect(
        reply,
        `/login?login_challenge=${encodeURIComponent(challenge)}&passkey=${
          used.reason === 'suspended' ? 'suspended' : 'failed'
        }`,
      );
      return;
    }

    await this.signIn.accept(reply, challenge, request, seen, {
      identityId: used.identityId,
      credentialId: used.credentialId,
      credentialKind: 'passkey',
      // RFC 8176: the key, and more than one factor (the device, and the member's verification).
      amr: [used.method, 'mfa'],
      detail: { method: 'passkey' },
    });
  }
}
