import { Injectable, Logger } from '@nestjs/common';
import { HydraAdmin } from '../hydra/hydra-admin.service';

/**
 * Ends at Hydra the sessions uni-auth has already revoked in its own database (auth-plan.md
 * section 12.2, part 7). Revoking a login session by sid makes Hydra send each client's
 * back-channel logout, which is how an API that trusts uni-auth learns to refuse the session's
 * access tokens at once.
 *
 * Called after the revoking transaction commits. The database is the truth: if Hydra cannot be
 * reached, the refresh hook still refuses the session's refresh tokens and single sign-on still
 * refuses the session, so what is lost is only the early end of access tokens already issued -
 * fifteen minutes at most.
 */
@Injectable()
export class SessionEnder {
  private readonly logger = new Logger(SessionEnder.name);

  constructor(private readonly hydra: HydraAdmin) {}

  async endAtHydra(sids: readonly string[]): Promise<void> {
    for (const sid of sids) {
      try {
        await this.hydra.revokeLoginSession(sid);
      } catch (err) {
        this.logger.warn(`could not end session ${sid} at Hydra: ${(err as Error).message}`);
      }
    }
  }
}
