import { ArgumentsHost, Catch, HttpException, Logger, type ExceptionFilter } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { HandledChallenge, UnknownChallenge } from '../hydra/hydra-admin.service';
import { CsrfRejected } from './csrf.guard';
import { redirect, renderError } from './pages';

/**
 * Every failure becomes a page, never a JSON body: the reader is a person in a browser.
 */
@Catch()
export class PageErrorFilter implements ExceptionFilter {
  private readonly log = new Logger('PageErrorFilter');

  catch(exception: unknown, host: ArgumentsHost): void {
    const reply = host.switchToHttp().getResponse<FastifyReply>();

    if (exception instanceof HandledChallenge) {
      void redirect(reply, exception.redirectTo);
      return;
    }
    if (exception instanceof UnknownChallenge) {
      void renderError(
        reply,
        400,
        'This sign-in link has expired',
        'Go back to the app you were using and start signing in again.',
      );
      return;
    }
    if (exception instanceof CsrfRejected) {
      void renderError(
        reply,
        403,
        'This page has expired',
        'Go back to the app you were using and start signing in again.',
      );
      return;
    }
    if (exception instanceof HttpException && exception.getStatus() < 500) {
      void renderError(
        reply,
        exception.getStatus(),
        'Something was wrong with that request',
        'Go back to the app you were using and try again.',
      );
      return;
    }

    this.log.error(exception instanceof Error ? (exception.stack ?? exception.message) : exception);
    void renderError(
      reply,
      exception instanceof HttpException ? exception.getStatus() : 500,
      'Something went wrong on our side',
      'Nothing has changed on your account. Please try again in a moment.',
    );
  }
}
