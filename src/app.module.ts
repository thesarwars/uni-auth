import { Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { CsrfGuard } from './common/csrf.guard';
import { PageErrorFilter } from './common/page-error.filter';
import { ConsentController } from './flows/consent.controller';
import { LoginController } from './flows/login.controller';
import { LogoutController } from './flows/logout.controller';
import { SystemController } from './flows/system.controller';
import { OtpService } from './credentials/otp.service';
import { PasswordService } from './credentials/password.service';
import { Database } from './db/database.service';
import { EmailSender } from './delivery/email.sender';
import { Outbox } from './delivery/outbox';
import { WhatsAppSender } from './delivery/whatsapp.sender';
import { HydraAdmin } from './hydra/hydra-admin.service';
import { IdentityRepository } from './identity/identity.repository';
import { Throttle } from './throttle/throttle.service';

@Module({
  controllers: [LoginController, ConsentController, LogoutController, SystemController],
  providers: [
    HydraAdmin,
    Database,
    IdentityRepository,
    PasswordService,
    OtpService,
    Outbox,
    EmailSender,
    WhatsAppSender,
    Throttle,
    { provide: APP_GUARD, useClass: CsrfGuard },
    { provide: APP_FILTER, useClass: PageErrorFilter },
  ],
})
export class AppModule {}
