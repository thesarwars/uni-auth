import { Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { CsrfGuard } from './common/csrf.guard';
import { PageErrorFilter } from './common/page-error.filter';
import { ConsentController } from './flows/consent.controller';
import { LoginController } from './flows/login.controller';
import { LogoutController } from './flows/logout.controller';
import { SystemController } from './flows/system.controller';
import { HydraAdmin } from './hydra/hydra-admin.service';

@Module({
  controllers: [LoginController, ConsentController, LogoutController, SystemController],
  providers: [
    HydraAdmin,
    { provide: APP_GUARD, useClass: CsrfGuard },
    { provide: APP_FILTER, useClass: PageErrorFilter },
  ],
})
export class AppModule {}
