import { Module } from '@nestjs/common';
import { AccessControlController } from './access-control.controller';
import { AccessControlService } from './access-control.service';
import { SuiModule } from '../sui/sui.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [SuiModule, AuthModule],
  controllers: [AccessControlController],
  providers: [AccessControlService],
  exports: [AccessControlService],
})
export class AccessControlModule {}
