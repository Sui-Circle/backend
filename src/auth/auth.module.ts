import { Module, forwardRef } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { ZkLoginService } from './zklogin.service';
import { AuthService } from './auth.service';
import { SuiModule } from '../sui/sui.module';

@Module({
  imports: [forwardRef(() => SuiModule)],
  controllers: [AuthController],
  providers: [ZkLoginService, AuthService],
  exports: [ZkLoginService, AuthService],
})
export class AuthModule {}
