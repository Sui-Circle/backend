import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { FileModule } from './file/file.module';
import { SuiModule } from './sui/sui.module';
import { StorageModule } from './storage/storage.module';
import { AuthModule } from './auth/auth.module';
import { AccessControlModule } from './access-control/access-control.module';

@Module({
  imports: [FileModule, SuiModule, StorageModule, AuthModule, AccessControlModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
