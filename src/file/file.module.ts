import { Module } from '@nestjs/common';
import { FileController } from './file.controller';
import { FileService } from './file.service';
import { SuiModule } from '../sui/sui.module';
import { AuthModule } from '../auth/auth.module';
import { StorageModule } from '../storage/storage.module';
import { AccessControlModule } from '../access-control/access-control.module';

@Module({
  imports: [SuiModule, AuthModule, StorageModule, AccessControlModule],
  controllers: [FileController],
  providers: [FileService],
  exports: [FileService],
})
export class FileModule {}
