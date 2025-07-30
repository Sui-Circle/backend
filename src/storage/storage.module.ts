import { Module } from '@nestjs/common';
import { SealService } from './seal/seal.service';
import { WalrusService } from './walrus/walrus.service';

@Module({
  providers: [SealService, WalrusService],
  exports: [SealService, WalrusService]
})
export class StorageModule {}
