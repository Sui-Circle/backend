import { Test, TestingModule } from '@nestjs/testing';
import { SuiService } from './sui.service';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';

// Mock the Sui client
jest.mock('@mysten/sui/client', () => ({
  SuiClient: jest.fn().mockImplementation(() => ({
    executeTransactionBlock: jest.fn(),
  })),
  getFullnodeUrl: jest.fn().mockReturnValue('https://fullnode.testnet.sui.io:443'),
}));

// Mock zkLogin functions
jest.mock('@mysten/sui/zklogin', () => ({
  getZkLoginSignature: jest.fn().mockReturnValue('mock-zklogin-signature'),
}));

describe('SuiService', () => {
  let service: SuiService;
  let mockSuiClient: any;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SuiService],
    }).compile();

    service = module.get<SuiService>(SuiService);
    mockSuiClient = (service as any).suiClient;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('uploadFileWithZkLogin - User Pays Gas', () => {
    const mockZkLoginParams = {
      ephemeralKeyPair: {
        keypair: new Ed25519Keypair(),
        maxEpoch: 1000,
        randomness: 'test-randomness',
      },
      zkLoginProof: {
        proofPoints: {
          a: ['test-a'],
          b: [['test-b']],
          c: ['test-c'],
        },
        issBase64Details: {
          value: 'test-value',
          indexMod4: 0,
        },
        headerBase64: 'test-header',
      },
      jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiZ2l0aHViLmNvbSIsImV4cCI6OTk5OTk5OTk5OX0.test',
      userSalt: 'test-salt',
    };

    it('should execute transaction with user paying gas fees', async () => {
      // Mock successful transaction execution
      mockSuiClient.executeTransactionBlock.mockResolvedValue({
        digest: 'test-transaction-digest',
        effects: {
          status: {
            status: 'success',
          },
        },
      });

      const result = await service.uploadFileWithZkLogin(
        'test-cid',
        'test-file.txt',
        1024,
        mockZkLoginParams
      );

      expect(result).toBe('test-transaction-digest');
      expect(mockSuiClient.executeTransactionBlock).toHaveBeenCalledWith(
        expect.objectContaining({
          options: expect.objectContaining({
            showEffects: true,
            showEvents: true,
            showObjectChanges: true,
          }),
        })
      );
    });

    it('should throw error when user has insufficient gas', async () => {
      // Mock failed transaction execution due to insufficient gas
      mockSuiClient.executeTransactionBlock.mockResolvedValue({
        digest: 'test-transaction-digest',
        effects: {
          status: {
            status: 'failure',
            error: 'Insufficient gas',
          },
        },
      });

      await expect(
        service.uploadFileWithZkLogin(
          'test-cid',
          'test-file.txt',
          1024,
          mockZkLoginParams
        )
      ).rejects.toThrow('Transaction failed: Insufficient gas');
    });
  });
});
