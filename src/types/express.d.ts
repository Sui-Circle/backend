import { Multer } from 'multer';

declare global {
  namespace Express {
    namespace Multer {
      interface File extends globalThis.Multer.File {
        buffer: Buffer;
        originalname: string;
        encoding: string;
        mimetype: string;
        size: number;
        destination?: string;
        filename?: string;
        path?: string;
        fieldname: string;
      }
    }
  }
}