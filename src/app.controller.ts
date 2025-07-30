import { Controller, Get, Delete, Headers, UseGuards, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { AppService } from './app.service';
import { FileService } from './file/file.service';
import { AuthGuard, CurrentUser } from './auth/auth.guard';

@Controller()
export class AppController {
  private readonly logger = new Logger(AppController.name);

  constructor(
    private readonly appService: AppService,
    private readonly fileService: FileService
  ) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  /**
   * List user's files - authenticated endpoint
   * GET /files
   */
  @Get('files')
  @UseGuards(AuthGuard)
  async listUserFiles(
    @Headers('authorization') authorization: string,
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.fileService.listUserFiles(token);

      return {
        success: result.success,
        files: result.files, // Direct files array for compatibility
        data: {
          files: result.files,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to list user files', error);
      throw new HttpException(
        'Failed to list user files',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * List user's files without authentication (for testing)
   * GET /files-test
   */
  @Get('files-test')
  async listUserFilesTest() {
    try {
      const result = await this.fileService.listUserFilesNoAuth();

      return {
        success: result.success,
        files: result.files, // Direct files array for compatibility
        data: {
          files: result.files,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to list user files (test)', error);
      throw new HttpException(
        'Failed to list user files',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Delete all user files - authenticated endpoint
   * DELETE /files
   */
  @Delete('files')
  @UseGuards(AuthGuard)
  async clearUserFiles(
    @Headers('authorization') authorization: string,
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.fileService.clearUserFiles(token);

      return {
        success: result.success,
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to clear user files', error);
      throw new HttpException(
        'Failed to clear user files',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Delete all user files without authentication (for testing)
   * DELETE /files-test
   */
  @Delete('files-test')
  async clearUserFilesTest() {
    try {
      const result = await this.fileService.clearUserFilesNoAuth();

      return {
        success: result.success,
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to clear user files (test)', error);
      throw new HttpException(
        'Failed to clear user files',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }
}
