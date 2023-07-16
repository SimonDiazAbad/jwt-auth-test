import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { env } from 'process';
import { ConfigService } from '@nestjs/config';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly configService: ConfigService,
  ) {}

  @Get()
  getHello(): string {
    // return this.configService.get('AT_SECRET');
    return this.appService.getHello();
  }
}