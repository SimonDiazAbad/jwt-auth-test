import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dtos';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post('/local/signup')
  @HttpCode(HttpStatus.CREATED)
  async localSignup(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.localSignup(dto);
  }

  @Post('/local/signin')
  @HttpCode(HttpStatus.OK)
  async localSignin(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.localSignin(dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  @Post('/local/logout')
  async logout(@Req() req: Request) {
    const user: any = req.user;
    console.log(user.sub);
    return this.authService.logout(user.sub);
  }

  @Post('/local/refresh')
  @UseGuards(AuthGuard('jwt-refresh'))
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request) {
    const user: any = req.user;
    return this.authService.refreshTokens(user.sub, user.refreshToken);
  }
}
