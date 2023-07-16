import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dtos';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  hashPassword(password: string) {
    return bcrypt.hash(password, 10);
  }

  async getTokens(userId: string, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, email },
        {
          secret: this.configService.get('AT_SECRET'),
          expiresIn: '15m',
        },
      ),
      this.jwtService.signAsync(
        { sub: userId, email },
        {
          secret: this.configService.get('RT_SECRET'),
          expiresIn: '7d',
        },
      ),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hash = await this.hashPassword(refreshToken);
    await this.prismaService.user.update({
      where: { id: userId },
      data: { hashedRt: hash },
    });
  }

  async localSignup(dto: AuthDto): Promise<Tokens> {
    const hashedPassword = await this.hashPassword(dto.password);

    const newUser = await this.prismaService.user.create({
      data: {
        email: dto.email,
        hash: hashedPassword,
        name: dto.name,
      },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);

    await this.updateRefreshToken(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async localSignin(dto: AuthDto): Promise<Tokens> {
    const user = await this.prismaService.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new ForbiddenException('Invalid credentials');
    }

    const passworMatches = await bcrypt.compare(dto.password, user.hash);

    if (!passworMatches) {
      throw new ForbiddenException('Invalid credentials');
    }

    const tokens = await this.getTokens(user.id, user.email);

    await this.updateRefreshToken(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: string) {
    await this.prismaService.user.updateMany({
      where: {
        id: userId,
        hashedRt: { not: null },
      },
      data: { hashedRt: null },
    });
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new ForbiddenException('Invalid credentials');
    }

    const refreshTokenMatches = await bcrypt.compare(
      refreshToken,
      user.hashedRt,
    );

    if (!refreshTokenMatches) {
      throw new ForbiddenException('Invalid credentials');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);
    return tokens;
  }
}
