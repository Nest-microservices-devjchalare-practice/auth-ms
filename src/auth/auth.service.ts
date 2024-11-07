import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';

import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interfaces';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('Connected to the database Mongo');
  }

  async singJwt(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      const { iat, exp, ...payload } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user: payload,
        token: await this.singJwt(payload),
        iat,
        exp,
      };
    } catch (error) {
      throw new RpcException({
        code: 401,
        message: error.message,
      });
    }
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;

    try {
      const user = await this.user.findUnique({
        where: {
          email: email,
        },
      });

      if (user) {
        throw new RpcException({
          code: 400,
          message: 'User already exists',
        });
      }

      const newUser = await this.user.create({
        data: {
          email,
          name,
          password: bcrypt.hashSync(password, 10),
        },
      });

      const { password: __, ...userWithoutPassword } = newUser;

      return {
        user: userWithoutPassword,
        token: await this.singJwt(userWithoutPassword),
      };
    } catch (error) {
      throw new RpcException({
        code: 400,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const user = await this.user.findUnique({
        where: {
          email: email,
        },
      });

      if (!user) {
        throw new RpcException({
          code: 400,
          message: 'User not valid',
        });
      }

      const isValidPassword = bcrypt.compareSync(password, user.password);

      if (!isValidPassword) {
        throw new RpcException({
          code: 400,
          message: 'Password not valid',
        });
      }

      const { password: __, ...userWithoutPassword } = user;

      return {
        user: userWithoutPassword,
        token: await this.singJwt(userWithoutPassword),
      };
    } catch (error) {
      throw new RpcException({
        code: 400,
        message: error.message,
      });
    }
  }
}
