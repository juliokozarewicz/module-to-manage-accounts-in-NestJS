import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserController } from './accounts.controller';
import { ProfileEntity, UserEntity, CodeAccountActivate } from './accounts.entity';
import { UserService } from './accounts.service';
import { EmailService } from './accounts.email';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './accounts.jwt_strategy';


@Module({
    imports: [

        // TypeORM (database)
        TypeOrmModule.forFeature([UserEntity, ProfileEntity, CodeAccountActivate]),

        // JWT for login
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
            secret: String(process.env.API_SECURITY_CODE),
            signOptions: { expiresIn: '1h' },
        }),

    ],
    controllers: [UserController],
    providers: [JwtStrategy, UserService, EmailService],
    exports: [UserService],
})
export class AccountsModule {}