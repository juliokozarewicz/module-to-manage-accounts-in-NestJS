import { Controller, Post, Body, ValidationPipe, UseGuards, Put, Get, Req, Delete } from '@nestjs/common';
import {
    CodeAccountActivateDTO, resendUserDTO, UserEntityDTO,
    changePasswordLinkDTO, changePasswordDTO, LoginDTO,
    ProfileDTO, deletAccountLinkDTO, deletAccountDTO
} from './accounts.dto';
import { UserService } from './accounts.service';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { AuthGuard } from '@nestjs/passport';

@ApiTags('ACCOUNTS')
@Controller('accounts')
@UseGuards(ThrottlerGuard)
export class UserController {
    constructor(
        private readonly userService: UserService,
    ) {}

    @Post('signup')
    @ApiBody({ type: UserEntityDTO })
    @ApiOperation({
        summary: 'Create a new user',
        description: 'Registers a new user in the system with the provided details.'
    })
    async createUser(@Body(new ValidationPipe({ transform: true })) createUserDto: UserEntityDTO): Promise<any> {
        return await this.userService.createUser(createUserDto);
    }

    @Post('resend-verify-email')
    @ApiBody({ type: resendUserDTO})
    @ApiOperation({
        summary: 'Resend Verification Email',
        description: 'Resends a verification email to the user based on the provided email address.'
      })
    async resendVerifyEmailCode(@Body(new ValidationPipe({ transform: true })) resendEmailDto: resendUserDTO) {
        return await this.userService.resendVerifyEmailCode(resendEmailDto);
    }

    @Post('verify-email')
    @ApiBody({ type: CodeAccountActivateDTO})
    @ApiOperation({
        summary: 'Verify Email',
        description: 'Verifies the user’s email address based on the provided code.'
    })
    async verifyEmailCode (@Body(new ValidationPipe({ transform: true })) activateDTO: CodeAccountActivateDTO) { 
        return await this.userService.verifyEmailCode(activateDTO);
    }

    @Post('change-password-link')
    @ApiBody({ type: changePasswordLinkDTO})
    @ApiOperation({
        summary: 'Request Password Change Link',
        description: 'Generates a password change link and sends it to the user’s email address.'
    })
    async changePasswordLink(@Body(new ValidationPipe({ transform: true })) changePasswordLinkDTO: changePasswordLinkDTO) { 
        return await this.userService.changePasswordLink(changePasswordLinkDTO);
    }

    @Put('change-password')
    @ApiBody({ type: changePasswordDTO})
    @ApiOperation({
        summary: 'Change User Password',
        description: 'Allows the user to change their password by providing the code.'
    })
    async changePassword(@Body(new ValidationPipe({ transform: true })) changePasswordDTO: changePasswordDTO) { 
        return await this.userService.changePassword(changePasswordDTO);
    }

    @Post('login')
    @ApiBody({ type: LoginDTO})
    @ApiOperation({
        summary: 'User Login',
        description: 'Allows the user to log in by providing their username and password.'
      })
    async login(@Body(new ValidationPipe({ transform: true })) loginDto: LoginDTO) {
        return this.userService.login(loginDto);
    }

    @Get('profile')
    @UseGuards(AuthGuard('jwt'))
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Get Profile Data',
        description: 'Method to obtain user profile data, such as biography, identity, and other details.'
      })
    profile(@Req() req: any) {

        const userData = req.user;

        return this.userService.profile(userData);
    }

    @Put('profile-update')
    @UseGuards(AuthGuard('jwt'))
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Update Profile Data',
        description: 'Method to update user profile data, such as biography, identity, and other details.'
    })
    updateProfile(
        @Req() req: any,
        @Body(new ValidationPipe({ transform: true })) profileDTO: ProfileDTO
    ) {
        const userData = req.user;
        return this.userService.updateProfile(userData, profileDTO);
    }

    @Post('delete-account-link')
    @ApiBody({ type: deletAccountLinkDTO})
    @ApiOperation({
        summary: 'Request Account Deletion Link',
        description: 'Sends a link to the user’s email that allows them to delete their account.'
    })
    async deletAccountLink(@Body(new ValidationPipe({ transform: true })) deletAccountLinkDTO: deletAccountLinkDTO) { 
        return await this.userService.deletAccountLink(deletAccountLinkDTO);
    }

    @Delete('delete-account')
    @ApiBody({ type: deletAccountDTO})
    @ApiOperation({
        summary: 'Delete User Account',
        description: 'Deletes the user’s account based on the provided information.'
    })
    async deletAccount(@Body(new ValidationPipe({ transform: true })) deletAccountDTO: deletAccountDTO) { 
        return await this.userService.deletAccount(deletAccountDTO);
    }
}