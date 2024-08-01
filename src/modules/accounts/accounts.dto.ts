import { IsNotEmpty, IsBoolean, IsInt, IsString, IsEmail, Length, IsOptional, Matches, IsNumber } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';


export class UserEntityDTO {

    @IsBoolean()
    isActive: boolean;

    @IsBoolean()
    level: boolean;

    @ApiProperty({ 
        example: 'Robert Folk',
    })
    @IsString()
    @IsNotEmpty()
    name: string;

    @ApiProperty({ 
        example: 'robertfolk@gmail.com', 
    })
    @IsEmail({}, { message: 'Please enter a valid email address' })
    email: string;

    @IsNotEmpty()
    @IsBoolean()
    isEmailConfirmed: boolean;

    @ApiProperty({ 
        example: "www.yourlink.com/auth/login",
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 255)
    urlRedirect: string;

    @ApiProperty({ 
        example: '$2b$10$hi5p9zPdA2z7qGy4QF5OP.xONlFhwBwJr8FMTZPmeWudZdVnBB2cq', 
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 255)
    @Matches(/^(?=.*[A-Z])/, { message: 'Password must contain at least one uppercase letter' })
    @Matches(/^(?=.*[a-z])/, { message: 'Password must contain at least one lowercase letter' })
    @Matches(/^(?=.*\d)/, { message: 'Password must contain at least one number' })
    @Matches(/^(?=.*[!@#$%^&*])/, { message: 'Password must contain at least one special character (e.g., !@#$%^&*)' })
    @Length(6, 255, { message: 'Password must be between 6 and 255 characters' })
    password: string;

    constructor(partial: Partial<UserEntityDTO>) {
        Object.assign(this, partial);
        this.isActive = true;
        this.level = false;
        this.isEmailConfirmed = false;
    }
}

export class resendUserDTO {

    @ApiProperty({ 
        example: 'robertfolk@gmail.com', 
    })
    @IsEmail({}, { message: 'Please enter a valid email address' })
    email: string;

    @ApiProperty({ 
        example: "www.yourlink.com/auth/login",
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 255)
    urlRedirect: string;

}

export class ProfileDTO {

    @ApiProperty({ 
        example: "I'm Robert Folk, a pharmacist with a deep love for music and science. Exploring the intricate rhythms of life while delving into the complexities of medicine fuels my passion for both art and discovery.", 
    })
    @IsOptional()
    @IsString()
    @Length(1, 500)
    biography: string;

    @ApiProperty({ 
        example: '55041997106575', 
    })
    @IsOptional()
    @IsString()
    @Length(1, 25)
    phone: string;

    @ApiProperty({ 
        example: '12345678909', 
    })
    @IsOptional()
    @IsString()
    @Length(1, 25)
    cpf: string;
}

export class CodeAccountActivateDTO {

    @ApiProperty({
        example: 'robertfolk@gmail.com', 
    })
    @IsEmail({}, { message: 'Please enter a valid email address' })
    email: string;

    @ApiProperty({ 
        example: "SHA256 Hash",
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 515)
    code: string;

    @ApiProperty({ 
        example: "www.yourlink.com/auth/login",
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 255)
    urlRedirect: string;
}

export class changePasswordLinkDTO {

    @ApiProperty({ 
        example: 'robertfolk@gmail.com', 
    })
    @IsEmail({}, { message: 'Please enter a valid email address' })
    email: string;

    @ApiProperty({ 
        example: "www.yourlink.com/auth/login",
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 255)
    urlRedirect: string;
}

export class changePasswordDTO {

    @ApiProperty({ 
        example: 'robertfolk@gmail.com', 
    })
    @IsEmail({}, { message: 'Please enter a valid email address' })
    email: string;

    @ApiProperty({ 
        example: '$2b$10$hi5p9zPdA2z7qGy4QF5OP.xONlFhwBwJr8FMTZPmeWudZdVnBB2cq', 
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 255)
    @Matches(/^(?=.*[A-Z])/, { message: 'Password must contain at least one uppercase letter' })
    @Matches(/^(?=.*[a-z])/, { message: 'Password must contain at least one lowercase letter' })
    @Matches(/^(?=.*\d)/, { message: 'Password must contain at least one number' })
    @Matches(/^(?=.*[!@#$%^&*])/, { message: 'Password must contain at least one special character (e.g., !@#$%^&*)' })
    @Length(6, 255, { message: 'Password must be between 6 and 255 characters' })
    password: string;

    @ApiProperty({ 
        example: "SHA256 Hash",
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 515)
    code: string;

    @ApiProperty({ 
        example: "www.yourlink.com/auth/login",
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 255)
    urlRedirect: string;
}

export class LoginDTO {

    @ApiProperty({ 
        example: 'robertfolk@gmail.com', 
    })
    @IsEmail({}, { message: 'Please enter a valid email address' })
    email: string;

    @ApiProperty({ 
        example: '$2b$10$hi5p9zPdA2z7qGy4QZPmeWudZdVnBB2cq', 
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 255)
    password: string;
}

export class deletAccountLinkDTO {

    @ApiProperty({ 
        example: 'robertfolk@gmail.com', 
    })
    @IsEmail({}, { message: 'Please enter a valid email address' })
    email: string;

    @ApiProperty({ 
        example: "www.yourlink.com/auth/delete-account",
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 255)
    urlRedirect: string;
}

export class deletAccountDTO {

    @ApiProperty({ 
        example: 'robertfolk@gmail.com', 
    })
    @IsEmail({}, { message: 'Please enter a valid email address' })
    email: string;

    @ApiProperty({ 
        example: '$2b$10$hi5p9zPdA2z7qGy4QF5OP.xONlFhwBwJr8FMTZPmeWudZdVnBB2cq', 
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 255)
    @Matches(/^(?=.*[A-Z])/, { message: 'Password must contain at least one uppercase letter' })
    @Matches(/^(?=.*[a-z])/, { message: 'Password must contain at least one lowercase letter' })
    @Matches(/^(?=.*\d)/, { message: 'Password must contain at least one number' })
    @Matches(/^(?=.*[!@#$%^&*])/, { message: 'Password must contain at least one special character (e.g., !@#$%^&*)' })
    @Length(6, 255, { message: 'Password must be between 6 and 255 characters' })
    password: string;

    @ApiProperty({ 
        example: "SHA256 Hash",
    })
    @IsNotEmpty()
    @IsString()
    @Length(1, 515)
    code: string;
}