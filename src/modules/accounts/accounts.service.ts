import { BadRequestException, ConflictException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
    CodeAccountActivateDTO, resendUserDTO, UserEntityDTO,
    changePasswordLinkDTO, changePasswordDTO, LoginDTO,
    ProfileDTO, deletAccountLinkDTO, deletAccountDTO
} from './accounts.dto';
import { ProfileEntity, UserEntity, CodeAccountActivate } from './accounts.entity';
import * as bcrypt from 'bcryptjs';
import { sanitizeNameString, sanitizeEmail, sanitizeUserId, sanitizeString } from './accounts.sanitize';
import * as crypto from 'crypto';
import { EmailService } from './accounts.email';
import { logsGenerator } from './accounts.logs';
import { JwtService } from '@nestjs/jwt';


@Injectable()
export class UserService {

    constructor(
        @InjectRepository(UserEntity)
        private readonly userRepository: Repository<UserEntity>,

        @InjectRepository(ProfileEntity)
        private readonly profileRepository: Repository<ProfileEntity>,

        @InjectRepository(CodeAccountActivate)
        private readonly userAccCodeActivate: Repository<CodeAccountActivate>,

        private readonly emailService: EmailService,
        private readonly jwtService: JwtService,
    ) {}

    // exception handling
    private readonly knownExceptions = [
        ConflictException,
        BadRequestException,
        UnauthorizedException
    ];

    // insert new user
    async createUser(userDto: UserEntityDTO): Promise<any> {

        try {

            // get user data
            const existingUser = await this.userRepository.findOne({ where: { email: sanitizeEmail(userDto.email) } });

            // existing email verification
            if (existingUser) {
                throw new ConflictException({
                    statusCode: 409,
                    message: `email already registered`,
                    _links: {
                        self: { href: "/accounts/signup" },
                        next: { href: "/accounts/login" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }
            
            // insert data user
            const newUser = new UserEntity();
            newUser.isActive = userDto.isActive;
            newUser.level = userDto.level;
            newUser.name = sanitizeNameString(userDto.name);
            newUser.email = sanitizeEmail(userDto.email);
            newUser.isEmailConfirmed = userDto.isEmailConfirmed;
            newUser.password = await this.hashPassword(userDto.password);

            await this.userRepository.manager.transaction(async transactionalEntityManager => {

                // commit user
                const savedUser = await transactionalEntityManager.save(newUser);

                // commit new profile
                const newProfile = new ProfileEntity();
                newProfile.id = savedUser.id;
                await transactionalEntityManager.save(newProfile);

                // Send email
                const textSend = `Click the link in this email to activate your account`;
                const codeAccount = await this.sendEmailVerify(userDto.urlRedirect, sanitizeEmail(newUser.email), textSend)

                // commit code activate
                const codeAccActivate = new CodeAccountActivate();
                codeAccActivate.id = savedUser.id;
                codeAccActivate.code = codeAccount;
                codeAccActivate.email = sanitizeEmail(savedUser.email);
                await transactionalEntityManager.save(codeAccActivate);
            });

            return {
                statusCode: 201,
                message: "user created successfully",
                _links: {
                    self: { href: "/accounts/signup" },
                    next: { href: `/accounts/login`},
                    prev: { href: "/accounts/login" }
                }
            };

        } catch (error) {

            // logs
            logsGenerator('error', `create user service [createUser()]: ${error}`)

            if (this.knownExceptions.some(exc => error instanceof exc)) {
                throw error;
            }

            // return server error
            throw new InternalServerErrorException({
                statusCode: 500,
                message: 'an unexpected error occurred, please try again later',
                _links: {
                    self: { href: "/accounts/signup" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            });
        }
    }

    // Resend verify email
    async resendVerifyEmailCode(resendActivateDTO: resendUserDTO): Promise<any> {

        try {

            // get user data
            const existingUser = await this.userRepository.findOne({ where: { email: sanitizeEmail(resendActivateDTO.email) } });

            // account not activated (deleted or banned)
            if (!existingUser.isActive) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `account not activated, please contact support`,
                    _links: {
                        self: { href: "/accounts/resend-verify-email" },
                        next: { href: "/accounts/signup" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // existing email verification
            if (!existingUser) {
                throw new BadRequestException({
                    statusCode: 404,
                    message: `email not registered`,
                    _links: {
                        self: { href: "/accounts/resend-verify-email" },
                        next: { href: "/accounts/signup" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // activated email
            if (existingUser.isEmailConfirmed) {
                throw new ConflictException({
                    statusCode: 409,
                    message: `account with email activated`,
                    _links: {
                        self: { href: "/accounts/resend-verify-email" },
                        next: { href: "/accounts/login" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // delete existing codes
            const deleteAllCodes = await this.userAccCodeActivate.find( { where: { email: sanitizeEmail(resendActivateDTO.email) } } );

            for (let i = 0; i < deleteAllCodes.length; i++) {
                await this.userAccCodeActivate.remove(deleteAllCodes[i]);
            }

            await this.userRepository.manager.transaction(async transactionalResendCodeManager => {
                const textSend = `Click the link in this email to activate your account`;
                const codeAccount = await this.sendEmailVerify(resendActivateDTO.urlRedirect, sanitizeEmail(resendActivateDTO.email), textSend)

                const codeAccActivate = new CodeAccountActivate();
                codeAccActivate.code = codeAccount;
                codeAccActivate.email = sanitizeEmail(resendActivateDTO.email);
                await transactionalResendCodeManager.save(codeAccActivate);
            })

            return {
                statusCode: 201,
                message: "code resent successfully",
                _links: {
                    self: { href: "/accounts/resend-verify-email" },
                    next: { href: `/accounts/login`},
                    prev: { href: "/accounts/login" }
                }
            };

        } catch (error) {

            // logs
            logsGenerator('error', `error when resending the email link [resendVerifyEmailCode()]: ${error}`)
        
            if (this.knownExceptions.some(exc => error instanceof exc)) {
                throw error;
            }
        
            // return server error
            throw new InternalServerErrorException({
                statusCode: 500,
                message: 'an unexpected error occurred, please try again later',
                _links: {
                    self: { href: "/accounts/resend-verify-email" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            });
        }
    }

    // Verify email
    async verifyEmailCode(accActivateDTO: CodeAccountActivateDTO): Promise<any> {

        try {

            const CodeAccActivate = await this.userAccCodeActivate.findOne({ where: { email: sanitizeEmail(accActivateDTO.email), code: sanitizeString(accActivateDTO.code) }});

            if (CodeAccActivate) {

                // delete all codes
                const deleteAllCodes = await this.userAccCodeActivate.find( { where: { email: sanitizeEmail(accActivateDTO.email) } } );

                for (let i = 0; i < deleteAllCodes.length; i++) {
                    await this.userAccCodeActivate.remove(deleteAllCodes[i]);
                }

                // Active account
                const activeAccEnd = await this.userRepository.findOne( { where: { email: sanitizeEmail(accActivateDTO.email) } } );

                // account not activated (deleted or banned)
                if (!activeAccEnd.isActive) {
                    throw new UnauthorizedException({
                        statusCode: 401,
                        message: `account not activated, please contact support`,
                        _links: {
                            self: { href: "/accounts/verify-email" },
                            next: { href: "/accounts/signup" },
                            prev: { href: "/accounts/login" }
                        }
                    });
                }

                activeAccEnd.isEmailConfirmed = true;
                await this.userRepository.save(activeAccEnd);

                return {
                    statusCode: 201,
                    message: "account activated successfully",
                    _links: {
                        self: { href: `/accounts/verify-email` },
                        next: { href: "/accounts/login" },
                        prev: { href: "/accounts/signup" }
                    }
                };
            } else {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `invalid email verification code`,
                    _links: {
                        self: { href: "/accounts/verify-email" },
                        next: { href: "/accounts/resend-verify-email" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

        } catch (error) {

            // logs
            logsGenerator('error', `error with verify email code [verifyEmailCode()]: ${error}`)
        
            if (this.knownExceptions.some(exc => error instanceof exc)) {
                throw error;
            }
        
            // return server error
            throw new InternalServerErrorException({
                statusCode: 500,
                message: 'an unexpected error occurred, please try again later',
                _links: {
                    self: { href: "/accounts/verify-email" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            });
        }
    }

    // Change password Link
    async changePasswordLink(changePasswordLinkDTO: changePasswordLinkDTO): Promise<any> {

        try {

            // get user data
            const existingUser = await this.userRepository.findOne({ where: { email: sanitizeEmail(changePasswordLinkDTO.email) } });
            
            // existing email verification
            if (!existingUser) {
                throw new BadRequestException({
                    statusCode: 404,
                    message: `email not registered`,
                    _links: {
                        self: { href: "/accounts/change-password-link" },
                        next: { href: "/accounts/signup" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // email not activated
            if (existingUser.isEmailConfirmed === false) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `email not activated`,
                    _links: {
                        self: { href: "/accounts/change-password-link" },
                        next: { href: "/accounts/resend-verify-email" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // account not activated (deleted or banned)
            if (!existingUser.isActive) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `account not activated, please contact support`,
                    _links: {
                        self: { href: "/accounts/change-password-link" },
                        next: { href: "/accounts/signup" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // delete existing codes
            const deleteAllCodes = await this.userAccCodeActivate.find( { where: { email: sanitizeEmail(changePasswordLinkDTO.email) } } );

            for (let i = 0; i < deleteAllCodes.length; i++) {
                await this.userAccCodeActivate.remove(deleteAllCodes[i]);
            }

            // save the code in the db and send the link via email
            await this.userRepository.manager.transaction(async transactionalResendCodeManager => {
                const textSend = `Click the link in this email to change your password`;
                const codeAccount = await this.sendEmailVerify(changePasswordLinkDTO.urlRedirect, sanitizeEmail(changePasswordLinkDTO.email), textSend)

                const codeAccActivate = new CodeAccountActivate();
                codeAccActivate.code = codeAccount;
                codeAccActivate.email = sanitizeEmail(changePasswordLinkDTO.email);
                await transactionalResendCodeManager.save(codeAccActivate);
            })

            return {
                statusCode: 201,
                message: "password change link sent successfully",
                _links: {
                    self: { href: "/accounts/change-password-link" },
                    next: { href: `/accounts/change-password`},
                    prev: { href: "/accounts/login" }
                }
            };

        } catch (error) {

            // logs
            logsGenerator('error', `error sending password change link [changePasswordLink()]: ${error}`)
        
            if (this.knownExceptions.some(exc => error instanceof exc)) {
                throw error;
            }
        
            // return server error
            throw new InternalServerErrorException({
                statusCode: 500,
                message: 'an unexpected error occurred, please try again later',
                _links: {
                    self: { href: "/accounts/change-password-link" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            });
        }
    }

    // change password
    async changePassword(changePasswordDTO: changePasswordDTO): Promise<any> {

        try {

            // get user data
            const existingUser = await this.userRepository.findOne({ where: { email: sanitizeEmail(changePasswordDTO.email) } });
            const CodeAccChange = await this.userAccCodeActivate.findOne({ where: { email: sanitizeEmail(changePasswordDTO.email), code: sanitizeString(changePasswordDTO.code) }});

            // existing email verification
            if (!existingUser) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `email not registered`,
                    _links: {
                        self: { href: "/accounts/change-password" },
                        next: { href: "/accounts/signup" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // email not activated
            if (existingUser.isEmailConfirmed === false) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `email not activated`,
                    _links: {
                        self: { href: "/accounts/change-password" },
                        next: { href: "/accounts/resend-verify-email" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // account not activated (deleted or banned)
            if (!existingUser.isActive) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `account not activated, please contact support`,
                    _links: {
                        self: { href: "/accounts/change-password-link" },
                        next: { href: "/accounts/signup" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            if (CodeAccChange) {
                await this.userRepository.manager.transaction(async transactionalEntityManager => {
                    // delete all codes
                    const deleteAllCodes = await this.userAccCodeActivate.find( { where: { email: sanitizeEmail(changePasswordDTO.email) } } );

                    for (let i = 0; i < deleteAllCodes.length; i++) {
                        await this.userAccCodeActivate.remove(deleteAllCodes[i]);
                    }

                    // change password
                    const changePasswordDB = new UserEntity();
                    changePasswordDB.id = existingUser.id;
                    changePasswordDB.password = await this.hashPassword(changePasswordDTO.password);
                    await transactionalEntityManager.save(changePasswordDB);
                });
            } else {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `invalid password verification code`,
                    _links: {
                        self: { href: "/accounts/change-password" },
                        next: { href: "/accounts/change-password-link" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            return {
                statusCode: 201,
                message: "password changed successfully",
                _links: {
                    self: { href: `/accounts/change-password` },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            };

        } catch (error) {

            // logs
            logsGenerator('error', `invalid password verification code [changePassword()]`)
        
            if (this.knownExceptions.some(exc => error instanceof exc)) {
                throw error;
            }
        
            // return server error
            throw new InternalServerErrorException({
                statusCode: 500,
                message: 'an unexpected error occurred, please try again later',
                _links: {
                    self: { href: "/accounts/change-password" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            });
        }
    }

    // login
    async login(loginCredentials: LoginDTO): Promise<any> {

        try {

            // get user data
            const user = await this.userRepository.findOne({ where: { email: sanitizeEmail(loginCredentials.email) } });

            // verify credentials
            if (!user || !await bcrypt.compare(loginCredentials.password, user.password)) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `invalid credentials`,
                    _links: {
                        self: { href: "/accounts/login" },
                        next: { href: "/accounts/login" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // Email not activated
            if (!user.isEmailConfirmed) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `email not activated`,
                    _links: {
                        self: { href: "/accounts/login" },
                        next: { href: "/accounts/login" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // account not activated (deleted or banned)
            if (!user.isActive) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `account not activated, please contact support`,
                    _links: {
                        self: { href: "/accounts/login" },
                        next: { href: "/accounts/login" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // token generator
            const payload = { email: sanitizeEmail(loginCredentials.email), sub: user.id };
            const jwtToken = {
                "acessToken": this.jwtService.sign(payload)
            };

            return jwtToken;

        } catch (error) {

            // logs
            logsGenerator('error', `login user service [login()]: ${error}`)
        
            if (this.knownExceptions.some(exc => error instanceof exc)) {
                throw error;
            }
        
            // return server error
            throw new InternalServerErrorException({
                statusCode: 500,
                message: 'an unexpected error occurred, please try again later',
                _links: {
                    self: { href: "/accounts/login" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            });
        }
    }

    // get profile data
    async profile(userData: any): Promise<any> {

        try {

            // get profile user data
            const profile = await this.profileRepository.findOne({ where: { id: sanitizeUserId(userData.userId) } });

            return profile;

        } catch (error) {

            // logs
            logsGenerator('error', `profile user service [profile()]: ${error}`)
        
            if (this.knownExceptions.some(exc => error instanceof exc)) {
                throw error;
            }
        
            // return server error
            throw new InternalServerErrorException({
                statusCode: 500,
                message: 'an unexpected error occurred, please try again later',
                _links: {
                    self: { href: "/accounts/profile" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            });
        }

    }

    // update profile data
    async updateProfile(userData: any, ProfileDTO: ProfileDTO): Promise<any> {

        try {

            // get profile user data
            const profile = await this.profileRepository.findOne({ where: { id: sanitizeUserId(userData.userId) } });

            // update profile
            profile.id = userData.userId;
            profile.biography = ProfileDTO.biography;
            profile.cpf = ProfileDTO.cpf;
            profile.phone = ProfileDTO.phone;
            this.profileRepository.save(profile)

            return {
                statusCode: 201,
                message: "profile changed successfully",
                _links: {
                    self: { href: `/accounts/profile-update` },
                    next: { href: "/accounts/profile" },
                    prev: { href: "/accounts/profile" }
                }
            };

        } catch (error) {

            // logs
            logsGenerator('error', `profile user service [updateProfile()]: ${error}`)
        
            if (this.knownExceptions.some(exc => error instanceof exc)) {
                throw error;
            }
        
            // return server error
            throw new InternalServerErrorException({
                statusCode: 500,
                message: 'an unexpected error occurred, please try again later',
                _links: {
                    self: { href: "/accounts/profile-update" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            });
        }

    }

    // delete account link
    async deletAccountLink(deletAccountLinkDTO: deletAccountLinkDTO): Promise<any> {

        try {

            // get user data
            const existingUser = await this.userRepository.findOne({ where: { email: sanitizeEmail(deletAccountLinkDTO.email) } });
            
            // existing email verification
            if (!existingUser) {
                throw new BadRequestException({
                    statusCode: 404,
                    message: `email not registered`,
                    _links: {
                        self: { href: "/accounts/change-password-link" },
                        next: { href: "/accounts/signup" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // email not activated
            if (existingUser.isEmailConfirmed === false) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `email not activated`,
                    _links: {
                        self: { href: "/accounts/change-password-link" },
                        next: { href: "/accounts/resend-verify-email" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // account not activated (deleted or banned)
            if (!existingUser.isActive) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `account not activated, please contact support`,
                    _links: {
                        self: { href: "/accounts/change-password-link" },
                        next: { href: "/accounts/signup" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // delete existing codes
            const deleteAllCodes = await this.userAccCodeActivate.find( { where: { email: sanitizeEmail(deletAccountLinkDTO.email) } } );

            for (let i = 0; i < deleteAllCodes.length; i++) {
                await this.userAccCodeActivate.remove(deleteAllCodes[i]);
            }

            // save the code in the db and send the link via email
            await this.userRepository.manager.transaction(async transactionalResendCodeManager => {
                const textSend = `Click the link in this email to delete your account`;
                const codeAccount = await this.sendEmailVerify(deletAccountLinkDTO.urlRedirect, sanitizeEmail(deletAccountLinkDTO.email), textSend)

                const codeAccActivate = new CodeAccountActivate();
                codeAccActivate.code = codeAccount;
                codeAccActivate.email = sanitizeEmail(deletAccountLinkDTO.email);
                await transactionalResendCodeManager.save(codeAccActivate);
            })

            return {
                statusCode: 201,
                message: "account deletion link sent successfully",
                _links: {
                    self: { href: "/accounts/delete-account-link" },
                    next: { href: `/accounts/accounts/delete-account`},
                    prev: { href: "/accounts/login" }
                }
            };

        } catch (error) {

            // logs
            logsGenerator('error', `An error occurred while deleting the account: ${sanitizeEmail(deletAccountLinkDTO.email)} [deletAccount()]: ${error}`)
        
            if (this.knownExceptions.some(exc => error instanceof exc)) {
                throw error;
            }
        
            // return server error
            throw new InternalServerErrorException({
                statusCode: 500,
                message: 'an unexpected error occurred, please try again later',
                _links: {
                    self: { href: "/accounts/delete-account-link" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            });
        }
    }

    // delete account
    async deletAccount(deletAccountDTO: deletAccountDTO): Promise<any> {

        try {

            // get user data
            const existingUser = await this.userRepository.findOne({ where: { email: sanitizeEmail(deletAccountDTO.email) } });
            const CodeAccDelete = await this.userAccCodeActivate.findOne({ where: { email: sanitizeEmail(deletAccountDTO.email), code: sanitizeString(deletAccountDTO.code) }});

            // verify credentials
            if (!existingUser || !await bcrypt.compare(deletAccountDTO.password, existingUser.password)) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `invalid credentials`,
                    _links: {
                        self: { href: "/accounts/delete-account" },
                        next: { href: "/accounts/login" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }            

            // email not activated
            if (existingUser.isEmailConfirmed === false) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `email not activated`,
                    _links: {
                        self: { href: "/accounts/delete-account" },
                        next: { href: "/accounts/signup" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            // account not activated (deleted or banned)
            if (!existingUser.isActive) {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `account not activated, please contact support`,
                    _links: {
                        self: { href: "/accounts/delete-account" },
                        next: { href: "/accounts/login" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            if (CodeAccDelete) {
                await this.userRepository.manager.transaction(async transactionalEntityManager => {
                    // delete all codes
                    const deleteAllCodes = await this.userAccCodeActivate.find( { where: { email: sanitizeEmail(deletAccountDTO.email) } } );

                    for (let i = 0; i < deleteAllCodes.length; i++) {
                        await this.userAccCodeActivate.remove(deleteAllCodes[i]);
                    }

                    // delete account
                    existingUser.isActive = false;
                    await this.userRepository.save(existingUser);
                });
            } else {
                throw new UnauthorizedException({
                    statusCode: 401,
                    message: `account deletion code is invalid`,
                    _links: {
                        self: { href: "/accounts/delete-account" },
                        next: { href: "/accounts/delete-account-link" },
                        prev: { href: "/accounts/login" }
                    }
                });
            }

            return {
                statusCode: 201,
                message: "Account has been successfully deleted",
                _links: {
                    self: { href: "/accounts/delete-account" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            };

        } catch (error) {

            // logs
            logsGenerator('error', `invalid password verification code [changePassword()]`)
        
            if (this.knownExceptions.some(exc => error instanceof exc)) {
                throw error;
            }
        
            // return server error
            throw new InternalServerErrorException({
                statusCode: 500,
                message: 'an unexpected error occurred, please try again later',
                _links: {
                    self: { href: "/accounts/delete-account" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            });
        }
    }

    // Password hash
    private async hashPassword(password: string): Promise<string> {
        try {
            const saltRounds = 12;
            return bcrypt.hash(password, saltRounds);
        } catch (error) {
            logsGenerator('critical', `bcrypt error [hashPassword()]: ${error}`)
        }
    }    

    // Send code verify-email
    private async sendEmailVerify(link: string, email: string, textSend: string): Promise<string> {

        try {

            const hashString = `${Date.now()*100}${email}${process.env.API_SECURITY_CODE}`;
            const codeAccount = crypto.createHash('sha256').update(hashString).digest('hex');

            const activationLink = (
                `${link}?` +
                `email=${email}&` +
                `code=${encodeURIComponent(codeAccount)}`
            )
            const to = email;
            const subject = `${process.env.API_NAME} - Account Service`;
            const text = (`${textSend}: \n\n\n${activationLink}`);

            await this.emailService.sendTextEmail(to, subject, text);

            return codeAccount

        } catch (error) {

            // logs
            logsGenerator('critical', `error with code delivery service via email [sendEmailVerify()]: ${error}`)

            if (this.knownExceptions.some(exc => error instanceof exc)) {
                throw error;
            }

            // return server error
            throw new InternalServerErrorException({
                statusCode: 500,
                message: 'an unexpected error occurred, please try again later',
                _links: {
                    self: { href: "/accounts/login" },
                    next: { href: "/accounts/login" },
                    prev: { href: "/accounts/login" }
                }
            });
        }
    }
}