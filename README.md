# Account Management Module
This repository contains a NestJS-based module for managing accounts. It uses TypeORM for database interactions, Swagger for API documentation, and includes a logger and throttling module.

## Technologies Used
NestJS: A progressive Node.js framework for building efficient, reliable, and scalable server-side applications.
TypeORM: An ORM for TypeScript and JavaScript that supports various SQL-based databases.
Swagger: A tool for API documentation and testing.
Logger: Built-in logging capabilities in NestJS.
ThrottlerModule: Provides rate-limiting capabilities to prevent abuse.
PostgreSQL: The relational database used for data storage.
Getting Started
Follow these steps to set up and run the project locally.

## Prerequisites
Node.js (v14 or later)
PostgreSQL

## Installation
Clone the repository:
```bash
git clone https://github.com/your-username/account-management-module.git
cd account-management-module
```

## Install dependencies
```bash
npm install
```

## Set Up Environment Variables
Create a .env file in the root directory and add the following environment variables:
```text
# SERVER
API_NAME=
API_SECURITY_CODE=
DOMAIN_NAME=127.0.0.1:3000

# EMAIL
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=
EMAIL_PASS=

# DATABASE
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=
DB_NAME=
```

## Running the Application
```bash
npm run start
```
The application will start on port 3000.

## Access Swagger Documentation
Open your browser and navigate to http://localhost:3000/docs to view the API documentation.

## Configuration
main.ts: Sets up the NestJS application, configures Swagger for API documentation, and sets up logging.
```javascript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { Logger } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Swagger
  const config = new DocumentBuilder()
    .setTitle('Account Management Module')
    .setDescription('API for managing accounts using NestJS.')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  // Logs
  app.useLogger(new Logger());

  await app.listen(3000);
}
bootstrap();
```
app.module.ts: Configures the application modules, TypeORM, and ThrottlerModule.
```javascript
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { drugModule } from './modules/drugs/drugs.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { AccountsModule } from './modules/accounts/accounts.module';
import { ThrottlerModule } from '@nestjs/throttler';

@Module({
  imports: [
    ThrottlerModule.forRoot({
      ttl: 600000,
      limit: 1000,
    }),
    AccountsModule,
    ConfigModule.forRoot(),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT),
      username: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      entities: [__dirname + '/**/*.entity{.ts,.js}'],
      synchronize: true,
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
```