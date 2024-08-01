import { BadRequestException } from '@nestjs/common';
import * as sanitizeHtml from 'sanitize-html';


export function sanitizeNameString(input: string): string {

    if (/[^a-zA-Z0-9\s]/.test(input)) {
        throw new BadRequestException('has disallowed characters');
    }

    const sanitizedInput = sanitizeHtml(input, {
        allowedTags: [],
        allowedAttributes: {},
    }).trim();

    return sanitizedInput;
}

export function sanitizeEmail(input: string): string {

    if (/[^\w.@+-]/g.test(input)) {
        throw new BadRequestException('has disallowed characters');
    }

    const sanitizedInput = sanitizeHtml(input, {
        allowedTags: [],
        allowedAttributes: {},
    });

    return sanitizedInput;
}

export function sanitizeUserId(input: string): string {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    if (!uuidRegex.test(input)) {
        throw new BadRequestException('invalid user ID format, must be a valid UUID');
    }

    return input;
}

export function sanitizeString(input: string): string {
    const validStringRegex = /^[a-zA-Z0-9\s]+$/;

    if (!validStringRegex.test(input)) {
        throw new BadRequestException('input contains disallowed characters');
    }

    return input;
}