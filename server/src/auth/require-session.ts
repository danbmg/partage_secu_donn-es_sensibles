import type { Request } from 'express';
import { authenticatedUserId } from './session.js';

export function requestUserId(request: Request): string | null {
  return authenticatedUserId(request.header('authorization'));
}
