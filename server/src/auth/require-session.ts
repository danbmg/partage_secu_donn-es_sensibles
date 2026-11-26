import type { Request } from 'express';
import type Database from 'better-sqlite3';
import { authenticatedSession, type ActiveSession } from './session.js';

export function requestSession(database: Database.Database, request: Request): ActiveSession | null {
  return authenticatedSession(database, request.header('authorization'));
}

export function requestUserId(database: Database.Database, request: Request): string | null {
  return requestSession(database, request)?.userId ?? null;
}
