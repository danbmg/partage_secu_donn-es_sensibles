import { Router, type Request, type Response } from 'express';
import type Database from 'better-sqlite3';
import { auditEntriesFor } from '../audit.js';
import { requestUserId } from '../auth/require-session.js';

export function auditRoutes(database: Database.Database): Router {
  const router = Router();

  router.get('/', (request: Request, response: Response) => {
    const userId = requestUserId(request);
    if (!userId) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    response.status(200).json({ entries: auditEntriesFor(database, userId) });
  });

  return router;
}
