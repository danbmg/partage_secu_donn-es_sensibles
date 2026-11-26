import express from 'express';
import type Database from 'better-sqlite3';
import { createFailureLimiter, type FailureLimiter } from './auth/rate-limit.js';
import { openDatabase } from './db.js';
import { accountRoutes } from './routes/account.js';
import { auditRoutes } from './routes/audit.js';
import { authRoutes } from './routes/auth.js';
import { itemRoutes } from './routes/items.js';

export function createApp(database: Database.Database, limiter: FailureLimiter = createFailureLimiter()): express.Express {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  app.get('/api/health', (_request, response) => {
    response.status(200).json({ status: 'ok' });
  });
  app.use('/api', authRoutes(database, limiter));
  app.use('/api', accountRoutes(database, limiter));
  app.use('/api/items', itemRoutes(database));
  app.use('/api/audit', auditRoutes(database));

  app.use((error: unknown, _request: express.Request, response: express.Response, next: express.NextFunction) => {
    void next;
    console.error('Unhandled API error');
    response.status(500).json({ error: 'Internal server error' });
  });
  return app;
}

export const app = createApp(openDatabase(':memory:'));
