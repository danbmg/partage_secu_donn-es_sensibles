import express from 'express';
import type Database from 'better-sqlite3';
import { openDatabase } from './db.js';
import { authRoutes } from './routes/auth.js';
import { itemRoutes } from './routes/items.js';

export function createApp(database: Database.Database): express.Express {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  app.get('/api/health', (_request, response) => {
    response.status(200).json({ status: 'ok' });
  });
  app.use('/api', authRoutes(database));
  app.use('/api/items', itemRoutes(database));

  app.use((error: unknown, _request: express.Request, response: express.Response, next: express.NextFunction) => {
    void next;
    console.error('Unhandled API error');
    response.status(500).json({ error: 'Internal server error' });
  });
  return app;
}

export const app = createApp(openDatabase(':memory:'));
