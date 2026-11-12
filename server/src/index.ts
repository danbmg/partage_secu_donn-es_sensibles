import { createApp } from './app.js';
import { openDatabase } from './db.js';

const port = Number(process.env.PORT ?? 3000);
const app = createApp(openDatabase());

app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});
