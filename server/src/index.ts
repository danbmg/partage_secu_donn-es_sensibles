import { app } from './app.js';
import { openDatabase } from './db.js';

openDatabase();

const port = Number(process.env.PORT ?? 3000);

app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});
