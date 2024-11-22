import sqlite3 from 'sqlite3';
import { open, Database } from 'sqlite';

// Open the database using sqlite3 driver
const dbPromise = open({
  filename: './auth.db',
  driver: sqlite3.Database,
});

export const initializeDB = async (): Promise<void> => {
  const db = await dbPromise;
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);
  console.log('Users table created or already exists.');
};

export default dbPromise;
