import { Pool } from 'pg';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

dotenv.config();

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_DATABASE || 'quarkshield_scanner',
  password: process.env.DB_PASSWORD || 'postgres',
  port: Number(process.env.DB_PORT) || 5432,
  connectionTimeoutMillis: 2000,
});

export const initDb = async () => {
  try {
    const client = await pool.connect();
    console.log('Connected to PostgreSQL successfully.');
    
    const schemaPath = path.join(__dirname, '../models/schema.sql');
    if (fs.existsSync(schemaPath)) {
      const schemaSql = fs.readFileSync(schemaPath, 'utf8');
      await client.query(schemaSql);
      console.log('Database tables verified/created successfully.');
    } else {
      console.warn('Warning: schema.sql file not found at', schemaPath);
    }
    
    client.release();
  } catch (err) {
    console.error('Database connection error:', err);
    // Don't crash immediately in dev, allows container DB to start up
  }
};

export default pool;
