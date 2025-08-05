// IMPORTANT: Load environment variables FIRST, before any other imports
import * as dotenv from 'dotenv';
import * as path from 'path';

// Load environment variables from .env file
// Try multiple possible locations for the .env file
const envPaths = [
  path.join(__dirname, '../.env'),           // From dist directory
  path.join(process.cwd(), '.env'),          // From current working directory
  path.join(process.cwd(), 'backend/.env'),  // From project root
];

let envLoaded = false;
for (const envPath of envPaths) {
  try {
    const result = dotenv.config({ path: envPath });
    if (!result.error) {
      console.log(`✅ Successfully loaded .env from: ${envPath}`);
      envLoaded = true;
      break;
    }
  } catch (error) {
    console.log(`❌ Failed to load .env from: ${envPath}`);
  }
}

if (!envLoaded) {
  console.log('⚠️  No .env file found, using default values');
}

// Debug: Log the current working directory and env values
console.log('Current working directory:', process.cwd());
console.log('GITHUB_CLIENT_ID from env:', process.env.GITHUB_CLIENT_ID);

// NOW import the rest after env vars are loaded
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS for frontend
  app.enableCors({
  origin: [
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:5175',
    'http://localhost:5176',
    'http://localhost:3000',
    'http://localhost:4173',
    'https://frontend-delta-umber-24.vercel.app', // ✅ Add your Vercel frontend here
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
});


  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
