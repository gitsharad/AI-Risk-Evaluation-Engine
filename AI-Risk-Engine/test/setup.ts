import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { beforeAll, afterEach, afterAll } from '@jest/globals';

let mongoServer: MongoMemoryServer;

// Connect to a new in-memory database before running any tests
beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  await mongoose.connect(mongoUri);
});

// Clean up database between tests
afterEach(async () => {
  const collections = mongoose.connection.collections;
  
  for (const key in collections) {
    const collection = collections[key];
    await collection.deleteMany({});
  }
});

// Close database connection after all tests are done
afterAll(async () => {
  await mongoose.connection.close();
  await mongoServer.stop();
});

export {}; // Export an empty object to make TypeScript treat this as a module 