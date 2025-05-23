FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

# Install dependencies including Redis
RUN npm install
RUN npm install ioredis @types/ioredis

COPY . .

RUN npm run build

EXPOSE 6000

CMD ["npm", "start"] 