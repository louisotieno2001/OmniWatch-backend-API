FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package metadata and generator
COPY package.cjs package-lock.json ./
COPY scripts/generate-package-json.cjs ./scripts/generate-package-json.cjs

# Install dependencies
RUN node scripts/generate-package-json.cjs && npm install

# Copy source code
COPY . .

# Expose port
EXPOSE 5000

# Start the application
CMD ["node", "server.js"]
