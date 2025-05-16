# AI Risk Engine

A Node.js backend system for evaluating payment transaction risks based on various fraud indicators.

## Features

- **Risk Evaluation**: Analyzes transactions based on email domain, amount, IP address, and device fingerprint
- **LLM Integration**: Enhanced risk analysis powered by OpenAI's language models
- **Fraud Logging**: Saves suspicious transactions to MongoDB
- **Statistics API**: Get aggregate fraud data by risk level
- **Configuration Management**: Dynamic updates of risk thresholds and flagged entities
- **Rate Limiting**: Prevents abuse of the API endpoints
- **Docker Support**: Easy deployment with Docker and MongoDB

## Tech Stack

- Node.js + TypeScript
- Express.js
- MongoDB with Mongoose
- OpenAI API for LLM integration
- Jest for testing
- Docker and docker-compose

## API Endpoints

### Risk Evaluation

```
POST /api/evaluate-risk
```

Request Body:
```json
{
  "email": "user@example.com",
  "amount": 5000,
  "ip": "192.168.1.1",
  "deviceFingerprint": "d3v1c3-1d-h3r3",
  "enableLlmAnalysis": true
}
```

Response:
```json
{
  "success": true,
  "data": {
    "score": 35,
    "riskLevel": "medium",
    "explanation": ["Transaction amount ₹5000 exceeds threshold"],
    "llmEnhanced": true,
    "llmFlags": ["Unusual transaction pattern for this account"]
  }
}
```

### Fraud Statistics

```
GET /api/fraud-stats
```

Response:
```json
{
  "success": true,
  "data": {
    "totalAttempts": 128,
    "byRiskLevel": {
      "low": { "count": 58, "averageScore": 15.2 },
      "medium": { "count": 42, "averageScore": 45.7 },
      "high": { "count": 28, "averageScore": 82.3 }
    }
  }
}
```

### Configuration Management

```
GET /config
```

Response:
```json
{
  "success": true,
  "data": {
    "flaggedDomains": ["fraud.com", "temp-mail.org", "fakeemail.com"],
    "thresholds": {
      "low": 30,
      "medium": 60,
      "high": 80,
      "amountThreshold": 10000
    },
    "suspiciousIps": ["1.2.3.4"],
    "suspiciousDevices": ["blocked-device-id"]
  }
}
```

```
PUT /config
```

Request Body:
```json
{
  "flaggedDomains": ["fraud.com", "scam.net", "temp-mail.org"],
  "thresholds": {
    "amountThreshold": 15000
  }
}
```

## Installation and Setup

### Prerequisites

- Node.js (>= 14.x)
- npm or yarn
- MongoDB (if not using Docker)
- Docker and docker-compose (for containerized setup)
- OpenAI API key (for LLM integration)

### Local Development

1. Clone the repository
   ```
   git clone https://github.com/yourusername/ai-risk-engine.git
   cd ai-risk-engine
   ```

2. Install dependencies
   ```
   npm install
   ```

3. Create a `.env` file based on the example
   ```
   cp sample.env .env
   ```

4. Update environment variables in `.env` as needed, especially the `OPENAI_API_KEY` for LLM integration

5. Start the development server
   ```
   npm run dev
   ```

### Using Docker

1. Build and start containers
   ```
   docker-compose up -d
   ```

2. The API will be available at `http://localhost:6000`

3. MongoDB will be available at `mongodb://localhost:27017`

## Using the LLM Integration

To enable LLM-enhanced risk analysis:

1. Make sure you have set your `OPENAI_API_KEY` in the `.env` file
2. Set `enableLlmAnalysis: true` in your API request

The LLM will:
- Process the same transaction data used in rule-based analysis
- Provide additional risk insights not covered by rules
- Contribute to the final risk score through a weighted blend
- Add unique risk flags and explanations to the response

This provides more nuanced fraud detection, especially for complex or novel fraud patterns.

## Testing

Run tests with Jest:

```
npm test
```

Or with coverage report:

```
npm test -- --coverage
```

## License

ISC 