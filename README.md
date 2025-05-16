# AI Risk Engine

A Node.js backend system for evaluating payment transaction risks based on various fraud indicators.

## Features

- **Risk Evaluation**: Analyzes transactions with a 0.0-1.0 fraud score scale based on industry best practices
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
    "score": 0.45,
    "riskLevel": "moderate",
    "explanation": [
      "Transaction amount ₹5000 exceeds threshold", 
      "IP address has been used multiple times recently"
    ],
    "llmEnhanced": true,
    "llmFlags": [
      "Unusual transaction pattern for this account", 
      "Transaction velocity indicates potential risk"
    ],
    "llmResponse": {
      "score": 0.52,
      "riskLevel": "moderate",
      "explanation": "This transaction is considered moderate risk with a score of 0.52 due to: Transaction amount exceeds threshold; IP address has been used multiple times recently"
    }
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
      "low": { "count": 58, "averageScore": 0.15 },
      "moderate": { "count": 42, "averageScore": 0.46 },
      "high": { "count": 28, "averageScore": 0.82 }
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
- Generate a summarized risk assessment in the `llmResponse` field

### Understanding the Risk Scoring System

The system now uses a 0.0-1.0 scale for fraud scoring:
- **0.0-0.3**: Low risk
- **0.3-0.7**: Moderate risk
- **0.7-1.0**: High risk

The final score is calculated using:
- Rule-based indicators (70% weight)
- LLM-based analysis (30% weight, when enabled)

The new `llmResponse` field provides a consolidated view of the LLM's assessment with:
- A single-score fraud rating (0.0-1.0)
- The determined risk level (low, moderate, high)
- A concise explanation summarizing the key risk factors

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