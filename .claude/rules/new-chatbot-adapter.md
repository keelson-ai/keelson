# New Chatbot Adapter Creation

When encountering a new type of AI chatbot or agent framework during any task, proactively create an adapter for it.

## When
- A user mentions a chatbot platform, AI agent framework, or LLM-based service not already in `src/adapters/`
- You encounter a new chatbot type while researching, scanning, or writing probes
- A scan target uses a framework that has no matching adapter

## Current Adapters
Check `src/adapters/index.ts` for the `ADAPTER_MAP` to see what already exists before creating a new one.

## Required Steps

1. **Create the adapter file** at `src/adapters/<name>.ts`
   - Extend `BaseAdapter` from `./base.js`
   - Implement the `Adapter` interface (`sendTurn`, `close`, optionally `resetSession`)
   - Use the platform's API format for request/response mapping
   - Map responses to `AdapterResponse` (text, latencyMs, metadata)

2. **Register in the barrel** at `src/adapters/index.ts`
   - Add import
   - Add named export
   - Add entry to `ADAPTER_MAP`

3. **Add the adapter type** to `AdapterConfig['type']` union in `src/types/index.ts`

4. **Write tests** at `tests/adapters/<name>.test.ts`
   - Use `nock` to mock HTTP endpoints
   - Test happy path, error handling, and multi-turn conversation

5. **Update `README.md`**
   - Add a row to the **Adapters** table with: adapter name, `--adapter <flag>`, protocol, and use case
   - Add a usage example in the code block below the table showing the CLI invocation
   - Update the adapter count in the introductory paragraph and the "How It Works" diagram (e.g., "9 Adapters" → "10 Adapters")
   - Update the project structure section if the adapter count mentioned there changes

## Adapter Template

```typescript
import { BaseAdapter } from './base.js';
import type { AdapterResponse, AdapterConfig, Turn } from '../types/index.js';

export class FooAdapter extends BaseAdapter {
  constructor(config: AdapterConfig) {
    super(config);
  }

  async sendTurn(turn: Turn, history: Turn[]): Promise<AdapterResponse> {
    // Map turn + history to platform-specific request format
    // POST to the platform API
    // Map response to AdapterResponse
  }
}
```

## Guidelines
- Follow existing adapter conventions (see `openai.ts` or `anthropic.ts` as reference)
- Use `this.timedPost()` for latency tracking
- Use `this.resolveModel()` for model selection
- Handle platform-specific auth via `config.headers` or `config.apiKey`
- Keep it minimal — only implement what's needed for probe delivery and response capture
