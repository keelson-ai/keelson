import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

/**
 * LangChain adapter stub for Node.js.
 *
 * The Python version calls LangChain agents in-process. In the Node.js migration,
 * LangChain agents are accessed via a local HTTP bridge or subprocess.
 * Set baseUrl to the bridge endpoint (e.g., http://localhost:8002).
 */
export class LangChainAdapter extends BaseAdapter {
  private readonly inputKey: string;
  private readonly outputKey: string;

  constructor(config: AdapterConfig) {
    super(config);
    this.inputKey = config.inputKey ?? 'input';
    this.outputKey = config.outputKey ?? 'output';
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    const lastUser = messages.filter((m) => m.role === 'user').pop();
    const userInput = lastUser?.content ?? '';

    const start = performance.now();
    const { data } = await this.client.post('/invoke', {
      [this.inputKey]: userInput,
    });
    const latencyMs = Math.round(performance.now() - start);

    const content: string = typeof data === 'string' ? data : (data[this.outputKey] ?? data.content ?? '');
    return { content, raw: data, latencyMs };
  }
}
