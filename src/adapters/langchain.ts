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

    const { data, latencyMs } = await this.timedPost('/invoke', {
      [this.inputKey]: userInput,
    });

    const content: string =
      typeof data === 'string'
        ? data
        : ((data as Record<string, string>)[this.outputKey] ?? (data as Record<string, string>).content ?? '');
    return { content, raw: data, latencyMs };
  }
}
