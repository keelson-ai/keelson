import { BaseAdapter } from './base.js';
import type { AdapterResponse, Turn } from '../types/index.js';

/**
 * CrewAI adapter stub for Node.js.
 *
 * The Python version calls CrewAI agents in-process. In the Node.js migration,
 * CrewAI agents are accessed via a local HTTP bridge or subprocess.
 * Set baseUrl to the bridge endpoint (e.g., http://localhost:8001).
 */
export class CrewAIAdapter extends BaseAdapter {
  async send(messages: Turn[]): Promise<AdapterResponse> {
    const lastUser = messages.filter((m) => m.role === 'user').pop();
    const userInput = lastUser?.content ?? '';

    const start = performance.now();
    const { data } = await this.client.post('/kickoff', {
      input: userInput,
    });
    const latencyMs = Math.round(performance.now() - start);

    const content: string = data.result ?? data.raw ?? '';
    return { content, raw: data, latencyMs };
  }
}
