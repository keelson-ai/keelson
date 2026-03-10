import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

const TIMESTAMP_RE_LINE = /^\d{1,2}:\d{2}\s*(?:AM|PM)$/i;
const TIMESTAMP_RE_GLOBAL = /\d{1,2}:\d{2}\s*(?:AM|PM)/gi;
const HUBSPOT_CTA_RE = /let us know your email|want updates about/i;

/**
 * HubSpot chat widget adapter using Playwright.
 *
 * Automates a real browser to interact with AI chatbots embedded in
 * HubSpot Conversations widgets (the inline iframe pattern used by many sites).
 *
 * Requires `playwright` as an optional peer dependency:
 *   pnpm add playwright && npx playwright install chromium
 *
 * Config options:
 *   - baseUrl: the page URL containing the HubSpot chat widget
 *   - browserHeadless: run headless (default: true)
 *   - browserResponseStabilityMs: how long to wait for response stabilization (default: 2000)
 *   - hubspotPreInteraction: JS snippet to run before interacting (e.g. toggle marketing mode)
 */
export class HubSpotAdapter extends BaseAdapter {
  private browser: any = null;
  private page: any = null;
  private hsFrame: any = null;
  private initialized = false;

  private readonly headless: boolean;
  private readonly responseStabilityMs: number;
  private readonly preInteraction: string | undefined;

  constructor(config: AdapterConfig) {
    super({ ...config, baseUrl: config.baseUrl });
    this.headless = config.browserHeadless !== false;
    this.responseStabilityMs = config.browserResponseStabilityMs ?? 2000;
    this.preInteraction = config.hubspotPreInteraction;
  }

  private async loadPlaywright(): Promise<any> {
    try {
      const moduleName = 'playwright';
      return await import(/* webpackIgnore: true */ moduleName);
    } catch {
      throw new Error(
        'HubSpot adapter requires playwright. Install it:\n' +
          '  pnpm add playwright && npx playwright install chromium',
      );
    }
  }

  private async ensureBrowser(): Promise<void> {
    if (this.initialized) return;

    const pw = await this.loadPlaywright();
    this.browser = await pw.chromium.launch({ headless: this.headless });
    const context = await this.browser.newContext({
      userAgent:
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    });
    this.page = await context.newPage();

    await this.page.goto(this.config.baseUrl, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    // Allow page scripts and widgets to initialize
    await this.page.waitForTimeout(5000);

    // Run pre-interaction hook if provided (e.g. toggle marketing mode)
    if (this.preInteraction) {
      await this.page.evaluate(this.preInteraction);
      await this.page.waitForTimeout(3000);
    }

    // Find the HubSpot conversations iframe
    this.hsFrame = this.page.frame({ url: /hubspot/ });
    if (!this.hsFrame) {
      // Try waiting a bit longer — some sites lazy-load the widget
      await this.page.waitForTimeout(5000);
      this.hsFrame = this.page.frame({ url: /hubspot/ });
    }

    if (!this.hsFrame) {
      throw new Error(
        'HubSpot adapter: could not find HubSpot conversations iframe. ' +
          'Ensure the page at baseUrl embeds a HubSpot chat widget.',
      );
    }

    // Wait for the textbox to appear inside the frame
    await this.hsFrame
      .waitForSelector('[role="textbox"], textarea, [contenteditable="true"]', { timeout: 15_000 })
      .catch(() => {
        throw new Error('HubSpot adapter: chat textbox not found in HubSpot iframe.');
      });

    // Snapshot initial conversation text

    this.initialized = true;
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    await this.ensureBrowser();

    const lastUser = messages.filter((m) => m.role === 'user').pop();
    const message = lastUser?.content ?? '';

    const start = performance.now();

    // Snapshot conversation text before sending
    const beforeText = await this.getConversationText();

    // Wait for the send button to be enabled (critical for multi-turn: button is
    // disabled while the bot is still responding from a previous turn)
    await this.waitForSendReady();

    // Type into the textbox
    const textbox = await this.findTextbox();
    await textbox.click({ force: true });
    await this.page.waitForTimeout(300);
    await textbox.fill(message);
    await this.page.waitForTimeout(300);

    // Send the message
    await this.clickSend();

    // Wait for bot response
    const content = await this.waitForReply(beforeText, message);
    const latencyMs = Math.round(performance.now() - start);

    return { content, raw: { method: 'hubspot-iframe' }, latencyMs };
  }

  private async waitForSendReady(): Promise<void> {
    const timeout = 30_000;
    const deadline = Date.now() + timeout;
    const btnSelectors = 'button[aria-label="send message"], button[data-test-id="send-button"]';

    while (Date.now() < deadline) {
      const btn = await this.hsFrame.$(btnSelectors);
      if (btn) {
        const disabled = await btn.getAttribute('disabled');
        const ariaDisabled = await btn.getAttribute('aria-disabled');
        if (disabled === null && ariaDisabled !== 'true') return;
      } else {
        // No explicit send button — widget uses Enter key, always ready
        return;
      }
      await this.page.waitForTimeout(500);
    }
    // Don't block — proceed and let the send attempt fail naturally if still disabled
  }

  private async clickSend(): Promise<void> {
    const sendBtn = await this.hsFrame.$('button[aria-label="send message"], button[data-test-id="send-button"]');
    if (sendBtn) {
      await sendBtn.click({ force: true });
    } else {
      await this.hsFrame.press('[role="textbox"]', 'Enter');
    }
  }

  private async findTextbox(): Promise<any> {
    const selectors = [
      '[role="textbox"][aria-label*="message" i]',
      '[role="textbox"][aria-label*="ask" i]',
      '[role="textbox"]',
      'textarea',
      '[contenteditable="true"]',
    ];

    for (const sel of selectors) {
      const el = await this.hsFrame.$(sel);
      if (el) return el;
    }

    throw new Error('HubSpot adapter: could not find chat input in HubSpot frame');
  }

  private async getConversationText(): Promise<string> {
    return this.hsFrame.evaluate(() => {
      const conv = document.querySelector('#current-view-component');
      return conv ? (conv as HTMLElement).innerText?.trim() || '' : '';
    });
  }

  private async waitForReply(beforeText: string, sentMessage: string): Promise<string> {
    const timeout = this.config.timeout ?? 60_000;
    const deadline = Date.now() + timeout;
    const beforeTimestampCount = (beforeText.match(TIMESTAMP_RE_GLOBAL) || []).length;

    while (Date.now() < deadline) {
      await this.page.waitForTimeout(this.responseStabilityMs);

      const currentText = await this.getConversationText();
      const currentTimestampCount = (currentText.match(TIMESTAMP_RE_GLOBAL) || []).length;

      // New timestamps = new messages (both user and bot messages get timestamps)
      // We need at least 2 new timestamps: one for the user message, one for the bot reply
      if (currentTimestampCount >= beforeTimestampCount + 2) {
        // Wait for streaming to stabilize
        await this.page.waitForTimeout(1500);
        const stableText = await this.getConversationText();
        if (stableText !== currentText) {
          await this.page.waitForTimeout(1500);
        }

        const finalText = await this.getConversationText();
        const botReply = this.extractLastBotReply(finalText, sentMessage);
        if (botReply) return botReply;
      }
    }

    throw new Error(`HubSpot adapter: no reply within ${timeout / 1000}s`);
  }

  /**
   * Extract the last bot reply from HubSpot conversation innerText.
   *
   * HubSpot innerText structure:
   *   BotName                          ← bot name header (standalone line)
   *   <welcome message lines>
   *   <user message lines>
   *   HH:MM AM/PM                      ← timestamp after user message
   *   Let us know your email...         ← HubSpot CTA (optional, skip)
   *   BotName                          ← bot name header before bot reply
   *   <bot response line 1>
   *   HH:MM AM/PM                      ← timestamp after each bot message bubble
   *   <bot response line 2>
   *   HH:MM AM/PM
   *
   * Strategy: detect the bot name from line 1, then parse message blocks.
   * Bot messages are preceded by the bot name. User messages are not.
   * We find the user's sent message, then collect the next bot-attributed block.
   */
  private extractLastBotReply(convText: string, sentMessage: string): string | null {
    const lines = convText
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    if (lines.length === 0) return null;

    // The very first line is the bot's display name
    const botName = lines[0];

    // Parse the conversation into attributed message blocks
    const blocks = this.parseMessageBlocks(lines, botName);

    // Find the last user block that matches the sent message
    let lastUserIdx = -1;
    const sentNorm = sentMessage.replace(/\s+/g, ' ').trim().substring(0, 80);
    for (let i = blocks.length - 1; i >= 0; i--) {
      if (blocks[i].author === 'user') {
        const blockNorm = blocks[i].text.replace(/\s+/g, ' ').trim().substring(0, 80);
        if (blockNorm.includes(sentNorm) || sentNorm.includes(blockNorm)) {
          lastUserIdx = i;
          break;
        }
      }
    }

    if (lastUserIdx === -1) return null;

    // Collect all bot blocks after the matched user message
    const replyParts: string[] = [];
    for (let i = lastUserIdx + 1; i < blocks.length; i++) {
      if (blocks[i].author === 'bot') {
        replyParts.push(blocks[i].text);
      } else {
        // Stop at the next user message
        break;
      }
    }

    return replyParts.join('\n').trim() || null;
  }

  /**
   * Parse HubSpot innerText lines into attributed message blocks.
   *
   * Rules:
   * - A line matching the botName exactly starts a new bot block
   * - A timestamp line ends the current accumulating content
   * - Lines between a botName header and the next timestamp are bot content
   * - Lines between a timestamp (after bot content) and the next timestamp are user content
   * - HubSpot CTA lines ("Let us know your email...") are skipped
   */
  private parseMessageBlocks(lines: string[], botName: string): Array<{ author: 'bot' | 'user'; text: string }> {
    const blocks: Array<{ author: 'bot' | 'user'; text: string }> = [];
    let currentAuthor: 'bot' | 'user' = 'bot'; // First block is typically bot welcome
    let currentLines: string[] = [];

    for (let i = 1; i < lines.length; i++) {
      // skip first line (botName header already consumed)
      const line = lines[i];

      if (TIMESTAMP_RE_LINE.test(line)) {
        // Timestamp = end of current content chunk
        if (currentLines.length > 0) {
          const text = currentLines.join('\n').trim();
          if (text && !HUBSPOT_CTA_RE.test(text)) {
            blocks.push({ author: currentAuthor, text });
          }
          currentLines = [];
        }
        // After a bot block's timestamp, next content is user (until we see botName again)
        if (currentAuthor === 'bot') {
          currentAuthor = 'user';
        }
        continue;
      }

      if (line === botName) {
        // Flush any pending user content
        if (currentLines.length > 0) {
          const text = currentLines.join('\n').trim();
          if (text && !HUBSPOT_CTA_RE.test(text)) {
            blocks.push({ author: currentAuthor, text });
          }
          currentLines = [];
        }
        currentAuthor = 'bot';
        continue;
      }

      currentLines.push(line);
    }

    // Flush remaining
    if (currentLines.length > 0) {
      const text = currentLines.join('\n').trim();
      if (text && !HUBSPOT_CTA_RE.test(text)) {
        blocks.push({ author: currentAuthor, text });
      }
    }

    return blocks;
  }

  override async healthCheck(): Promise<boolean> {
    try {
      await this.ensureBrowser();
      return true;
    } catch {
      return false;
    }
  }

  override resetSession(): void {
    const oldBrowser = this.browser;
    this.browser = null;
    this.page = null;
    this.hsFrame = null;
    this.initialized = false;

    if (oldBrowser) {
      void (oldBrowser as { close: () => Promise<void> }).close();
    }
  }

  override async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.page = null;
      this.hsFrame = null;
      this.initialized = false;
    }
  }
}
