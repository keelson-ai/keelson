import { PlaywrightBaseAdapter } from './playwright-base.js';
import type { AdapterResponse, Turn } from '../types/index.js';

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
 *   - browserPreInteraction: JS snippet to run before chat interaction (e.g. toggle marketing mode)
 */
export class HubSpotAdapter extends PlaywrightBaseAdapter {
  private hsFrame: any = null;

  protected override async onBrowserReady(): Promise<void> {
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
  }

  protected override onSessionReset(): void {
    this.hsFrame = null;
  }

  protected async sendCore(messages: Turn[]): Promise<AdapterResponse> {
    await this.ensureBrowserCore();

    const lastUser = messages.filter((m) => m.role === 'user').pop();
    const message = lastUser?.content ?? '';

    const start = performance.now();

    // Snapshot conversation text before sending
    const beforeText = await this.getConversationText();

    // Type into the textbox
    const textbox = await this.findTextbox();
    await textbox.click({ force: true });
    await this.page.waitForTimeout(300);
    await textbox.fill(message);
    await this.page.waitForTimeout(300);

    // Wait for the send button to be enabled (critical for multi-turn: button is
    // disabled while the bot is still responding from a previous turn, and also
    // disabled when the textbox is empty — so we must fill first)
    await this.waitForSendReady();

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
   * Strategy: find the user's sent message in the raw lines, then collect
   * all bot-attributed content that follows (between the next botName header
   * and the end or next user message).
   *
   * HubSpot innerText structure:
   *   BotName                          <- bot name header (standalone line)
   *   <welcome message lines>          <- NO timestamp after welcome
   *   <user message text>
   *   HH:MM AM/PM                      <- timestamp after user message
   *   Let us know your email...         <- HubSpot CTA (optional)
   *   BotName                          <- bot name header before bot reply
   *   <bot response line 1>
   *   HH:MM AM/PM                      <- timestamp after each bot message bubble
   */
  private extractLastBotReply(convText: string, sentMessage: string): string | null {
    const lines = convText
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    if (lines.length === 0) return null;

    // The very first line is the bot's display name
    const botName = lines[0];

    // Find the user's sent message in the raw lines (fuzzy match on first 80 chars)
    const sentNorm = sentMessage.replace(/\s+/g, ' ').trim().substring(0, 80).toLowerCase();
    let userLineIdx = -1;
    for (let i = lines.length - 1; i >= 0; i--) {
      if (TIMESTAMP_RE_LINE.test(lines[i]) || lines[i] === botName) continue;
      const lineNorm = lines[i].replace(/\s+/g, ' ').trim().substring(0, 80).toLowerCase();
      if (lineNorm.includes(sentNorm) || sentNorm.includes(lineNorm)) {
        userLineIdx = i;
        break;
      }
    }

    if (userLineIdx === -1) return null;

    // Scan forward from the user message line: skip the user's timestamp,
    // skip CTA lines, then collect bot content (after botName header)
    const replyLines: string[] = [];
    let inBotReply = false;

    for (let i = userLineIdx + 1; i < lines.length; i++) {
      const line = lines[i];

      if (line === botName) {
        inBotReply = true;
        continue;
      }

      if (!inBotReply) continue; // skip user timestamp, CTA, etc.

      if (TIMESTAMP_RE_LINE.test(line)) continue; // skip bot timestamps
      if (HUBSPOT_CTA_RE.test(line)) continue;

      replyLines.push(line);
    }

    return replyLines.join('\n').trim() || null;
  }
}
