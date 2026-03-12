import { PlaywrightBaseAdapter } from './playwright-base.js';
import type { AdapterResponse, Turn } from '../types/index.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

const BOT_MSG_PREFIX_RE = /^Bot Response:\s*/i;
const WIDGET_FRAME_NAME = 'Virtual Assistant Chat';

/**
 * Forethought Solve widget adapter using Playwright.
 *
 * Automates a real browser to interact with AI agents embedded via the
 * Forethought Solve widget (`solve-widget.forethought.ai/embed.js`).
 *
 * The widget renders inside an iframe named "Virtual Assistant Chat"
 * with id `forethought-chat`. It exposes a global `Forethought()` API
 * for programmatic control.
 *
 * Requires `playwright` as an optional peer dependency:
 *   pnpm add playwright && npx playwright install chromium
 *
 * Config options:
 *   - baseUrl: the page URL embedding the Forethought widget
 *   - browserHeadless: run headless (default: true)
 *   - browserResponseStabilityMs: wait for response stabilization (default: 2000)
 *   - browserPreInteraction: JS snippet to run before chat (e.g. dismiss cookies)
 */
export class ForethoughtAdapter extends PlaywrightBaseAdapter {
  private ftFrame: any = null;
  private initialBotCount = 0;
  private totalBotCountSeen = 0;

  protected override async onBrowserReady(): Promise<void> {
    // Wait for the Forethought global to become available
    await this.page
      .waitForFunction(() => typeof (window as any).Forethought === 'function', { timeout: 20_000 })
      .catch(() => {
        throw new Error(
          'Forethought adapter: window.Forethought not found. ' +
            'Ensure the page at baseUrl loads the Forethought Solve widget.',
        );
      });

    // Open the widget
    await this.page.evaluate(() => (window as any).Forethought('widget', 'open'));
    await this.page.waitForTimeout(3000);

    // Locate the iframe
    this.ftFrame = this.page.frame({ name: WIDGET_FRAME_NAME });
    if (!this.ftFrame) {
      // Fallback: try finding by id
      const iframeEl = await this.page.$('#forethought-chat');
      if (iframeEl) {
        this.ftFrame = await iframeEl.contentFrame();
      }
    }

    if (!this.ftFrame) {
      throw new Error(
        'Forethought adapter: widget iframe not found. ' +
          'Expected iframe with name="Virtual Assistant Chat" or id="forethought-chat".',
      );
    }

    // Wait for the input field inside the widget
    await this.ftFrame.waitForSelector('input[type="text"], textarea', { timeout: 10_000 }).catch(() => {
      throw new Error('Forethought adapter: chat input not found in widget iframe.');
    });

    // Record initial bot messages (greeting) so we can detect new ones
    const initialMsgs = await this.ftFrame.$$('.js-bot-message');
    this.initialBotCount = initialMsgs.length;
    this.totalBotCountSeen = this.initialBotCount;
  }

  protected override onSessionReset(): void {
    this.ftFrame = null;
    this.initialBotCount = 0;
    this.totalBotCountSeen = 0;
  }

  protected async sendCore(messages: Turn[]): Promise<AdapterResponse> {
    await this.ensureBrowserCore();

    const lastUser = messages.filter((m) => m.role === 'user').pop();
    const message = lastUser?.content ?? '';

    const start = performance.now();

    // Snapshot bot message count before sending
    const beforeCount = await this.getBotMessageCount();

    // Type and send the message
    await this.typeAndSend(message);

    // Wait for new bot response
    const content = await this.waitForReply(beforeCount);
    const latencyMs = Math.round(performance.now() - start);

    return { content, raw: { method: 'forethought-widget' }, latencyMs };
  }

  private async typeAndSend(message: string): Promise<void> {
    const inputSelectors = ['input[type="text"]', 'textarea', 'input:not([type="hidden"]):not([type="submit"])'];

    let input: any = null;
    for (const sel of inputSelectors) {
      input = await this.ftFrame.$(sel);
      if (input) break;
    }

    if (!input) {
      throw new Error('Forethought adapter: chat input not found in widget');
    }

    await input.click();
    await input.fill(message);
    await this.page.waitForTimeout(300);
    await input.press('Enter');
  }

  private async getBotMessageCount(): Promise<number> {
    const msgs = await this.ftFrame.$$('.js-bot-message');
    return msgs.length;
  }

  private async waitForReply(beforeCount: number): Promise<string> {
    const timeout = this.config.timeout ?? 90_000;
    const deadline = Date.now() + timeout;

    while (Date.now() < deadline) {
      await this.page.waitForTimeout(this.responseStabilityMs);

      const currentCount = await this.getBotMessageCount();
      if (currentCount > beforeCount) {
        // New bot message appeared — wait for streaming to stabilize
        await this.page.waitForTimeout(3000);

        // Check if the loading indicator is still visible
        const isLoading = await this.isWidgetLoading();
        if (isLoading) {
          // Wait longer for streaming to complete
          await this.waitForLoadingComplete(deadline);
        }

        // Extract all new bot messages since beforeCount
        const content = await this.extractNewBotMessages(beforeCount);
        this.totalBotCountSeen = await this.getBotMessageCount();
        return content;
      }
    }

    throw new Error(`Forethought adapter: no reply within ${timeout / 1000}s`);
  }

  private async isWidgetLoading(): Promise<boolean> {
    return this.ftFrame.evaluate(() => {
      // Forethought shows ●●● dots during loading via various patterns
      const loadingIndicators = document.querySelectorAll('[class*="loading"], [class*="typing"], [class*="dots"]');
      for (const el of loadingIndicators) {
        if ((el as HTMLElement).offsetParent !== null) return true;
      }
      return false;
    });
  }

  private async waitForLoadingComplete(deadline: number): Promise<void> {
    while (Date.now() < deadline) {
      await this.page.waitForTimeout(2000);
      const stillLoading = await this.isWidgetLoading();
      if (!stillLoading) return;
    }
  }

  private async extractNewBotMessages(beforeCount: number): Promise<string> {
    const allBotMsgs = await this.ftFrame.$$('.js-bot-message');
    const newMsgs = allBotMsgs.slice(beforeCount);

    const texts: string[] = [];
    for (const msg of newMsgs) {
      const raw = await msg.textContent().catch(() => '');
      if (!raw?.trim()) continue;

      // Strip "Bot Response:" prefix and clean up
      const clean = raw.trim().replace(BOT_MSG_PREFIX_RE, '').trim();
      if (clean) texts.push(clean);
    }

    // Also capture quick-reply buttons that may be part of the response
    const buttons = await this.getQuickReplyButtons();
    if (buttons.length > 0) {
      texts.push(`[Quick replies: ${buttons.join(' | ')}]`);
    }

    return texts.join('\n') || '[Empty response]';
  }

  private async getQuickReplyButtons(): Promise<string[]> {
    return this.ftFrame.evaluate(() => {
      const chips = document.querySelectorAll(
        '[class*="chip"], [class*="quick-reply"], [class*="suggestion"], [class*="Chip"]',
      );
      return Array.from(chips)
        .map((el) => el.textContent?.trim())
        .filter((t): t is string => !!t && t.length < 60);
    });
  }

  override async healthCheck(): Promise<boolean> {
    try {
      await this.ensureBrowserCore();
      return !!this.ftFrame;
    } catch {
      return false;
    }
  }
}
