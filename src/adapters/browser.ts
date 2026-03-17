import { PlaywrightBaseAdapter } from './playwright-base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Browser-based chat widget adapter using Playwright.
 *
 * Automates a real browser to interact with any embedded AI chat widget
 * (Intercom Messenger, Drift, Zendesk, generic chat, etc.).
 *
 * Requires `playwright` as an optional peer dependency:
 *   pnpm add playwright && npx playwright install chromium
 *
 * Config options:
 *   - baseUrl: the page URL containing the chat widget
 *   - chatInputSelector: CSS selector for the chat input (auto-detected if omitted)
 *   - chatSubmitSelector: CSS selector for the submit button (auto-detected if omitted)
 *   - chatResponseSelector: CSS selector for bot response messages (auto-detected if omitted)
 *   - browserHeadless: run headless (default: true)
 *   - browserPreInteraction: JS snippet to run in page before chat interaction
 *   - browserLauncherSelector: CSS selector for chat launcher button (clicked before auto-detection)
 *   - browserFreshContextPerSend: fresh browser context per send (default: false)
 *   - browserAdaptiveTimeout: retry on timeout with 2x timeout (default: false)
 */
export class BrowserAdapter extends PlaywrightBaseAdapter {
  private detectedInputSelector: string;
  private detectedSubmitSelector: string;
  private detectedResponseSelector: string;
  private chatFrame: any = null;
  private readonly launcherSelector: string | undefined;

  private static readonly RESPONSE_CANDIDATES = [
    '[data-testid="bot-message"]',
    '[data-testid="assistant-message"]',
    '.bot-message',
    '.assistant-message',
    '.agent-message',
    '[data-message-author="bot"]',
    '[data-author-type="bot"]',
    '[data-author-type="admin"]',
    'div.group\\/message',
    '.prose',
    '.markdown',
    '[class*="markdown"]',
    // Gorgias
    '[class*="message-window-iframe"]',
    '[data-testid="message-bubble"]',
    // Zendesk
    '[data-garden-id="chat.message"]',
    '[class*="StyledMessage"]',
    '.zd-chat-message',
    // Drift
    '[class*="drift-widget-message"]',
    // Tidio
    '[class*="message-visitor"]',
    '[class*="message-operator"]',
    // Ada
    '[class*="ada-chat-message"]',
    // LivePerson / generic
    '[class*="lp_message"]',
    '[class*="chat-message"]',
    '[class*="chatMessage"]',
    '[class*="bot-response"]',
    '[class*="botResponse"]',
    // Microsoft Bot Framework / WebChat
    '[class*="webchat__bubble"]',
    '[class*="ac-textBlock"]',
  ];

  constructor(config: AdapterConfig) {
    super(config);

    this.detectedInputSelector = config.chatInputSelector ?? '';
    this.detectedSubmitSelector = config.chatSubmitSelector ?? '';
    this.detectedResponseSelector = config.chatResponseSelector ?? '';
    this.launcherSelector = config.browserLauncherSelector;
  }

  /** Common launcher selectors tried when no explicit launcher is configured. */
  private static readonly LAUNCHER_CANDIDATES = [
    // Gorgias
    'iframe#chat-button',
    // Intercom
    '.intercom-lightweight-app-launcher',
    'div[class*="intercom-launcher"]',
    // Zendesk
    'iframe[title*="chat" i]',
    '[data-testid="launcher"]',
    // Drift
    '#drift-widget-container iframe',
    // Tidio
    '#tidio-chat-iframe',
    // Ada
    '#ada-chat-button',
    // Generic
    '[class*="chat-launcher"]',
    '[class*="chat-button"]',
    '[class*="chatLauncher"]',
    '[aria-label*="chat" i][role="button"]',
    'button[aria-label*="chat" i]',
  ];

  protected override async onBrowserReady(): Promise<void> {
    this.chatFrame = null;

    // Click explicit launcher or try auto-detecting one
    if (this.launcherSelector) {
      const launcher = await this.page.$(this.launcherSelector);
      if (launcher) {
        await this.clickLauncher(launcher);
      }
    } else {
      await this.tryAutoLauncher();
    }

    if (!this.detectedInputSelector || !this.detectedResponseSelector) {
      await this.autoDetectSelectors();
    }
  }

  /** Click a launcher element, handling iframes (e.g. Gorgias chat-button is an iframe). */
  private async clickLauncher(launcher: any /* ElementHandle */): Promise<void> {
    const tag = await launcher.evaluate((el: Element) => el.tagName);
    if (tag === 'IFRAME') {
      // Click inside the iframe (some launchers like Gorgias are iframes)
      const box = await launcher.boundingBox();
      if (box) {
        await this.page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
      }
    } else {
      await launcher.click();
    }
    await this.page.waitForTimeout(3000);
  }

  /** Try common launcher selectors to open hidden chat widgets. */
  private async tryAutoLauncher(): Promise<void> {
    for (const sel of BrowserAdapter.LAUNCHER_CANDIDATES) {
      const el = await this.page.$(sel).catch(() => null);
      if (el) {
        const visible = await el.isVisible().catch(() => false);
        if (visible) {
          await this.clickLauncher(el);
          return;
        }
      }
    }
  }

  private async autoDetectSelectors(): Promise<void> {
    const inputCandidates = [
      'iframe[name="intercom-messenger-frame"]',
      '[data-testid="chat-input"]',
      // Gorgias
      '#chat-message-input',
      'textarea[aria-label*="live chat" i]',
      // Zendesk
      'textarea[aria-label*="Type a message" i]',
      '[data-garden-id="chat.textInput"]',
      // Drift
      'textarea[data-testid="chat-input"]',
      // Generic textarea patterns
      'textarea[placeholder*="message" i]',
      'textarea[placeholder*="type" i]',
      'textarea[placeholder*="ask" i]',
      'textarea[placeholder*="question" i]',
      'textarea[placeholder*="chat" i]',
      'input[placeholder*="message" i]',
      'input[placeholder*="type" i]',
      'input[placeholder*="ask" i]',
      'input[placeholder*="question" i]',
      // Aria label patterns
      '[aria-label*="message input" i]',
      '[aria-label*="chat input" i]',
      '[aria-label*="Message input" i]',
      '[aria-label*="message" i][role="textbox"]',
      '[contenteditable="true"][role="textbox"]',
      '[contenteditable="true"][aria-label*="message" i]',
      // Structural patterns
      '.chat-input textarea',
      '.chat-input input',
      '#chat-input',
      '[aria-label*="chat" i] textarea',
      '[aria-label*="chat" i] input',
      '[aria-label*="message" i]',
      // Microsoft Bot Framework / WebChat
      'input[class*="webchat__send-box"]',
      '[class*="webchat__send-box"] input',
    ];

    const submitCandidates = [
      'button[type="submit"]',
      'button[aria-label*="send" i]',
      '[data-testid="send-button"]',
      '#chat-message-input-send-button',
      '[class*="send-button"]',
      '.chat-submit',
      '#chat-submit',
      'button[class*="submit"]',
    ];

    // Check for Intercom iframe first — only set selectors not already provided by user
    const intercomFrame = await this.page.$('iframe[name="intercom-messenger-frame"]');
    if (intercomFrame) {
      if (!this.detectedInputSelector) this.detectedInputSelector = '__intercom_frame__';
      if (!this.detectedSubmitSelector) this.detectedSubmitSelector = '__intercom_frame__';
      if (!this.detectedResponseSelector) this.detectedResponseSelector = '__intercom_frame__';
      return;
    }

    const searchContexts: { ctx: any; isFrame: boolean }[] = [{ ctx: this.page, isFrame: false }];

    // Collect candidate iframes (skip non-chat iframes)
    const skipPatterns = ['stripe.com', 'google.com', 'analytics', 'recaptcha', 'optimizely', 'adsrvr', 'flashtalking'];
    for (const frame of this.page.frames()) {
      const url = frame.url();
      if (frame === this.page.mainFrame()) continue;
      // Include about:srcdoc frames (used by Gorgias, Ada, and other inline widget renderers)
      const isSrcdoc = url === 'about:srcdoc';
      const isCandidate = isSrcdoc || (url && url !== 'about:blank' && !skipPatterns.some((p) => url.includes(p)));
      if (isCandidate) {
        searchContexts.push({ ctx: frame, isFrame: true });
      }
    }

    for (const { ctx, isFrame } of searchContexts) {
      if (!this.detectedInputSelector) {
        for (const sel of inputCandidates) {
          if (sel.startsWith('iframe[')) continue; // skip iframe-matching selectors inside frames
          const el = await ctx.$(sel).catch(() => null);
          if (el) {
            this.detectedInputSelector = sel;
            if (isFrame) this.chatFrame = ctx;
            break;
          }
        }
      }

      if (this.detectedInputSelector && isFrame === !!this.chatFrame) {
        if (!this.detectedSubmitSelector) {
          for (const sel of submitCandidates) {
            const el = await ctx.$(sel).catch(() => null);
            if (el) {
              this.detectedSubmitSelector = sel;
              break;
            }
          }
        }

        if (!this.detectedResponseSelector) {
          for (const sel of BrowserAdapter.RESPONSE_CANDIDATES) {
            const el = await ctx.$(sel).catch(() => null);
            if (el) {
              this.detectedResponseSelector = sel;
              break;
            }
          }
        }

        break;
      }
    }

    if (!this.detectedInputSelector) {
      throw new Error(
        'Browser adapter: could not auto-detect chat input. ' + 'Provide --chat-input-selector explicitly.',
      );
    }
  }

  protected async sendCore(messages: Turn[]): Promise<AdapterResponse> {
    await this.ensureBrowserCore();

    const lastUser = messages.filter((m) => m.role === 'user').pop();
    const message = lastUser?.content ?? '';

    const start = performance.now();

    if (this.detectedInputSelector === '__intercom_frame__') {
      const content = await this.sendIntercomFrame(message);
      const latencyMs = Math.round(performance.now() - start);
      return { content, raw: { method: 'intercom-frame' }, latencyMs };
    }

    const content = await this.sendGenericWidget(message);
    const latencyMs = Math.round(performance.now() - start);
    return { content, raw: { method: 'generic-widget' }, latencyMs };
  }

  private async sendIntercomFrame(message: string): Promise<string> {
    const frame = this.page.frame({ name: 'intercom-messenger-frame' });

    if (!frame) {
      throw new Error('Browser adapter: Intercom messenger frame not found');
    }

    // Count existing messages before sending
    const beforeMessages = await frame.$$('[data-testid="message-body"], [class*="intercom-block"]');
    const beforeCount = beforeMessages.length;

    // Find the composer input inside the Intercom frame
    const composerSelectors = [
      '[aria-label="Write a message\u2026"]',
      '[aria-label="Write your message\u2026"]',
      '.intercom-composer textarea',
      '.intercom-composer [contenteditable]',
      'textarea',
      '[contenteditable="true"]',
    ];

    let composer: any = null;
    for (const sel of composerSelectors) {
      composer = await frame.$(sel);
      if (composer) break;
    }

    if (!composer) {
      throw new Error('Browser adapter: could not find Intercom chat composer');
    }

    await composer.click();
    await composer.fill(message);
    await composer.press('Enter');

    // Wait for a new message to appear
    const timeout = this.config.timeout ?? 60_000;
    const deadline = Date.now() + timeout;

    while (Date.now() < deadline) {
      await this.page.waitForTimeout(this.responseStabilityMs);

      const afterMessages = await frame.$$('[data-testid="message-body"], [class*="intercom-block"]');
      if (afterMessages.length > beforeCount) {
        const lastMsg = afterMessages[afterMessages.length - 1];
        const text = await lastMsg.textContent();
        if (text && text.trim()) {
          // Wait a bit more to ensure the message is complete (streaming)
          await this.page.waitForTimeout(1000);
          const finalMessages = await frame.$$('[data-testid="message-body"], [class*="intercom-block"]');
          const finalMsg = finalMessages[finalMessages.length - 1];
          const finalText = await finalMsg.textContent();
          return (finalText ?? text).trim();
        }
      }
    }

    throw new Error(`Browser adapter: no Intercom reply within ${timeout / 1000}s`);
  }

  private get widgetContext(): any {
    return this.chatFrame ?? this.page;
  }

  private async sendGenericWidget(message: string): Promise<string> {
    const ctx = this.widgetContext;

    // Snapshot text before sending for text-diff fallback
    const beforeText = await ctx.evaluate(() => document.body.innerText?.trim() ?? '').catch(() => '');

    let beforeCount = 0;
    if (this.detectedResponseSelector) {
      const beforeMsgs = await ctx.$$(this.detectedResponseSelector);
      beforeCount = beforeMsgs.length;
    }

    const input = await ctx.$(this.detectedInputSelector);
    if (!input) {
      throw new Error(`Browser adapter: chat input not found at "${this.detectedInputSelector}"`);
    }

    await input.click();
    await input.fill(message);

    if (this.detectedSubmitSelector) {
      const btn = await ctx.$(this.detectedSubmitSelector);
      if (btn) {
        await btn.click();
      } else {
        await input.press('Enter');
      }
    } else {
      await input.press('Enter');
    }

    if (this.detectedResponseSelector) {
      return this.waitForNewMessage(beforeCount);
    }

    // Response container may only appear after the first message
    await this.page.waitForTimeout(3000);
    await this.lateDetectResponseSelector(ctx);
    if (this.detectedResponseSelector) {
      return this.waitForNewMessage(0);
    }

    // Fallback: text-diff detection — compare page text before/after and extract new content
    return this.waitForTextDiff(ctx, beforeText, message);
  }

  /**
   * Fallback response detection via text diffing.
   * Compares page innerText before/after sending and extracts new content,
   * filtering out the user's own message.
   */
  private async waitForTextDiff(
    ctx: any /* Page | FrameLocator */,
    beforeText: string,
    sentMessage: string,
  ): Promise<string> {
    const timeout = this.config.timeout ?? 60_000;
    const deadline = Date.now() + timeout;
    const stabilityMs = Math.min(this.responseStabilityMs, 3000);
    let lastNewText = '';

    while (Date.now() < deadline) {
      await this.page.waitForTimeout(2000);

      const currentText: string = await ctx.evaluate(() => document.body.innerText?.trim() ?? '').catch(() => '');
      if (currentText === beforeText) continue;

      let newText: string;
      if (currentText.length > beforeText.length) {
        newText = currentText.substring(beforeText.length).trim();
      } else {
        // Text changed but didn't grow — find content not present in beforeText
        const beforeLines = new Set(
          beforeText
            .split('\n')
            .map((l) => l.trim())
            .filter(Boolean),
        );
        newText = currentText
          .split('\n')
          .map((l) => l.trim())
          .filter((l) => l && !beforeLines.has(l))
          .join('\n')
          .trim();
      }
      if (!newText) continue;

      // Remove the user's sent message from the new text
      const cleaned = this.extractBotReplyFromDiff(newText, sentMessage);
      if (!cleaned) continue;

      // Skip loading/thinking indicators
      if (/^(loading|thinking|gathering|typing|processing)\.{0,3}$/i.test(cleaned)) continue;

      // Check stability
      if (cleaned === lastNewText) {
        // Stable — wait one more cycle to be sure
        await this.page.waitForTimeout(stabilityMs);
        const finalText: string = await ctx.evaluate(() => document.body.innerText?.trim() ?? '').catch(() => '');
        const finalNew = finalText.length > beforeText.length ? finalText.substring(beforeText.length).trim() : '';
        const finalCleaned = this.extractBotReplyFromDiff(finalNew, sentMessage);
        return finalCleaned || cleaned;
      }
      lastNewText = cleaned;
    }

    return '[No response — timed out]';
  }

  /** Extract bot reply from a text diff, removing the user's sent message and noise. */
  private extractBotReplyFromDiff(newText: string, sentMessage: string): string {
    const lines = newText
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);

    // Remove lines that match the user's message
    const sentNorm = sentMessage.replace(/\s+/g, ' ').trim().toLowerCase();
    const filtered = lines.filter((line) => {
      const lineNorm = line.replace(/\s+/g, ' ').trim().toLowerCase();
      return !lineNorm.includes(sentNorm) && !sentNorm.includes(lineNorm);
    });

    // Remove common noise patterns (timestamps, UI labels)
    const cleaned = filtered.filter(
      (line) =>
        !/^\d{1,2}:\d{2}\s*(AM|PM)?$/i.test(line) &&
        !/^(you said|bot said|sent|delivered)$/i.test(line) &&
        line.length > 1,
    );

    return cleaned.join('\n').trim();
  }

  /** Detect response selector post-interaction (some UIs only render it after the first message). */
  private async lateDetectResponseSelector(ctx: any): Promise<void> {
    for (const sel of BrowserAdapter.RESPONSE_CANDIDATES) {
      const el = await ctx.$(sel).catch(() => null);
      if (el) {
        const text = await el.textContent().catch(() => '');
        if (text && text.trim().length > 5) {
          this.detectedResponseSelector = sel;
          break;
        }
      }
    }
  }

  /**
   * Wait for a new bot message using a MutationObserver inside the page.
   * Falls back to polling if the observer doesn't fire.
   */
  private async waitForNewMessage(beforeCount: number): Promise<string> {
    const timeout = this.config.timeout ?? 60_000;
    const selector = this.detectedResponseSelector;
    const ctx = this.widgetContext;

    const content = await Promise.race([
      ctx.evaluate(
        ({ sel, prevCount, stabilityMs }: { sel: string; prevCount: number; stabilityMs: number }) => {
          return new Promise<string>((resolve, reject) => {
            let stabilityTimer: ReturnType<typeof setTimeout> | null = null;
            let lastText = '';

            const checkStability = () => {
              const msgs = document.querySelectorAll(sel);
              if (msgs.length <= prevCount) return;

              const last = msgs[msgs.length - 1];
              const text = last.textContent?.trim() ?? '';
              if (!text || /^loading\.{0,3}$/i.test(text) || text === '…' || text === '...') return;
              // Skip short thinking/progress indicators
              if (
                text.length < 50 &&
                /^(analyzing|preparing|understanding|thinking|processing|searching|looking|generating|writing|selecting|reading|reviewing|checking|fetching|retrieving|consulting|gathering|compiling|organizing|summarizing|evaluating|considering|formulating|crafting|figuring|working|pulling|finding|connecting|loading)\b/i.test(
                  text,
                )
              )
                return;

              if (text !== lastText) {
                lastText = text;
                if (stabilityTimer) clearTimeout(stabilityTimer);
                stabilityTimer = setTimeout(() => {
                  const final = document.querySelectorAll(sel);
                  const finalEl = final[final.length - 1];
                  const finalText = (finalEl?.textContent ?? text).trim();
                  if ((window as any).__keelsonObserver) {
                    (window as any).__keelsonObserver.disconnect();
                    (window as any).__keelsonObserver = undefined;
                  }
                  resolve(finalText);
                }, stabilityMs);
              }
            };

            checkStability();

            const observer = new MutationObserver(() => checkStability());

            (window as any).__keelsonObserver = observer;
            observer.observe(document.body, { childList: true, subtree: true, characterData: true });

            void reject; // rejection handled externally by Promise.race timeout
          });
        },
        { sel: selector, prevCount: beforeCount, stabilityMs: Math.min(this.responseStabilityMs, 3000) },
      ),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error(`Browser adapter: no reply within ${timeout / 1000}s`)), timeout),
      ),
    ]).finally(() => {
      const cleanupCtx = this.chatFrame ?? this.page;
      cleanupCtx
        ?.evaluate(() => {
          (window as any).__keelsonObserver?.disconnect();
        })
        .catch(() => {});
    });

    return content;
  }
}
