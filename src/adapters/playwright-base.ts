import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

const DEFAULT_USER_AGENT =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

/**
 * Shared Playwright lifecycle for browser-based adapters.
 *
 * Handles browser launch, page navigation, pre-interaction hooks,
 * session reset, close, and health check. Subclasses implement
 * `onBrowserReady()` for widget-specific initialization and
 * `sendCore()` for message delivery.
 *
 * Features:
 *   - `browserFreshContextPerSend`: creates a fresh browser context before each
 *     send, clearing cookies/storage. Essential for targets with server-side
 *     session persistence.
 *   - `browserAdaptiveTimeout`: on timeout, retries once with doubled timeout.
 *
 * Requires `playwright` as an optional peer dependency:
 *   pnpm add playwright && npx playwright install chromium
 */
export abstract class PlaywrightBaseAdapter extends BaseAdapter {
  protected browser: any = null;
  protected page: any = null;
  protected initialized = false;

  protected readonly headless: boolean;
  protected readonly responseStabilityMs: number;
  private readonly preInteraction: string | undefined;
  private readonly freshContextPerSend: boolean;
  private readonly adaptiveTimeout: boolean;
  private pw: any = null;

  constructor(config: AdapterConfig) {
    super({ ...config, baseUrl: config.baseUrl });
    this.headless = config.browserHeadless !== false;
    this.responseStabilityMs = config.browserResponseStabilityMs ?? 2000;
    this.preInteraction = config.browserPreInteraction;
    this.freshContextPerSend = config.browserFreshContextPerSend === true;
    this.adaptiveTimeout = config.browserAdaptiveTimeout === true;
  }

  /** Dynamically import playwright (optional peer dependency). */
  protected async loadPlaywright(): Promise<any> {
    if (this.pw) return this.pw;
    try {
      const moduleName = 'playwright';
      this.pw = await import(/* webpackIgnore: true */ moduleName);
      return this.pw;
    } catch {
      throw new Error(
        'Playwright adapter requires playwright. Install it:\n' +
          '  pnpm add playwright && npx playwright install chromium',
      );
    }
  }

  /**
   * Launch browser, navigate to baseUrl, run pre-interaction hook,
   * then call the subclass `onBrowserReady()` hook.
   */
  protected async ensureBrowserCore(): Promise<any> {
    if (this.initialized) return this.page;

    const pw = await this.loadPlaywright();
    this.browser = await pw.chromium.launch({ headless: this.headless });
    const context = await this.browser.newContext({ userAgent: DEFAULT_USER_AGENT });
    this.page = await context.newPage();

    await this.page.goto(this.config.baseUrl, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    // Allow page scripts and widgets to initialize
    await this.page.waitForTimeout(5000);

    // Run pre-interaction hook if provided (e.g. dismiss cookie banner)
    if (this.preInteraction) {
      await this.page.evaluate(this.preInteraction);
      await this.page.waitForTimeout(3000);
    }

    await this.onBrowserReady();

    this.initialized = true;
    return this.page;
  }

  /**
   * When freshContextPerSend is enabled, tear down the current browser context
   * and reinitialize a new one. This clears all cookies/storage, giving each
   * probe a clean session.
   */
  protected async resetBrowserContext(): Promise<void> {
    if (!this.browser) return;
    // Close all existing pages/contexts
    const contexts = this.browser.contexts?.() ?? [];
    for (const ctx of contexts) {
      await ctx.close().catch(() => {});
    }
    this.page = null;
    this.initialized = false;
    this.onSessionReset();

    // Re-create context and page
    const context = await this.browser.newContext({ userAgent: DEFAULT_USER_AGENT });
    this.page = await context.newPage();
    await this.page.goto(this.config.baseUrl, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    await this.page.waitForTimeout(5000);

    if (this.preInteraction) {
      await this.page.evaluate(this.preInteraction);
      await this.page.waitForTimeout(3000);
    }

    await this.onBrowserReady();
    this.initialized = true;
  }

  /** Subclass hook called after page load and pre-interaction, before first send. */
  protected abstract onBrowserReady(): Promise<void>;

  /**
   * Subclasses implement this to perform the actual message send.
   * The base class `send()` wraps this with fresh-context and adaptive-timeout logic.
   */
  protected abstract sendCore(messages: Turn[]): Promise<AdapterResponse>;

  /**
   * Send messages with optional fresh-context isolation and adaptive timeout retry.
   *
   * Flow:
   * 1. If `browserFreshContextPerSend`, reset browser context first
   * 2. Try sendCore()
   * 3. If timeout and `browserAdaptiveTimeout`, retry once with 2x timeout
   * 4. If still timeout, return partial response with `timedOut: true`
   */
  async send(messages: Turn[]): Promise<AdapterResponse> {
    if (this.freshContextPerSend && this.initialized) {
      await this.resetBrowserContext();
    }

    try {
      return await this.sendCore(messages);
    } catch (err: unknown) {
      if (!this.isTimeoutError(err)) throw err;

      if (this.adaptiveTimeout) {
        // Retry with doubled timeout
        const baseTimeout = this.config.timeout ?? 60_000;
        const retryTimeout = baseTimeout * 2;
        const savedTimeout = this.config.timeout;
        this.config.timeout = retryTimeout;

        try {
          // Fresh context for the retry to avoid stale state
          if (this.initialized) {
            await this.resetBrowserContext();
          }
          return await this.sendCore(messages);
        } catch (retryErr: unknown) {
          this.config.timeout = savedTimeout;
          if (!this.isTimeoutError(retryErr)) throw retryErr;

          // Both attempts timed out — return timedOut response
          return {
            content: '[No response — timed out]',
            raw: { method: 'timeout', timeoutMs: retryTimeout },
            latencyMs: retryTimeout,
            timedOut: true,
          };
        } finally {
          this.config.timeout = savedTimeout;
        }
      }

      // No adaptive timeout — return timedOut response directly
      const timeout = this.config.timeout ?? 60_000;
      return {
        content: '[No response — timed out]',
        raw: { method: 'timeout', timeoutMs: timeout },
        latencyMs: timeout,
        timedOut: true,
      };
    }
  }

  /** Check if an error is a timeout error from the widget wait loops. */
  private isTimeoutError(err: unknown): boolean {
    if (!(err instanceof Error)) return false;
    return /no (?:reply|response|.*reply) within/i.test(err.message) || /timeout/i.test(err.message);
  }

  override async healthCheck(): Promise<boolean> {
    try {
      await this.ensureBrowserCore();
      return true;
    } catch {
      return false;
    }
  }

  override resetSession(): void {
    // Capture references before clearing, so the async close
    // cannot clobber a new browser created by ensureBrowserCore().
    const oldBrowser = this.browser;
    this.browser = null;
    this.page = null;
    this.initialized = false;

    this.onSessionReset();

    if (oldBrowser) {
      void (oldBrowser as { close: () => Promise<void> }).close();
    }
  }

  /** Optional hook for subclasses to clear their own state during resetSession. */
  protected onSessionReset(): void {
    // No-op by default
  }

  override async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.page = null;
      this.initialized = false;
    }
  }
}
