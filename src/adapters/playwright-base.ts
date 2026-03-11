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
 * `send()` for message delivery.
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

  constructor(config: AdapterConfig) {
    super({ ...config, baseUrl: config.baseUrl });
    this.headless = config.browserHeadless !== false;
    this.responseStabilityMs = config.browserResponseStabilityMs ?? 2000;
    this.preInteraction = config.browserPreInteraction;
  }

  /** Dynamically import playwright (optional peer dependency). */
  protected async loadPlaywright(): Promise<any> {
    try {
      const moduleName = 'playwright';
      return await import(/* webpackIgnore: true */ moduleName);
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

  /** Subclass hook called after page load and pre-interaction, before first send. */
  protected abstract onBrowserReady(): Promise<void>;

  abstract send(messages: Turn[]): Promise<AdapterResponse>;

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
