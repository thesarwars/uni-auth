import { Eta } from 'eta';
import { assetUrls } from '../flows/assets.controller';

/**
 * The template engine, as the app and the tests both build it. Every template can call
 * asset('icons/mail.svg') for an asset's versioned URL (assetUrl): the URLs are fixed at start,
 * so they are written into each compiled template as a plain object.
 */
export function createEta(views: string, cache = false): Eta {
  const urls = JSON.stringify(assetUrls());
  return new Eta({
    views,
    cache,
    functionHeader:
      `const __assets = ${urls};` +
      `const asset = (name) => __assets[name] || ('/assets/' + name);`,
  });
}
