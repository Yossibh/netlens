// Test-only stub for `@cloudflare/puppeteer`. See cloudflare-sockets.ts for
// why this exists. The real module is only available inside a Worker runtime
// with a BROWSER binding.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const puppeteer: any = {
  launch: () => {
    throw new Error('@cloudflare/puppeteer is not available in the Node test runner');
  },
};
export default puppeteer;
export type Browser = unknown;
