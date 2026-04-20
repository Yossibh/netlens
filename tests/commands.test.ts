import { describe, it, expect } from 'vitest';
import { generateCommands, commandsForDomain, commandsForIp, commandsForUrl } from '../src/lib/commands';
import { detectInput } from '../src/lib/input-detection';

describe('commands', () => {
  it('generates dig + curl + openssl for domain', () => {
    const cmds = commandsForDomain('example.com');
    expect(cmds.some((c) => c.includes('dig A example.com'))).toBe(true);
    expect(cmds.some((c) => c.includes('dig TXT _dmarc.example.com'))).toBe(true);
    expect(cmds.some((c) => c.includes('openssl s_client -connect example.com:443'))).toBe(true);
    expect(cmds.some((c) => c.startsWith('curl -sSI https://example.com'))).toBe(true);
  });

  it('generates whois + reverse dig for IP', () => {
    const cmds = commandsForIp('1.2.3.4', 'v4');
    expect(cmds).toContain('whois 1.2.3.4');
    expect(cmds.some((c) => c.includes('dig -x 1.2.3.4'))).toBe(true);
  });

  it('generates bracketed curl for IPv6', () => {
    const cmds = commandsForIp('::1', 'v6');
    expect(cmds.some((c) => c.includes('[::1]'))).toBe(true);
  });

  it('generates URL-specific commands', () => {
    const cmds = commandsForUrl('https://example.com/foo');
    expect(cmds.some((c) => c.includes('curl -sSI -L https://example.com/foo'))).toBe(true);
  });

  it('generateCommands is a deduped union', () => {
    const input = detectInput('https://example.com/path');
    const cmds = generateCommands(input);
    expect(cmds.length).toBe(new Set(cmds).size);
    expect(cmds.some((c) => c.includes('dig A example.com'))).toBe(true);
    expect(cmds.some((c) => c.includes('curl -sSI -L https://example.com/path'))).toBe(true);
  });
});
