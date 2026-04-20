import type { EmailModuleResult } from '@/types';
import { resolveTxt, queryDoH } from './dns';

function parseDmarcPolicy(raw: string): 'none' | 'quarantine' | 'reject' | undefined {
  const m = /p\s*=\s*(none|quarantine|reject)/i.exec(raw);
  return (m?.[1]?.toLowerCase() as 'none' | 'quarantine' | 'reject' | undefined) ?? undefined;
}

function parseSpfQualifier(raw: string): string | undefined {
  // terminal mechanism: -all / ~all / ?all / +all
  const m = /\s([-~?+])all(\s|$)/.exec(raw);
  return m?.[1];
}

export async function analyzeEmail(
  domain: string,
  dkimSelectors: string[] = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail']
): Promise<EmailModuleResult> {
  try {
    const [rootTxt, dmarcTxt, mtaStsTxt, bimiTxt, mxResp] = await Promise.all([
      resolveTxt(domain),
      resolveTxt(`_dmarc.${domain}`),
      resolveTxt(`_mta-sts.${domain}`),
      resolveTxt(`default._bimi.${domain}`),
      queryDoH(domain, 'MX').catch(() => undefined),
    ]);

    const spfRaw = rootTxt.find((t) => /^v=spf1\b/i.test(t));
    const dmarcRaw = dmarcTxt.find((t) => /^v=DMARC1\b/i.test(t));
    const mtaStsRaw = mtaStsTxt.find((t) => /^v=STSv1\b/i.test(t));
    const bimiRaw = bimiTxt.find((t) => /^v=BIMI1\b/i.test(t));

    const mxPresent = !!mxResp?.Answer?.some((a) => a.type === 15);

    const dkimSelectorProbe = await Promise.all(
      dkimSelectors.map(async (selector) => {
        const txt = await resolveTxt(`${selector}._domainkey.${domain}`);
        const raw = txt.find((t) => /(^|;)\s*(v=DKIM1|k=rsa|p=)/i.test(t));
        return { selector, present: !!raw, raw };
      })
    );

    const result: EmailModuleResult = {
      ok: true,
      spf: { present: !!spfRaw, raw: spfRaw, qualifier: spfRaw ? parseSpfQualifier(spfRaw) : undefined },
      dmarc: { present: !!dmarcRaw, raw: dmarcRaw, policy: dmarcRaw ? parseDmarcPolicy(dmarcRaw) : undefined },
      mtaSts: { present: !!mtaStsRaw, raw: mtaStsRaw },
      bimi: { present: !!bimiRaw, raw: bimiRaw },
      mxPresent,
      dkimSelectorProbe,
    };
    return result;
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      mxPresent: false,
    };
  }
}
