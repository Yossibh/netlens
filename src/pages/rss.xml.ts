import rss from '@astrojs/rss';
import type { APIContext } from 'astro';
import { getSortedPosts } from '../lib/blog';

export async function GET(context: APIContext) {
  const posts = await getSortedPosts();
  return rss({
    title: 'netlens - writing',
    description: 'Essays on SRE, security, applied AI, and network diagnostics by Yossi Ben Hagai.',
    site: context.site ?? 'https://netlens.pages.dev',
    items: posts.map((p) => ({
      title: p.data.title,
      description: p.data.description,
      pubDate: p.data.pubDate,
      link: `/blog/${p.slug}/`,
      author: p.data.author,
      categories: p.data.tags,
    })),
    customData: '<language>en-us</language>',
  });
}
