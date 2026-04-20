import { getCollection, type CollectionEntry } from 'astro:content';

export type Post = CollectionEntry<'blog'>;

// Centralized post helpers so the index, tag pages, and RSS feed share
// ordering and reading-time logic.

export async function getSortedPosts(): Promise<Post[]> {
  const posts = await getCollection('blog');
  return posts.sort((a, b) => b.data.pubDate.getTime() - a.data.pubDate.getTime());
}

export function readingTimeMinutes(post: Post): number {
  const words = post.body.trim().split(/\s+/).length;
  return Math.max(1, Math.round(words / 220));
}

export function formatDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export async function getAllTags(): Promise<Map<string, Post[]>> {
  const posts = await getSortedPosts();
  const map = new Map<string, Post[]>();
  for (const p of posts) {
    for (const t of p.data.tags ?? []) {
      const arr = map.get(t) ?? [];
      arr.push(p);
      map.set(t, arr);
    }
  }
  return map;
}
