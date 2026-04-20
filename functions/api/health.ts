export const onRequest: PagesFunction = async () =>
  new Response(
    JSON.stringify({
      ok: true,
      service: 'netlens',
      version: '0.1.0',
      time: new Date().toISOString(),
    }),
    { headers: { 'content-type': 'application/json' } }
  );
