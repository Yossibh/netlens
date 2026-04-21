export const onRequest: PagesFunction = async () =>
  new Response(
    JSON.stringify({
      ok: true,
      service: 'netrecon',
      version: '0.1.0',
      time: new Date().toISOString(),
    }),
    { headers: { 'content-type': 'application/json' } }
  );
