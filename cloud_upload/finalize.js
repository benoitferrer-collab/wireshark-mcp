export async function finalizeJob(manifest, authorization, options = {}) {
 const fetcher = options.fetcher || fetch;
 const sleep = options.sleep || (ms => new Promise(resolve => setTimeout(resolve, ms)));
 for (let attempt = 0; attempt < 3; attempt++) {
  try {
   const response = await fetcher('/api/cloud/jobs', {
    method: 'POST', headers: { Authorization: authorization, 'Content-Type': 'application/json' },
    body: JSON.stringify(manifest),
   });
   if ((response.status < 500 && response.status !== 429) || attempt === 2) return response;
  } catch (error) { if (attempt === 2) throw error; }
  await sleep(500 * (attempt + 1));
 }
}
