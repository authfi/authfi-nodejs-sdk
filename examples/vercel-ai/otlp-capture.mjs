// A local OTLP/HTTP capture server: the collector the example agent's tracer exports to, so you can
// read exactly what a trace would carry. It listens on 127.0.0.1 only, stores each request body
// under OTLP_DIR (default ./otlp), answers 200 {}, and forwards nothing.
import http from 'node:http';
import fs from 'node:fs';

const DIR = process.env.OTLP_DIR || './otlp';
const PORT = Number(process.env.OTLP_PORT || 4318);
fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
let n = 0;

http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    n += 1;
    const body = Buffer.concat(chunks);
    const name = `${String(n).padStart(4, '0')}-${req.url.replace(/[^a-z0-9]+/gi, '_')}.json`;
    fs.writeFileSync(`${DIR}/${name}`, body, { mode: 0o600 });
    console.log(`[otlp] ${req.method} ${req.url} ${body.length} bytes -> ${name}`);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
}).listen(PORT, '127.0.0.1', () => console.log(`[otlp] listening on 127.0.0.1:${PORT}, writing ${DIR}`));
