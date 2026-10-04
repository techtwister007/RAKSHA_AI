const express = require('express');
const minimist = require('minimist');

const argv = minimist(process.argv.slice(2));
const app = express();
app.get('/health', (req, res) => res.json({ ok: true, port: argv.port || 3000 }));
app.listen(argv.port || 3000);
