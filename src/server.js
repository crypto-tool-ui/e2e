/** Encrypted miner gateway; proxy owns pool-side Stratum. */
const { WebSocketServer } = require('ws');
const { generateKeypair, ecdh, createSession } = require('./crypto');
const TcpClient = require('./tcp-client');

const WS_PORT = 8000;
const WS_HOST = "0.0.0.0";
const TCP_HOST = "prl.kryptex.network"
const TCP_PORT = 7048;
const SUBSCRIBE_ID = 1;
const AUTHORIZE_ID = 2;

function retryAfterPoolThrottle(error) {
  // Kryptex error 20 is a temporary login throttle. Spread clients over a
  // minute instead of allowing a synchronized reconnect storm.
  return Array.isArray(error) && Number(error[0]) === 20
    ? 60 + Math.floor(Math.random() * 61)
    : null;
}

const proxyKeypair = process.env.PROXY_PRIVATE_KEY
  ? generateKeypair(process.env.PROXY_PRIVATE_KEY)
  : generateKeypair();
console.log(process.env.PROXY_PRIVATE_KEY ? '[crypto] loaded static keypair' : '[crypto] generated ephemeral keypair');

let totalConns = 0;
let activeConns = 0;
let totalMsgs = 0;

function walletForPool(wallet, worker) {
  const host = TCP_HOST.toLowerCase().replace(/\.$/, '');
  if (host === 'luckypool.io' || host.endsWith('.luckypool.io')) return wallet;
  const plainWallet = wallet.split('+', 1)[0];
  return worker && !plainWallet.includes('.') && !plainWallet.includes('/') ? `${plainWallet}.${worker}` : plainWallet;
}

const wss = new WebSocketServer({ host: WS_HOST, port: WS_PORT });
console.log(`ws://${WS_HOST}:${WS_PORT} → tcp://${TCP_HOST}:${TCP_PORT}`);

wss.on('connection', (ws, req) => {
  const id = ++totalConns;
  activeConns++;
  console.log(`[#${id}] connection from ${req.socket.remoteAddress} (active: ${activeConns})`);

  let session = null;
  let tcp = null;
  let tcpReady = false;
  let poolStarted = false;
  let poolAuthorized = false;
  let registration = null;
  let nextPoolId = 100;
  let discardedEarlyShares = 0;
  let discardedDisconnectedShares = 0;
  const pendingSubmissions = new Map();
  const bufferedPoolUpdates = [];

  const sendWorker = (message) => {
    if (!session || ws.readyState !== 1) return;
    ws.send(session.encrypt(Buffer.from(JSON.stringify(message), 'utf8')).toString('hex'));
    totalMsgs++;
  };

  const startPoolSession = () => {
    if (!tcpReady || !registration || poolStarted) return;
    poolStarted = true;
    const wallet = walletForPool(registration.wallet, registration.worker);
    tcp.send(JSON.stringify({ jsonrpc: '2.0', id: SUBSCRIBE_ID, method: 'mining.subscribe', params: [registration.agent] }));
    tcp.send(JSON.stringify({
      jsonrpc: '2.0', id: AUTHORIZE_ID, method: 'mining.authorize',
      params: { wallet, worker: registration.worker, pass: registration.password, password: registration.password, agent: registration.agent, type: 'v2' },
    }));
    console.log(`[#${id}] pool subscribe/authorize sent for worker ${registration.worker}`);
  };

  const handlePoolMessage = (line) => {
    let message;
    try { message = JSON.parse(line); } catch { console.warn(`[#${id}] ignored non-JSON pool line`); return; }
    totalMsgs++;
    if (message.id === AUTHORIZE_ID) {
      if (!message.result || message.error) {
        // Keep the pool's response in the server log.  It is needed to
        // distinguish invalid credentials from a pool-side rate limit.
        const detail = message.error ? JSON.stringify(message.error) : JSON.stringify(message.result);
        const retryAfter = retryAfterPoolThrottle(message.error);
        const params = { message: retryAfter ? 'pool temporarily busy' : 'pool authorization rejected' };
        if (retryAfter) params.retry_after = retryAfter;
        sendWorker({ method: 'worker.error', params });
        console.error(`[#${id}] pool authorization rejected: ${detail}${retryAfter ? `; retry_after=${retryAfter}s` : ''}`);
        ws.close(retryAfter ? 1013 : 1008, retryAfter ? 'try again later' : 'pool authorization rejected');
        return;
      }
      poolAuthorized = true;
      sendWorker({ method: 'worker.ready', params: { type: message.type || 'v1' } });
      for (const update of bufferedPoolUpdates.splice(0)) {
        if (update.method === 'mining.notify' || update.method === 'job') {
          sendWorker({ method: 'worker.dataset', params: update.params });
        } else {
          sendWorker({ method: 'worker.difficulty', params: update.params });
        }
      }
      console.log(`[#${id}] worker ready`);
      return;
    }
    if (message.method === 'mining.notify' || message.method === 'job') {
      if (poolAuthorized) sendWorker({ method: 'worker.dataset', params: message.params });
      else bufferedPoolUpdates.push(message);
      return;
    }
    if (message.method === 'mining.set_difficulty') {
      if (poolAuthorized) sendWorker({ method: 'worker.difficulty', params: message.params });
      else bufferedPoolUpdates.push(message);
      return;
    }
    if (pendingSubmissions.has(message.id)) {
      const jobId = pendingSubmissions.get(message.id);
      pendingSubmissions.delete(message.id);
      const accepted = Boolean(message.result) && !message.error;
      sendWorker({ method: 'worker.validation_result', params: { job_id: jobId, accepted, error: message.error || null } });
      const detail = accepted ? '' : `: ${JSON.stringify(message.error ?? message.result)}`;
      console.log(`[#${id}] share ${accepted ? 'accepted' : 'rejected'} for job ${jobId}${detail}`);
    }
  };

  const handleMinerMessage = (plain) => {
    let message;
    try { message = JSON.parse(plain); } catch { throw new Error('invalid worker JSON'); }
    if (message.method === 'worker.register') {
      const params = message.params || {};
      if (registration) throw new Error('worker already registered');
      if (![params.wallet, params.password, params.worker].every((value) => typeof value === 'string' && value)) {
        throw new Error('invalid worker registration');
      }
      registration = {
        wallet: params.wallet, password: params.password, worker: params.worker,
        agent: typeof params.agent === 'string' && params.agent ? params.agent : 'FFPG/unknown',
      };
      startPoolSession();
      return;
    }
    if (message.method === 'worker.solution') {
      // During a rolling deployment an older worker can still have a share
      // queued when it reconnects.  It cannot belong to this pool session,
      // so drop it rather than returning worker.error and forcing another
      // reconnect loop.
      if (!poolAuthorized) {
        discardedEarlyShares++;
        if (discardedEarlyShares === 1) {
          console.warn(`[#${id}] discarded share before pool authorization`);
        }
        return;
      }
      if (!tcp || !tcp.connected) {
        // tcp.on('close') and the WebSocket close callback are asynchronous.
        // Do not turn late GPU shares in that window into worker.error loops.
        discardedDisconnectedShares++;
        if (discardedDisconnectedShares === 1) {
          console.warn(`[#${id}] discarded share after TCP disconnect`);
        }
        return;
      }
      if (!message.params || typeof message.params.job_id !== 'string') throw new Error('invalid share');
      const requestId = nextPoolId++;
      pendingSubmissions.set(requestId, message.params.job_id);
      tcp.send(JSON.stringify({ jsonrpc: '2.0', id: requestId, method: 'mining.submit', params: message.params }));
      totalMsgs++;
      return;
    }
    throw new Error(`unsupported worker method: ${message.method}`);
  };

  ws.on('message', (data, isBinary) => {
    if (isBinary || (!Buffer.isBuffer(data) && typeof data !== 'string')) return;
    const wireText = data.toString('utf8');
    if (!session) {
      try {
        if (!/^[0-9a-f]{64}$/i.test(wireText)) throw new Error('invalid client public key');
        session = createSession(ecdh(proxyKeypair.privateKeyObj, Buffer.from(wireText, 'hex')), 'server');
        ws.send(proxyKeypair.publicKey.toString('hex'));
      } catch (error) {
        console.error(`[#${id}] E2E handshake error: ${error.message}`);
        ws.close(1008, 'invalid handshake');
        return;
      }
      tcp = new TcpClient(TCP_HOST, TCP_PORT);
      tcp.connect().then(() => { tcpReady = true; console.log(`[#${id}] TCP connected`); startPoolSession(); })
        .catch((error) => { console.error(`[#${id}] TCP failed: ${error.message}`); ws.close(1011, 'backend unreachable'); });
      tcp.on('message', handlePoolMessage);
      tcp.on('close', ({ hadError, bufferedData }) => {
        // This must happen before closing the WebSocket: workers can send a
        // final queued share while the close handshake is in progress.
        poolAuthorized = false;
        pendingSubmissions.clear();
        const suffix = bufferedData ? `; unterminated data=${JSON.stringify(bufferedData)}` : '';
        console.log(`[#${id}] TCP disconnected (hadError=${hadError})${suffix}`);
        if (ws.readyState === 1) ws.close(1011, 'backend closed');
      });
      tcp.on('error', (error) => console.error(`[#${id}] TCP error: ${error.message}`));
      return;
    }
    try {
      if (!/^[0-9a-f]+$/i.test(wireText) || wireText.length % 2 !== 0) throw new Error('invalid hexadecimal payload');
      handleMinerMessage(session.decrypt(Buffer.from(wireText, 'hex')).toString('utf8').trim());
    } catch (error) {
      console.error(`[#${id}] worker message error: ${error.message}`);
      sendWorker({ method: 'worker.error', params: { message: error.message } });
    }
  });

  ws.on('close', (code, reason) => {
    activeConns--;
    if (tcp) tcp.close();
    console.log(`[#${id}] WS closed code=${code} reason=${JSON.stringify(reason.toString())} (active: ${activeConns})`);
  });
  ws.on('error', (error) => console.error(`[#${id}] WS error: ${error.message}`));
});

setInterval(() => { if (activeConns || totalMsgs) console.log(`[stats] active=${activeConns} total=${totalConns} msgs=${totalMsgs}`); }, 60_000);
process.on('SIGINT', () => { console.log('\n[proxy] shutting down...'); wss.close(() => process.exit(0)); });
process.on('SIGTERM', () => { wss.close(() => process.exit(0)); });
