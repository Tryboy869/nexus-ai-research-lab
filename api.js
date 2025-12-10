// api.js - NEXUS AI Research Lab - API Gateway

import express from 'express';
import { WebSocketServer } from 'ws';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { BackendService } from './server.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// ═══════════════════════════════════════════════════════════
// SECURITY & LOGGING
// ═══════════════════════════════════════════════════════════

class SecurityLogger {
  constructor() {
    this.logs = [];
    this.maxLogsInMemory = 1000;
    this.rateLimits = new Map();
    this.blockedIPs = new Set();
    
    if (!fs.existsSync('logs')) {
      fs.mkdirSync('logs');
    }
  }
  
  log(level, type, data) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      type,
      ...data
    };
    
    this.logs.push(entry);
    if (this.logs.length > this.maxLogsInMemory) {
      this.logs.shift();
    }
    
    console.log(`[${level}] [${type}]`, JSON.stringify(data));
    
    this.writeToFile(level, entry);
  }
  
  writeToFile(level, entry) {
    const date = new Date().toISOString().split('T')[0];
    const logLine = `[${entry.timestamp}] [${entry.level}] [${entry.type}] ${JSON.stringify(entry)}\n`;
    
    fs.appendFileSync(`logs/api-${date}.log`, logLine);
    
    if (level === 'SECURITY') {
      fs.appendFileSync(`logs/security-${date}.log`, logLine);
    }
    
    if (level === 'ERROR') {
      fs.appendFileSync(`logs/errors-${date}.log`, logLine);
    }
  }
  
  info(type, data) {
    this.log('INFO', type, data);
  }
  
  warn(type, data) {
    this.log('WARN', type, data);
  }
  
  error(type, data) {
    this.log('ERROR', type, data);
  }
  
  security(type, data) {
    this.log('SECURITY', type, data);
  }
  
  checkRateLimit(identifier, limit = 100, windowMs = 15 * 60 * 1000) {
    const now = Date.now();
    
    if (!this.rateLimits.has(identifier)) {
      this.rateLimits.set(identifier, []);
    }
    
    const requests = this.rateLimits.get(identifier);
    const validRequests = requests.filter(time => now - time < windowMs);
    
    if (validRequests.length >= limit) {
      this.security('RATE_LIMIT_EXCEEDED', {
        identifier,
        requests: validRequests.length,
        limit
      });
      return false;
    }
    
    validRequests.push(now);
    this.rateLimits.set(identifier, validRequests);
    
    return true;
  }
  
  validateRequest(req) {
    const ip = req.ip || req.connection.remoteAddress;
    
    if (this.blockedIPs.has(ip)) {
      this.security('BLOCKED_IP_ATTEMPT', { ip, endpoint: req.path });
      return { valid: false, reason: 'IP blocked' };
    }
    
    if (!this.checkRateLimit(ip, 100, 15 * 60 * 1000)) {
      return { valid: false, reason: 'Rate limit exceeded' };
    }
    
    if (req.body && JSON.stringify(req.body).length > 10 * 1024 * 1024) {
      this.warn('LARGE_PAYLOAD', { ip, size: JSON.stringify(req.body).length });
      return { valid: false, reason: 'Payload too large' };
    }
    
    return { valid: true };
  }
  
  getRecentLogs(limit = 100) {
    return this.logs.slice(-limit).reverse();
  }
  
  getStats() {
    const last24h = Date.now() - 24 * 60 * 60 * 1000;
    const recentLogs = this.logs.filter(l => new Date(l.timestamp) > last24h);
    
    return {
      total: recentLogs.length,
      byLevel: {
        INFO: recentLogs.filter(l => l.level === 'INFO').length,
        WARN: recentLogs.filter(l => l.level === 'WARN').length,
        ERROR: recentLogs.filter(l => l.level === 'ERROR').length,
        SECURITY: recentLogs.filter(l => l.level === 'SECURITY').length
      },
      blockedIPs: Array.from(this.blockedIPs)
    };
  }
}

const securityLogger = new SecurityLogger();

// Security Middleware
app.use((req, res, next) => {
  const startTime = Date.now();
  const ip = req.ip || req.connection.remoteAddress;
  const userId = req.headers['x-user-id'] || 'anonymous';
  
  const validation = securityLogger.validateRequest(req);
  
  if (!validation.valid) {
    securityLogger.security('REQUEST_BLOCKED', {
      ip,
      userId,
      method: req.method,
      endpoint: req.path,
      reason: validation.reason
    });
    
    return res.status(403).json({
      success: false,
      message: 'Request blocked for security reasons'
    });
  }
  
  securityLogger.info('API_REQUEST', {
    ip,
    userId,
    method: req.method,
    endpoint: req.path
  });
  
  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - startTime;
    
    securityLogger.info('API_RESPONSE', {
      ip,
      userId,
      method: req.method,
      endpoint: req.path,
      statusCode: res.statusCode,
      duration
    });
    
    originalSend.call(this, data);
  };
  
  next();
});

// ═══════════════════════════════════════════════════════════
// BACKEND INITIALIZATION
// ═══════════════════════════════════════════════════════════

let backend;

async function initBackend() {
  securityLogger.info('SYSTEM', { message: 'Initializing backend service...' });
  try {
    backend = new BackendService();
    await backend.init();
    securityLogger.info('SYSTEM', { message: 'Backend service ready' });
  } catch (error) {
    securityLogger.error('SYSTEM', { message: 'Backend init failed', error: error.message });
    throw error;
  }
}

// ═══════════════════════════════════════════════════════════
// WEBSOCKET SERVER
// ═══════════════════════════════════════════════════════════

const wss = new WebSocketServer({ noServer: true });

const clients = new Map();

wss.on('connection', (ws, req) => {
  const clientId = `client_${Date.now()}`;
  clients.set(clientId, { 
    ws, 
    userId: null, 
    researchId: null,
    iteration: 0,
    currentState: {}
  });
  
  securityLogger.info('WS_CONNECTION', { clientId });
  
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      
      securityLogger.info('WS_MESSAGE', { clientId, type: data.type });
      
      switch (data.type) {
        case 'AUTH':
          const authResult = await backend.verifyToken(data.token);
          if (authResult.valid) {
            clients.get(clientId).userId = authResult.userId;
            ws.send(JSON.stringify({ type: 'AUTH_SUCCESS', userId: authResult.userId }));
          } else {
            ws.send(JSON.stringify({ type: 'AUTH_FAILED' }));
          }
          break;
          
        case 'START_RESEARCH':
          const client = clients.get(clientId);
          if (!client.userId) {
            ws.send(JSON.stringify({ type: 'ERROR', message: 'Not authenticated' }));
            return;
          }
          
          const researchResult = await backend.startResearch(client.userId, data.config);
          client.researchId = researchResult.researchId;
          client.iteration = 0;
          
          ws.send(JSON.stringify({
            type: 'RESEARCH_STARTED',
            researchId: researchResult.researchId
          }));
          break;
          
        case 'GENERATE_CODE':
          // AI generates code for REPL
          const researchClient = clients.get(clientId);
          if (!researchClient.researchId) {
            ws.send(JSON.stringify({ type: 'ERROR', message: 'No active research' }));
            return;
          }
          
          ws.send(JSON.stringify({ type: 'GENERATING_CODE', message: 'AI writing code...' }));
          
          const code = await backend.generateREPLCode(
            researchClient.researchId,
            data.problem,
            data.constraints,
            researchClient.iteration
          );
          
          // Send code to simulator REPL
          ws.send(JSON.stringify({
            type: 'CODE_GENERATED',
            code,
            iteration: researchClient.iteration
          }));
          
          researchClient.iteration++;
          break;
          
        case 'REPL_OUTPUT':
          // Receive output from simulator REPL
          const activeClient = clients.get(clientId);
          if (!activeClient.researchId) return;
          
          activeClient.currentState = data.output;
          
          ws.send(JSON.stringify({ type: 'ANALYZING_OUTPUT', message: 'AI analyzing results...' }));
          
          const analysis = await backend.analyzeREPLOutput(
            activeClient.researchId,
            data.output,
            data.problem
          );
          
          if (analysis.solution_found) {
            ws.send(JSON.stringify({
              type: 'SOLUTION_FOUND',
              analysis: analysis.analysis,
              finalState: activeClient.currentState
            }));
          } else if (analysis.next_action === 'continue' && analysis.next_code) {
            ws.send(JSON.stringify({
              type: 'CODE_GENERATED',
              code: analysis.next_code,
              iteration: activeClient.iteration,
              reasoning: analysis.analysis
            }));
            activeClient.iteration++;
          } else {
            ws.send(JSON.stringify({
              type: 'RESEARCH_COMPLETE',
              analysis: analysis.analysis,
              finalState: activeClient.currentState
            }));
          }
          break;
          
        case 'HUMAN_FEEDBACK':
          // Human researcher sends feedback
          const feedbackClient = clients.get(clientId);
          if (!feedbackClient.researchId) return;
          
          ws.send(JSON.stringify({ type: 'PROCESSING_FEEDBACK', message: 'Converting feedback to code...' }));
          
          const feedbackCode = await backend.processHumanFeedback(
            feedbackClient.researchId,
            data.feedback,
            feedbackClient.currentState
          );
          
          ws.send(JSON.stringify({
            type: 'CODE_GENERATED',
            code: feedbackCode,
            source: 'human_feedback'
          }));
          break;
          
        case 'END_RESEARCH':
          const endClient = clients.get(clientId);
          if (endClient.researchId) {
            await backend.endResearch(endClient.researchId);
            endClient.researchId = null;
            endClient.iteration = 0;
            endClient.currentState = {};
          }
          
          ws.send(JSON.stringify({ type: 'RESEARCH_ENDED' }));
          break;
          
        default:
          ws.send(JSON.stringify({ type: 'ERROR', message: 'Unknown message type' }));
      }
    } catch (error) {
      securityLogger.error('WS_ERROR', { clientId, error: error.message });
      ws.send(JSON.stringify({ type: 'ERROR', message: error.message }));
    }
  });
  
  ws.on('close', () => {
    securityLogger.info('WS_DISCONNECTION', { clientId });
    clients.delete(clientId);
  });
});

// ═══════════════════════════════════════════════════════════
// HTTP ROUTES
// ═══════════════════════════════════════════════════════════

// Serve pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/lab', (req, res) => {
  res.sendFile(path.join(__dirname, 'lab.html'));
});

app.get('/simulator', (req, res) => {
  res.sendFile(path.join(__dirname, 'simulator.html'));
});

app.get('/compute', (req, res) => {
  res.sendFile(path.join(__dirname, 'compute.html'));
});

app.get('/results', (req, res) => {
  res.sendFile(path.join(__dirname, 'results.html'));
});

app.get('/settings', (req, res) => {
  res.sendFile(path.join(__dirname, 'settings.html'));
});

app.get('/collaborative', (req, res) => {
  res.sendFile(path.join(__dirname, 'collaborative.html'));
});

app.get('/projects', (req, res) => {
  res.sendFile(path.join(__dirname, 'projects.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// API Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const result = await backend.register(req.body);
    res.json(result);
  } catch (error) {
    securityLogger.error('API_ERROR', { endpoint: '/api/auth/register', error: error.message });
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const result = await backend.login(req.body);
    res.json(result);
  } catch (error) {
    securityLogger.error('API_ERROR', { endpoint: '/api/auth/login', error: error.message });
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    const result = await backend.logout(req.headers.authorization);
    res.json(result);
  } catch (error) {
    securityLogger.error('API_ERROR', { endpoint: '/api/auth/logout', error: error.message });
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/auth/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const result = await backend.verifyToken(token);
    res.json(result);
  } catch (error) {
    res.status(401).json({ valid: false });
  }
});

app.post('/api/keys/save', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const auth = await backend.verifyToken(token);
    
    if (!auth.valid) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    
    const result = await backend.saveAPIKey(auth.userId, req.body.provider, req.body.apiKey);
    res.json(result);
  } catch (error) {
    securityLogger.error('API_ERROR', { endpoint: '/api/keys/save', error: error.message });
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/keys/list', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const auth = await backend.verifyToken(token);
    
    if (!auth.valid) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    
    const keys = await backend.listAPIKeys(auth.userId);
    res.json({ success: true, keys });
  } catch (error) {
    securityLogger.error('API_ERROR', { endpoint: '/api/keys/list', error: error.message });
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const auth = await backend.verifyToken(token);
    
    if (!auth.valid) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    
    const stats = await backend.getStats(auth.userId);
    res.json(stats);
  } catch (error) {
    securityLogger.error('API_ERROR', { endpoint: '/api/stats', error: error.message });
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json(backend.healthCheck());
});

// Admin endpoints
app.get('/api/admin/logs', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  
  if (adminKey !== process.env.ADMIN_KEY) {
    securityLogger.security('UNAUTHORIZED_ADMIN_ACCESS', {
      ip: req.ip,
      endpoint: '/api/admin/logs'
    });
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }
  
  const logs = securityLogger.getRecentLogs(500);
  res.json({ success: true, logs });
});

app.get('/api/admin/stats', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }
  
  const stats = securityLogger.getStats();
  res.json({ success: true, stats });
});

// Error handlers
app.use((err, req, res, next) => {
  securityLogger.error('UNHANDLED_ERROR', {
    error: err.message,
    stack: err.stack,
    endpoint: req.path
  });
  res.status(500).json({ success: false, message: 'Internal server error' });
});

app.use((req, res) => {
  securityLogger.warn('404_NOT_FOUND', {
    method: req.method,
    path: req.path,
    ip: req.ip
  });
  res.status(404).json({ success: false, message: 'Route not found' });
});

// ═══════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════

async function startServer() {
  await initBackend();
  
  const server = app.listen(PORT, '0.0.0.0', () => {
    securityLogger.info('SYSTEM', {
      message: 'Server started',
      port: PORT,
      environment: process.env.NODE_ENV || 'development'
    });
    
    console.log(`
===============================================================
   NEXUS AI RESEARCH LAB - API Gateway
   Server:     http://0.0.0.0:${PORT}
   WebSocket:  ws://0.0.0.0:${PORT}
   Security:   Active
   Logging:    logs/*
===============================================================
    `);
  });
  
  // WebSocket upgrade
  server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  });
}

// Graceful shutdown
process.on('SIGTERM', () => {
  securityLogger.info('SYSTEM', { message: 'SIGTERM received, shutting down gracefully' });
  process.exit(0);
});

process.on('SIGINT', () => {
  securityLogger.info('SYSTEM', { message: 'SIGINT received, shutting down gracefully' });
  process.exit(0);
});

// Launch
startServer();