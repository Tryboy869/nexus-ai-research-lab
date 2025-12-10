// server.js - NEXUS AI Research Lab Backend
// Multi-provider IA support (Groq, Anthropic, OpenAI)

import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import Groq from 'groq-sdk';
import { createClient } from '@libsql/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// ═══════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const SALT_ROUNDS = 10;

// ═══════════════════════════════════════════════════════════
// DATABASE (Turso)
// ═══════════════════════════════════════════════════════════

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN
});

// Initialiser tables
async function initDatabase() {
  try {
    // Table users
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT,
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        last_login INTEGER,
        email_verified INTEGER DEFAULT 0
      )
    `);
    
    // Table sessions
    await db.execute(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    
    // Table api_keys
    await db.execute(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        encrypted_key TEXT NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    
    // Table usage
    await db.execute(`
      CREATE TABLE IF NOT EXISTS usage (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        timestamp INTEGER DEFAULT (strftime('%s', 'now')),
        provider TEXT,
        tokens_used INTEGER,
        compute_time_seconds INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    
    console.log('✅ Database initialized');
  } catch (error) {
    console.error('❌ Database init error:', error);
  }
}

// ═══════════════════════════════════════════════════════════
// AUTH SERVICE
// ═══════════════════════════════════════════════════════════

class AuthService {
  static async register(email, password, name) {
    const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    
    try {
      await db.execute({
        sql: 'INSERT INTO users (id, email, password_hash, name) VALUES (?, ?, ?, ?)',
        args: [userId, email, passwordHash, name]
      });
      
      return { success: true, userId };
    } catch (error) {
      if (error.message.includes('UNIQUE constraint')) {
        return { success: false, error: 'Email already exists' };
      }
      throw error;
    }
  }
  
  static async login(email, password) {
    const result = await db.execute({
      sql: 'SELECT * FROM users WHERE email = ?',
      args: [email]
    });
    
    if (result.rows.length === 0) {
      return { success: false, error: 'Invalid credentials' };
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return { success: false, error: 'Invalid credentials' };
    }
    
    // Créer JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    // Sauvegarder session
    const sessionId = `session_${Date.now()}`;
    const expiresAt = Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60); // 7 jours
    
    await db.execute({
      sql: 'INSERT INTO sessions (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)',
      args: [sessionId, user.id, token, expiresAt]
    });
    
    // Update last_login
    await db.execute({
      sql: 'UPDATE users SET last_login = ? WHERE id = ?',
      args: [Math.floor(Date.now() / 1000), user.id]
    });
    
    return {
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      }
    };
  }
  
  static async verifyToken(token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      
      // Vérifier si session existe
      const result = await db.execute({
        sql: 'SELECT * FROM sessions WHERE token = ? AND expires_at > ?',
        args: [token, Math.floor(Date.now() / 1000)]
      });
      
      if (result.rows.length === 0) {
        return { valid: false };
      }
      
      return { valid: true, userId: decoded.userId, email: decoded.email };
    } catch (error) {
      return { valid: false };
    }
  }
  
  static async logout(token) {
    await db.execute({
      sql: 'DELETE FROM sessions WHERE token = ?',
      args: [token]
    });
    
    return { success: true };
  }
}

// ═══════════════════════════════════════════════════════════
// API KEYS SERVICE
// ═══════════════════════════════════════════════════════════

class APIKeysService {
  static encrypt(text) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(JWT_SECRET, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return iv.toString('hex') + ':' + encrypted;
  }
  
  static decrypt(encrypted) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(JWT_SECRET, 'salt', 32);
    const parts = encrypted.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedText = parts[1];
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
  
  static async saveKey(userId, provider, apiKey) {
    const keyId = `key_${Date.now()}`;
    const encryptedKey = this.encrypt(apiKey);
    
    // Supprimer ancienne clé du même provider
    await db.execute({
      sql: 'DELETE FROM api_keys WHERE user_id = ? AND provider = ?',
      args: [userId, provider]
    });
    
    // Insérer nouvelle clé
    await db.execute({
      sql: 'INSERT INTO api_keys (id, user_id, provider, encrypted_key) VALUES (?, ?, ?, ?)',
      args: [keyId, userId, provider, encryptedKey]
    });
    
    return { success: true };
  }
  
  static async getKey(userId, provider) {
    const result = await db.execute({
      sql: 'SELECT * FROM api_keys WHERE user_id = ? AND provider = ?',
      args: [userId, provider]
    });
    
    if (result.rows.length === 0) {
      return null;
    }
    
    const encryptedKey = result.rows[0].encrypted_key;
    return this.decrypt(encryptedKey);
  }
  
  static async listKeys(userId) {
    const result = await db.execute({
      sql: 'SELECT provider, created_at FROM api_keys WHERE user_id = ?',
      args: [userId]
    });
    
    return result.rows;
  }
}

// ═══════════════════════════════════════════════════════════
// MULTI-AI ORCHESTRATOR (REPL PILOT)
// ═══════════════════════════════════════════════════════════

class MultiAIOrchestrator {
  constructor() {
    this.clients = {};
    this.conversationHistory = new Map(); // Track AI conversations
  }
  
  async initClient(provider, apiKey) {
    switch (provider) {
      case 'groq':
        this.clients.groq = new Groq({ apiKey });
        break;
      case 'anthropic':
        this.clients.anthropic = new Anthropic({ apiKey });
        break;
      case 'openai':
        this.clients.openai = new OpenAI({ apiKey });
        break;
      default:
        throw new Error(`Unknown provider: ${provider}`);
    }
  }
  
  // AI generates JavaScript code to execute in REPL
  async generateCodeForREPL(provider, model, problem, constraints, iteration = 0) {
    const systemPrompt = this._buildREPLSystemPrompt();
    const userPrompt = this._buildREPLUserPrompt(problem, constraints, iteration);
    
    try {
      let response;
      
      switch (provider) {
        case 'groq':
          response = await this.clients.groq.chat.completions.create({
            model: model || 'llama-3.3-70b-versatile',
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: userPrompt }
            ],
            temperature: 0.7,
            max_tokens: 3000
          });
          return this._extractCode(response.choices[0].message.content);
          
        case 'anthropic':
          response = await this.clients.anthropic.messages.create({
            model: model || 'claude-sonnet-4-20250514',
            max_tokens: 3000,
            system: systemPrompt,
            messages: [{ role: 'user', content: userPrompt }],
            temperature: 0.7
          });
          return this._extractCode(response.content[0].text);
          
        case 'openai':
          response = await this.clients.openai.chat.completions.create({
            model: model || 'gpt-4o',
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: userPrompt }
            ],
            temperature: 0.7,
            max_tokens: 3000
          });
          return this._extractCode(response.choices[0].message.content);
          
        default:
          throw new Error(`Unknown provider: ${provider}`);
      }
    } catch (error) {
      console.error(`Error with ${provider}:`, error);
      throw error;
    }
  }
  
  _buildREPLSystemPrompt() {
    return `You are an AI engineer with access to a Universal Virtual Laboratory REPL.

AVAILABLE FUNCTIONS:
- createMicroLens(props) - Create virtual lens with optical properties
- createSensor(props) - Create electronic sensor
- createCircuit(props) - Create electronic circuit
- createMaterial(props) - Create material with physical properties
- assembleParts(...parts) - Combine multiple objects
- testOpticalPerformance(obj) - Test optical properties
- testCompatibility(...objs) - Test if objects work together
- simulateAging(obj, years) - Simulate aging over time
- modifyObject(id, newProps) - Modify existing object
- getObject(id) - Retrieve object by ID
- listObjects() - List all created objects

YOUR TASK:
1. Write JavaScript code to create virtual objects
2. Test combinations and properties
3. Iterate based on results
4. Find optimal solution

RULES:
- Write ONLY executable JavaScript code
- Use console.log() to show results
- Store important objects in variables
- Test each hypothesis thoroughly
- Code will be executed in sandboxed REPL

EXAMPLE:
\`\`\`javascript
// Create lens
const lens1 = createMicroLens({
  material: 'glass',
  focal_length: 5,
  diameter: 2
});

// Test performance
const result = testOpticalPerformance(lens1);
console.log('Performance:', result);

// If not optimal, modify
if (result.score < 0.8) {
  const lens2 = modifyObject(lens1.id, { focal_length: 4 });
  const newResult = testOpticalPerformance(lens2);
  console.log('Improved:', newResult);
}
\`\`\``;
  }
  
  _buildREPLUserPrompt(problem, constraints, iteration) {
    let prompt = `RESEARCH PROBLEM:
${problem}

CONSTRAINTS:
${JSON.stringify(constraints, null, 2)}

`;

    if (iteration === 0) {
      prompt += `This is your FIRST attempt. Generate JavaScript code to:
1. Create 3-5 different virtual objects/designs
2. Test each one
3. Log results

Write ONLY the JavaScript code (no explanations).`;
    } else {
      prompt += `This is iteration #${iteration}. Based on previous results, generate code to:
1. Refine best approach
2. Test edge cases
3. Optimize performance

Write ONLY the JavaScript code.`;
    }
    
    return prompt;
  }
  
  _extractCode(content) {
    // Extract code from markdown blocks
    if (content.includes('```javascript')) {
      content = content.split('```javascript')[1].split('```')[0].trim();
    } else if (content.includes('```js')) {
      content = content.split('```js')[1].split('```')[0].trim();
    } else if (content.includes('```')) {
      content = content.split('```')[1].split('```')[0].trim();
    }
    
    return content;
  }
  
  // AI analyzes REPL output and decides next action
  async analyzeREPLOutput(provider, model, output, problem) {
    const prompt = `You are analyzing results from virtual laboratory experiments.

PROBLEM: ${problem}

REPL OUTPUT:
${JSON.stringify(output, null, 2)}

TASK:
Analyze the output and decide:
1. Is solution found? (yes/no)
2. What should be tested next?
3. Generate JavaScript code for next iteration OR conclude

Respond in JSON:
{
  "solution_found": true/false,
  "analysis": "Your analysis",
  "next_action": "continue" or "conclude",
  "next_code": "JavaScript code" or null
}`;
    
    try {
      let response;
      
      switch (provider) {
        case 'groq':
          response = await this.clients.groq.chat.completions.create({
            model: model || 'llama-3.3-70b-versatile',
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.7,
            max_tokens: 2000
          });
          return this._parseJSON(response.choices[0].message.content);
          
        case 'anthropic':
          response = await this.clients.anthropic.messages.create({
            model: model || 'claude-sonnet-4-20250514',
            max_tokens: 2000,
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.7
          });
          return this._parseJSON(response.content[0].text);
          
        case 'openai':
          response = await this.clients.openai.chat.completions.create({
            model: model || 'gpt-4o',
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.7,
            max_tokens: 2000
          });
          return this._parseJSON(response.choices[0].message.content);
          
        default:
          throw new Error(`Unknown provider: ${provider}`);
      }
    } catch (error) {
      console.error(`Error with ${provider}:`, error);
      throw error;
    }
  }
  
  // Process human feedback (natural language or code)
  async processHumanFeedback(provider, model, feedback, currentState) {
    const prompt = `A human researcher has provided feedback on ongoing virtual lab experiments.

CURRENT STATE:
${JSON.stringify(currentState, null, 2)}

HUMAN FEEDBACK:
"${feedback}"

TASK:
Convert this feedback into executable JavaScript code for the REPL.
If feedback is already code, validate and return it.
If it's natural language, generate appropriate code.

Respond with ONLY the JavaScript code (no explanations).`;
    
    try {
      let response;
      
      switch (provider) {
        case 'groq':
          response = await this.clients.groq.chat.completions.create({
            model: model || 'llama-3.3-70b-versatile',
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.5,
            max_tokens: 1500
          });
          return this._extractCode(response.choices[0].message.content);
          
        case 'anthropic':
          response = await this.clients.anthropic.messages.create({
            model: model || 'claude-sonnet-4-20250514',
            max_tokens: 1500,
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.5
          });
          return this._extractCode(response.content[0].text);
          
        case 'openai':
          response = await this.clients.openai.chat.completions.create({
            model: model || 'gpt-4o',
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.5,
            max_tokens: 1500
          });
          return this._extractCode(response.choices[0].message.content);
          
        default:
          throw new Error(`Unknown provider: ${provider}`);
      }
    } catch (error) {
      console.error(`Error with ${provider}:`, error);
      throw error;
    }
  }
  
  _parseJSON(content) {
    if (content.includes('```json')) {
      content = content.split('```json')[1].split('```')[0].trim();
    } else if (content.includes('```')) {
      content = content.split('```')[1].split('```')[0].trim();
    }
    
    try {
      return JSON.parse(content);
    } catch (error) {
      console.error('Failed to parse JSON:', content);
      return {
        solution_found: false,
        analysis: content,
        next_action: 'continue',
        next_code: null
      };
    }
  }
}

// ═══════════════════════════════════════════════════════════
// USAGE TRACKING
// ═══════════════════════════════════════════════════════════

class UsageService {
  static async track(userId, provider, tokensUsed, computeTime) {
    const usageId = `usage_${Date.now()}`;
    
    await db.execute({
      sql: 'INSERT INTO usage (id, user_id, provider, tokens_used, compute_time_seconds) VALUES (?, ?, ?, ?, ?)',
      args: [usageId, userId, provider, tokensUsed, computeTime]
    });
  }
  
  static async getStats(userId) {
    const result = await db.execute({
      sql: `
        SELECT 
          provider,
          COUNT(*) as count,
          SUM(tokens_used) as total_tokens,
          SUM(compute_time_seconds) as total_time
        FROM usage
        WHERE user_id = ?
        GROUP BY provider
      `,
      args: [userId]
    });
    
    return result.rows;
  }
}

// ═══════════════════════════════════════════════════════════
// BACKEND SERVICE
// ═══════════════════════════════════════════════════════════

export class BackendService {
  constructor() {
    this.orchestrator = new MultiAIOrchestrator();
    this.activeResearches = new Map();
  }
  
  async init() {
    await initDatabase();
    console.log('✅ Backend Service initialized');
  }
  
  // Auth endpoints
  async register(data) {
    return await AuthService.register(data.email, data.password, data.name);
  }
  
  async login(data) {
    return await AuthService.login(data.email, data.password);
  }
  
  async logout(token) {
    return await AuthService.logout(token);
  }
  
  async verifyToken(token) {
    return await AuthService.verifyToken(token);
  }
  
  // API Keys endpoints
  async saveAPIKey(userId, provider, apiKey) {
    return await APIKeysService.saveKey(userId, provider, apiKey);
  }
  
  async getAPIKey(userId, provider) {
    return await APIKeysService.getKey(userId, provider);
  }
  
  async listAPIKeys(userId) {
    return await APIKeysService.listKeys(userId);
  }
  
  // Research endpoints (REPL-based)
  async startResearch(userId, config) {
    const researchId = `research_${Date.now()}`;
    
    // Récupérer API key
    const apiKey = await APIKeysService.getKey(userId, config.provider);
    if (!apiKey) {
      throw new Error(`No API key found for ${config.provider}`);
    }
    
    // Initialiser client IA
    await this.orchestrator.initClient(config.provider, apiKey);
    
    // Stocker recherche active
    this.activeResearches.set(researchId, {
      userId,
      config,
      status: 'running',
      startTime: Date.now(),
      iteration: 0,
      history: []
    });
    
    return {
      success: true,
      researchId,
      message: 'Research started'
    };
  }
  
  async generateREPLCode(researchId, problem, constraints, iteration) {
    const research = this.activeResearches.get(researchId);
    if (!research) {
      throw new Error('Research not found');
    }
    
    const { provider, model } = research.config;
    
    const startTime = Date.now();
    const code = await this.orchestrator.generateCodeForREPL(
      provider, 
      model, 
      problem, 
      constraints, 
      iteration
    );
    const computeTime = Math.floor((Date.now() - startTime) / 1000);
    
    // Track usage
    await UsageService.track(research.userId, provider, 3000, computeTime);
    
    // Store in history
    research.history.push({
      type: 'code_generation',
      iteration,
      code,
      timestamp: Date.now()
    });
    
    return code;
  }
  
  async analyzeREPLOutput(researchId, output, problem) {
    const research = this.activeResearches.get(researchId);
    if (!research) {
      throw new Error('Research not found');
    }
    
    const { provider, model } = research.config;
    
    const analysis = await this.orchestrator.analyzeREPLOutput(
      provider, 
      model, 
      output, 
      problem
    );
    
    // Store in history
    research.history.push({
      type: 'analysis',
      output,
      analysis,
      timestamp: Date.now()
    });
    
    return analysis;
  }
  
  async processHumanFeedback(researchId, feedback, currentState) {
    const research = this.activeResearches.get(researchId);
    if (!research) {
      throw new Error('Research not found');
    }
    
    const { provider, model } = research.config;
    
    const code = await this.orchestrator.processHumanFeedback(
      provider,
      model,
      feedback,
      currentState
    );
    
    // Store in history
    research.history.push({
      type: 'human_feedback',
      feedback,
      generated_code: code,
      timestamp: Date.now()
    });
    
    return code;
  }
  
  async endResearch(researchId) {
    this.activeResearches.delete(researchId);
    return { success: true };
  }
  
  // Stats
  async getStats(userId) {
    const usage = await UsageService.getStats(userId);
    return { success: true, stats: usage };
  }
  
  // Health check
  healthCheck() {
    return {
      success: true,
      status: 'healthy',
      timestamp: new Date().toISOString(),
      activeResearches: this.activeResearches.size
    };
  }
}

export default BackendService;