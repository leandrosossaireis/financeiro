/**
 * ============================================================================
 * CONTROLE FINANCEIRO PESSOAL (100% Client-Side)
 * Arquitetura Modular em ES6+ para Hospedagem Estática no GitHub Pages
 * ============================================================================
 */

// Schema & Configurações
const SCHEMA_VERSION = 1;
const STORAGE_KEY = 'fincontrol_storage_v1';
const THEME_KEY = 'fincontrol_theme_preference';

// Segurança / Criptografia
const VAULT_KEY = 'fincontrol_vault_v1';          // Dados criptografados (AES-GCM)
const LOCK_REASON_KEY = 'fincontrol_lock_reason'; // Mensagem exibida após bloqueio
const PBKDF2_ITERATIONS = 310000;                 // Recomendação OWASP para PBKDF2-SHA256
const MIN_PASSWORD_LENGTH = 8;
const AUTO_LOCK_MINUTES = 15;                     // Bloqueio automático por inatividade

// Sincronização (GitHub Gist privado)
const GIST_FILENAME = 'fincontrol-vault.json';
const GIST_DESCRIPTION = 'FinControl - dados financeiros criptografados (nao editar)';
const SYNC_DEBOUNCE_MS = 300;                     // Resposta rápida após alterações
const SYNC_INTERVAL_MS = 60 * 1000;                // Verificação periódica automática a cada 1 minuto
const TOMBSTONE_TTL_DAYS = 180;                   // Por quanto tempo lembrar exclusões para sincronizar

const CATEGORIES = [
  { id: 'moradia', name: 'Moradia', icon: 'home', color: '#3b82f6' },
  { id: 'alimentacao', name: 'Alimentação', icon: 'utensils', color: '#f59e0b' },
  { id: 'transporte', name: 'Transporte', icon: 'car', color: '#8b5cf6' },
  { id: 'lazer', name: 'Lazer', icon: 'film', color: '#ec4899' },
  { id: 'saude', name: 'Saúde', icon: 'heart-pulse', color: '#ef4444' },
  { id: 'educacao', name: 'Educação', icon: 'graduation-cap', color: '#06b6d4' },
  { id: 'salario', name: 'Salário', icon: 'wallet', color: '#10b981' },
  { id: 'freelance', name: 'Freelance', icon: 'briefcase', color: '#14b8a6' },
  { id: 'investimentos', name: 'Investimentos', icon: 'trending-up', color: '#6366f1' },
  { id: 'outros', name: 'Outros', icon: 'tag', color: '#64748b' }
];

/**
 * Utilitários Auxiliares
 */
const Utils = {
  // Prevenção contra injeção de scripts (XSS)
  escapeHtml(str) {
    if (typeof str !== 'string') return str;
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  },

  // Formatação monetária BRL
  formatCurrency(value) {
    const num = Number(value) || 0;
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL'
    }).format(num);
  },

  // Formatação de data "YYYY-MM-DD" para "DD/MM/AAAA" segura contra fuso horário
  formatDateBR(dateStr) {
    if (!dateStr) return '';
    const parts = dateStr.split('-');
    if (parts.length === 3) {
      return `${parts[2]}/${parts[1]}/${parts[0]}`;
    }
    return dateStr;
  },

  // Gerador de identificador único
  generateId() {
    return 'tx_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 8);
  },

  // Obter mês atual no formato "YYYY-MM"
  getCurrentMonth() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    return `${year}-${month}`;
  },

  // Formatar "YYYY-MM" para nome legível (ex: "Novembro de 2026")
  formatMonthYear(yearMonthStr) {
    if (!yearMonthStr) return '';
    const [year, month] = yearMonthStr.split('-');
    const date = new Date(parseInt(year, 10), parseInt(month, 10) - 1, 1);
    const monthName = date.toLocaleDateString('pt-BR', { month: 'long' });
    return monthName.charAt(0).toUpperCase() + monthName.slice(1) + ' de ' + year;
  },

  // Subtrair ou adicionar meses a uma string "YYYY-MM" ou "YYYY-MM-DD"
  addMonths(dateOrMonthStr, count) {
    const parts = dateOrMonthStr.split('-');
    const y = parseInt(parts[0], 10);
    const m = parseInt(parts[1], 10);
    const day = parts[2] ? parseInt(parts[2], 10) : 1;

    const d = new Date(y, m - 1 + count, day);
    const ny = d.getFullYear();
    const nm = String(d.getMonth() + 1).padStart(2, '0');
    if (parts.length === 3) {
      const nd = String(d.getDate()).padStart(2, '0');
      return `${ny}-${nm}-${nd}`;
    }
    return `${ny}-${nm}`;
  }
};

/**
 * Camada de Persistência (Storage Service)
 */
const StorageService = {
  _queue: Promise.resolve(),

  normalize(parsed) {
    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.transactions)) {
      console.warn('Estrutura de dados inválida. Inicializando padrão.');
      return this.getDefaultData();
    }
    return {
      version: parsed.version || SCHEMA_VERSION,
      updatedAt: parsed.updatedAt || new Date().toISOString(),
      transactions: parsed.transactions,
      deleted: (parsed.deleted && typeof parsed.deleted === 'object') ? parsed.deleted : {},
      settings: (parsed.settings && typeof parsed.settings === 'object') ? parsed.settings : {}
    };
  },

  readLegacyPlain() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed?.transactions) ? this.normalize(parsed) : null;
    } catch (err) {
      console.error('Falha ao ler dados legados:', err);
      return null;
    }
  },

  removeLegacyPlain() {
    try { localStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignora */ }
  },

  saveData(data) {
    const payload = {
      version: SCHEMA_VERSION,
      updatedAt: new Date().toISOString(),
      transactions: Array.isArray(data.transactions) ? data.transactions : [],
      deleted: data.deleted || {},
      settings: data.settings || {}
    };
    this._queue = this._queue
      .then(() => CryptoVault.encryptAndStore(payload))
      .catch(err => {
        console.error('Erro ao salvar dados criptografados:', err);
        Toast.show('Erro ao salvar dados. Faça backup em JSON.', 'error');
      });
    return this._queue;
  },

  flush() {
    return this._queue;
  },

  getDefaultData() {
    return {
      version: SCHEMA_VERSION,
      updatedAt: new Date().toISOString(),
      transactions: [],
      deleted: {},
      settings: {
        budgets: {}
      }
    };
  },

  wipeAll() {
    try {
      localStorage.removeItem(VAULT_KEY);
      localStorage.removeItem(STORAGE_KEY);
      return true;
    } catch (e) {
      return false;
    }
  }
};

/**
 * Cofre Criptográfico (Web Crypto API)
 */
const CryptoVault = {
  key: null,
  salt: null,
  iterations: PBKDF2_ITERATIONS,

  isSupported() {
    return !!(window.crypto && window.crypto.subtle && window.crypto.getRandomValues);
  },

  hasVault() {
    try {
      return !!localStorage.getItem(VAULT_KEY);
    } catch (e) {
      return false;
    }
  },

  toB64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  },

  fromB64(str) {
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  },

  async deriveKey(password, salt, iterations) {
    const material = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  readVault() {
    const raw = localStorage.getItem(VAULT_KEY);
    if (!raw) throw new Error('Cofre não encontrado.');
    const vault = JSON.parse(raw);
    if (!vault || !vault.salt || !vault.iv || !vault.data) {
      throw new Error('Cofre corrompido.');
    }
    return vault;
  },

  async decryptVault(vault, key) {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: this.fromB64(vault.iv) },
      key,
      this.fromB64(vault.data)
    );
    return JSON.parse(new TextDecoder().decode(plain));
  },

  async create(password, data) {
    this.salt = crypto.getRandomValues(new Uint8Array(16));
    this.iterations = PBKDF2_ITERATIONS;
    this.key = await this.deriveKey(password, this.salt, this.iterations);
    await this.encryptAndStore(data);
  },

  async unlock(password) {
    const vault = this.readVault();
    const salt = this.fromB64(vault.salt);
    const iterations = vault.iterations || PBKDF2_ITERATIONS;
    const key = await this.deriveKey(password, salt, iterations);

    let data;
    try {
      data = await this.decryptVault(vault, key);
    } catch (e) {
      const err = new Error('Senha incorreta.');
      err.code = 'BAD_PASSWORD';
      throw err;
    }

    this.key = key;
    this.salt = salt;
    this.iterations = iterations;
    return StorageService.normalize(data);
  },

  async adopt(password, vault) {
    const salt = this.fromB64(vault.salt);
    const iterations = vault.iterations || PBKDF2_ITERATIONS;
    const key = await this.deriveKey(password, salt, iterations);
    const data = await this.decryptVault(vault, key);
    this.key = key;
    this.salt = salt;
    this.iterations = iterations;
    return data;
  },

  async verifyPassword(password) {
    try {
      const vault = this.readVault();
      const key = await this.deriveKey(password, this.fromB64(vault.salt), vault.iterations || PBKDF2_ITERATIONS);
      await this.decryptVault(vault, key);
      return true;
    } catch (e) {
      return false;
    }
  },

  async encryptAndStore(data) {
    if (!this.key || !this.salt) throw new Error('Cofre bloqueado.');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, encoded);

    localStorage.setItem(VAULT_KEY, JSON.stringify({
      version: SCHEMA_VERSION,
      kdf: 'PBKDF2-SHA256',
      iterations: this.iterations,
      cipher: 'AES-256-GCM',
      salt: this.toB64(this.salt),
      iv: this.toB64(iv),
      data: this.toB64(cipher),
      updatedAt: new Date().toISOString()
    }));
  },

  async changePassword(newPassword, data) {
    await this.create(newPassword, data);
  },

  lock() {
    this.key = null;
    this.salt = null;
  }
};

/**
 * Cliente da API de Gists do GitHub
 */
const GistAPI = {
  async request(token, path, options = {}) {
    let res;
    try {
      res = await fetch('https://api.github.com' + path, {
        ...options,
        cache: 'no-store',
        headers: {
          'Accept': 'application/vnd.github+json',
          'Authorization': `Bearer ${token}`,
          'X-GitHub-Api-Version': '2022-11-28',
          ...(options.body ? { 'Content-Type': 'application/json' } : {})
        }
      });
    } catch (e) {
      const err = new Error('Sem conexão com a internet.');
      err.status = 0;
      throw err;
    }

    if (!res.ok) {
      const messages = {
        401: 'Token do GitHub inválido ou expirado.',
        403: 'Token sem permissão de "gist" ou limite de requisições atingido.',
        404: 'Gist de sincronização não encontrado.',
        422: 'Requisição rejeitada pelo GitHub.'
      };
      const err = new Error(messages[res.status] || `Erro do GitHub (HTTP ${res.status}).`);
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  },

  validateToken(token) {
    return this.request(token, '/user');
  },

  async findVaultGist(token) {
    for (let page = 1; page <= 10; page++) {
      const list = await this.request(token, `/gists?per_page=100&page=${page}`);
      const found = list.find(g => g.files && g.files[GIST_FILENAME]);
      if (found) return found.id;
      if (list.length < 100) break;
    }
    return null;
  },

  async readVault(token, gistId) {
    const gist = await this.request(token, `/gists/${gistId}`);
    const file = gist.files && gist.files[GIST_FILENAME];
    if (!file) return null;
    if (file.truncated && file.raw_url) {
      const res = await fetch(file.raw_url, { cache: 'no-store' });
      return res.text();
    }
    return file.content;
  },

  async createGist(token, content) {
    const gist = await this.request(token, '/gists', {
      method: 'POST',
      body: JSON.stringify({
        description: GIST_DESCRIPTION,
        public: false,
        files: { [GIST_FILENAME]: { content } }
      })
    });
    return gist.id;
  },

  updateGist(token, gistId, content) {
    return this.request(token, `/gists/${gistId}`, {
      method: 'PATCH',
      body: JSON.stringify({ files: { [GIST_FILENAME]: { content } } })
    });
  }
};

/**
 * Serviço de Sincronização entre Aparelhos
 */
const SyncService = {
  status: 'off',
  statusDetail: '',
  lastSync: null,
  debounceTimer: null,
  intervalTimer: null,
  chain: Promise.resolve(),
  listenersBound: false,

  get config() {
    return (App.state.settings && App.state.settings.sync) || null;
  },

  isEnabled() {
    const c = this.config;
    return !!(c && c.token && c.gistId);
  },

  init() {
    if (!this.listenersBound) {
      this.listenersBound = true;
      window.addEventListener('online', () => this.syncNow({ silent: true }));
      window.addEventListener('offline', () => this.isEnabled() && this.setStatus('offline'));
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
          this.syncNow({ silent: true });
        } else if (document.visibilityState === 'hidden') {
          this.flushPending();
        }
      });
      window.addEventListener('pagehide', () => this.flushPending());
      window.addEventListener('beforeunload', () => this.flushPending());
    }
    if (this.isEnabled()) {
      this.startInterval();
      this.syncNow({ silent: true });
    } else {
      this.setStatus('off');
    }
  },

  startInterval() {
    clearInterval(this.intervalTimer);
    this.intervalTimer = setInterval(() => {
      if (document.visibilityState === 'visible') this.syncNow({ silent: true });
    }, SYNC_INTERVAL_MS);
  },

  schedule(immediate = false) {
    if (!this.isEnabled()) return;
    clearTimeout(this.debounceTimer);
    if (immediate) {
      this.debounceTimer = null;
      this.syncNow({ silent: true });
      return;
    }
    this.setStatus('pending');
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      this.syncNow({ silent: true });
    }, SYNC_DEBOUNCE_MS);
  },

  syncNow(opts = {}) {
    clearTimeout(this.debounceTimer);
    this.debounceTimer = null;
    this.chain = this.chain.then(() => this._sync(opts)).catch(() => {});
    return this.chain;
  },

  async flushPending(timeoutMs = 5000) {
    if (!this.isEnabled()) return;
    const pending = this.debounceTimer ? this.syncNow({ silent: true }) : this.chain;
    await Promise.race([pending, new Promise(r => setTimeout(r, timeoutMs))]);
  },

  pushOnly() {
    clearTimeout(this.debounceTimer);
    this.debounceTimer = null;
    this.chain = this.chain.then(async () => {
      if (!this.isEnabled()) return;
      this.setStatus('syncing');
      try {
        await StorageService.flush();
        const { token, gistId } = this.config;
        await GistAPI.updateGist(token, gistId, localStorage.getItem(VAULT_KEY));
        this.lastSync = new Date();
        this.setStatus('ok');
      } catch (err) {
        this.setStatus('error', err.message);
        Toast.show('Falha ao enviar para a nuvem: ' + err.message, 'error');
      }
    }).catch(() => {});
    return this.chain;
  },

  async _sync({ silent = false } = {}) {
    if (!this.isEnabled()) return;
    if (!navigator.onLine) {
      this.setStatus('offline');
      return;
    }

    this.setStatus('syncing');
    const { token, gistId } = this.config;

    try {
      await StorageService.flush();
      const remoteRaw = await GistAPI.readVault(token, gistId);

      if (remoteRaw) {
        const remoteVault = JSON.parse(remoteRaw);
        let remoteData;
        try {
          remoteData = await CryptoVault.decryptVault(remoteVault, CryptoVault.key);
        } catch (e) {
          localStorage.setItem(VAULT_KEY, remoteRaw);
          await AuthUI.lock('A senha foi alterada em outro aparelho. Entre com a nova senha.', { skipSync: true });
          return;
        }

        const local = App.getPersistPayload();
        const remote = StorageService.normalize(remoteData);
        const merged = this.merge(local, remote);
        const mergedSig = this.signature(merged);

        if (mergedSig !== this.signature(local)) {
          App.applySyncedData(merged);
          await StorageService.saveData(App.getPersistPayload());
        }
        if (mergedSig !== this.signature(remote)) {
          await StorageService.flush();
          await GistAPI.updateGist(token, gistId, localStorage.getItem(VAULT_KEY));
        }
      } else {
        await GistAPI.updateGist(token, gistId, localStorage.getItem(VAULT_KEY));
      }

      this.lastSync = new Date();
      this.setStatus('ok');
      if (!silent) Toast.show('Sincronizado com sucesso!', 'success', 2000);
    } catch (err) {
      console.error('Falha na sincronização:', err);
      this.setStatus(err.status === 0 ? 'offline' : 'error', err.message);
      if (!silent) Toast.show('Falha na sincronização: ' + err.message, 'error');
    }
  },

  merge(local, remote) {
    const now = Date.now();
    const ttl = TOMBSTONE_TTL_DAYS * 24 * 60 * 60 * 1000;

    const deleted = {};
    [remote.deleted || {}, local.deleted || {}].forEach(src => {
      Object.entries(src).forEach(([id, ts]) => {
        if (now - ts > ttl) return;
        deleted[id] = Math.max(deleted[id] || 0, ts);
      });
    });

    const byId = new Map();
    [...(remote.transactions || []), ...(local.transactions || [])].forEach(tx => {
      const current = byId.get(tx.id);
      if (!current || (tx.updatedAt || 0) > (current.updatedAt || 0)) byId.set(tx.id, tx);
    });

    const transactions = [...byId.values()].filter(tx => !(deleted[tx.id] && deleted[tx.id] >= (tx.updatedAt || 0)));

    // Mesclar orçamentos
    const localBudgets = (local.settings && local.settings.budgets) || {};
    const remoteBudgets = (remote.settings && remote.settings.budgets) || {};
    const mergedBudgets = { ...remoteBudgets, ...localBudgets };

    return {
      transactions,
      deleted,
      settings: {
        ...(local.settings || {}),
        budgets: mergedBudgets
      }
    };
  },

  signature(data) {
    const txs = (data.transactions || []).map(t => `${t.id}:${t.updatedAt || 0}`).sort().join('|');
    const del = Object.keys(data.deleted || {}).sort().join('|');
    const budgets = JSON.stringify((data.settings && data.settings.budgets) || {});
    return txs + '#' + del + '#' + budgets;
  },

  async connect(token, password, overwrite) {
    if (!(await CryptoVault.verifyPassword(password))) {
      throw new Error('Senha atual incorreta.');
    }
    await GistAPI.validateToken(token);
    let gistId = await GistAPI.findVaultGist(token);
    await StorageService.flush();

    if (gistId) {
      const remoteRaw = await GistAPI.readVault(token, gistId);
      if (remoteRaw) {
        let remoteData = null;
        try {
          remoteData = await CryptoVault.adopt(password, JSON.parse(remoteRaw));
        } catch (e) {
          if (!overwrite) {
            throw new Error('Os dados da nuvem usam outra senha. Use neste aparelho a mesma senha ou marque a opção de substituir.');
          }
        }
        if (remoteData) {
          App.applySyncedData(this.merge(App.getPersistPayload(), StorageService.normalize(remoteData)));
        }
      }
    }

    App.state.settings.sync = { token, gistId: gistId || null };
    await StorageService.saveData(App.getPersistPayload());

    if (!gistId) {
      gistId = await GistAPI.createGist(token, localStorage.getItem(VAULT_KEY));
      App.state.settings.sync.gistId = gistId;
      await StorageService.saveData(App.getPersistPayload());
    }
    await StorageService.flush();
    await GistAPI.updateGist(token, gistId, localStorage.getItem(VAULT_KEY));

    App.render();
    this.lastSync = new Date();
    this.setStatus('ok');
    this.startInterval();
  },

  async disconnect() {
    clearTimeout(this.debounceTimer);
    clearInterval(this.intervalTimer);
    delete App.state.settings.sync;
    await StorageService.saveData(App.getPersistPayload());
    this.setStatus('off');
  },

  setStatus(status, detail = '') {
    this.status = status;
    this.statusDetail = detail;

    const labels = {
      off: 'Sincronização desativada (toque para configurar)',
      pending: 'Gravando alterações...',
      syncing: 'Sincronizando com a nuvem...',
      ok: 'Sincronizado na nuvem',
      error: 'Erro na sincronização',
      offline: 'Sem conexão (sincroniza ao reconectar)'
    };
    const dotColors = {
      off: 'bg-slate-400',
      pending: 'bg-amber-400',
      syncing: 'bg-blue-500 status-pulse',
      ok: 'bg-emerald-500',
      error: 'bg-rose-500',
      offline: 'bg-slate-500'
    };

    let text = labels[status] || '';
    if (status === 'ok' && this.lastSync) {
      text += ' às ' + this.lastSync.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
    if (detail && (status === 'error' || status === 'offline')) text += ': ' + detail;

    const dot = document.getElementById('sync-dot');
    if (dot) dot.className = `absolute top-1.5 right-1.5 w-2 h-2 rounded-full ${dotColors[status] || 'bg-slate-400'}`;
    const btn = document.getElementById('btn-sync');
    if (btn) btn.title = text;
    const icon = document.getElementById('sync-icon');
    if (icon) {
      if (status === 'syncing') {
        icon.classList.add('animate-pulse', 'text-blue-500');
      } else {
        icon.classList.remove('animate-pulse', 'text-blue-500');
      }
    }
    const statusText = document.getElementById('sync-status-text');
    if (statusText) statusText.textContent = text;
  }
};

/**
 * Gerenciador de Tema (Dark / Light)
 */
const ThemeManager = {
  init() {
    const savedTheme = localStorage.getItem(THEME_KEY);
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const isDark = savedTheme === 'dark' || (!savedTheme && prefersDark);
    this.applyTheme(isDark, false);

    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      if (!localStorage.getItem(THEME_KEY)) {
        this.applyTheme(e.matches, true);
      }
    });
  },

  applyTheme(isDark, animate = true) {
    const html = document.documentElement;
    if (animate) {
      html.classList.add('transition-theme');
      setTimeout(() => html.classList.remove('transition-theme'), 350);
    }
    if (isDark) {
      html.classList.add('dark');
      localStorage.setItem(THEME_KEY, 'dark');
    } else {
      html.classList.remove('dark');
      localStorage.setItem(THEME_KEY, 'light');
    }
    this.updateToggleIcon(isDark);
  },

  toggle() {
    const isCurrentlyDark = document.documentElement.classList.contains('dark');
    this.applyTheme(!isCurrentlyDark, true);
  },

  isDark() {
    return document.documentElement.classList.contains('dark');
  },

  updateToggleIcon(isDark) {
    const sunIcon = document.getElementById('theme-icon-sun');
    const moonIcon = document.getElementById('theme-icon-moon');
    if (!sunIcon || !moonIcon) return;

    if (isDark) {
      sunIcon.classList.remove('hidden');
      moonIcon.classList.add('hidden');
    } else {
      sunIcon.classList.add('hidden');
      moonIcon.classList.remove('hidden');
    }
  }
};

/**
 * Gerenciamento de Gráficos (Chart.js)
 */
const ChartService = {
  categoryChartInstance: null,
  historyChartInstance: null,

  getColors(isDark) {
    return {
      text: isDark ? '#94a3b8' : '#64748b',
      border: isDark ? '#334155' : '#e2e8f0',
      grid: isDark ? 'rgba(51, 65, 85, 0.4)' : 'rgba(226, 232, 240, 0.7)',
      tooltipBg: isDark ? '#0f172a' : '#1e293b',
      tooltipText: '#ffffff'
    };
  },

  renderCategoryChart(transactions) {
    const canvas = document.getElementById('chartCategory');
    const emptyState = document.getElementById('chartCategoryEmpty');
    if (!canvas) return;

    const expenses = transactions.filter(t => t.type === 'expense');

    if (expenses.length === 0) {
      if (this.categoryChartInstance) {
        this.categoryChartInstance.destroy();
        this.categoryChartInstance = null;
      }
      canvas.classList.add('hidden');
      if (emptyState) emptyState.classList.remove('hidden');
      return;
    }

    canvas.classList.remove('hidden');
    if (emptyState) emptyState.classList.add('hidden');

    const categoryTotals = {};
    expenses.forEach(t => {
      const cat = t.category || 'Outros';
      categoryTotals[cat] = (categoryTotals[cat] || 0) + Number(t.amount);
    });

    const labels = Object.keys(categoryTotals);
    const data = Object.values(categoryTotals);

    const backgroundColors = labels.map(label => {
      const match = CATEGORIES.find(c => c.name.toLowerCase() === label.toLowerCase());
      return match ? match.color : '#94a3b8';
    });

    const isDark = ThemeManager.isDark();
    const colors = this.getColors(isDark);

    if (this.categoryChartInstance) {
      this.categoryChartInstance.destroy();
    }

    const ctx = canvas.getContext('2d');
    this.categoryChartInstance = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: backgroundColors,
          borderWidth: 2,
          borderColor: isDark ? '#1e293b' : '#ffffff',
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: colors.text,
              font: { family: 'Inter', size: 11 },
              padding: 10,
              usePointStyle: true,
              pointStyle: 'circle'
            }
          },
          tooltip: {
            backgroundColor: colors.tooltipBg,
            titleColor: colors.tooltipText,
            bodyColor: colors.tooltipText,
            padding: 8,
            cornerRadius: 8,
            callbacks: {
              label: function(context) {
                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                const val = context.raw || 0;
                const percentage = total > 0 ? ((val / total) * 100).toFixed(1) : '0';
                return ` ${context.label}: ${Utils.formatCurrency(val)} (${percentage}%)`;
              }
            }
          }
        },
        cutout: '66%'
      }
    });
  },

  renderHistoryChart(allTransactions, currentMonthStr) {
    const canvas = document.getElementById('chartHistory');
    if (!canvas) return;

    const months = [];
    for (let i = 5; i >= 0; i--) {
      months.push(Utils.addMonths(currentMonthStr, -i));
    }

    const labels = months.map(m => {
      const [y, mm] = m.split('-');
      const d = new Date(parseInt(y, 10), parseInt(mm, 10) - 1, 1);
      return d.toLocaleDateString('pt-BR', { month: 'short' }).replace('.', '') + '/' + y.slice(2);
    });

    const incomeData = [];
    const expenseData = [];

    months.forEach(m => {
      const monthTxs = allTransactions.filter(t => t.date && t.date.startsWith(m));
      const inc = monthTxs.filter(t => t.type === 'income').reduce((acc, cur) => acc + Number(cur.amount), 0);
      const exp = monthTxs.filter(t => t.type === 'expense').reduce((acc, cur) => acc + Number(cur.amount), 0);
      incomeData.push(inc);
      expenseData.push(exp);
    });

    const isDark = ThemeManager.isDark();
    const colors = this.getColors(isDark);

    if (this.historyChartInstance) {
      this.historyChartInstance.destroy();
    }

    const ctx = canvas.getContext('2d');
    this.historyChartInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Receitas',
            data: incomeData,
            backgroundColor: '#10b981',
            borderRadius: 5,
            maxBarThickness: 24
          },
          {
            label: 'Despesas',
            data: expenseData,
            backgroundColor: '#f43f5e',
            borderRadius: 5,
            maxBarThickness: 24
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: {
            position: 'top',
            align: 'end',
            labels: {
              color: colors.text,
              font: { family: 'Inter', size: 11 },
              usePointStyle: true,
              pointStyle: 'circle'
            }
          },
          tooltip: {
            backgroundColor: colors.tooltipBg,
            titleColor: colors.tooltipText,
            bodyColor: colors.tooltipText,
            padding: 8,
            cornerRadius: 8,
            callbacks: {
              label: function(context) {
                return ` ${context.dataset.label}: ${Utils.formatCurrency(context.raw)}`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: colors.text, font: { family: 'Inter', size: 10 } }
          },
          y: {
            grid: { color: colors.grid, drawBorder: false },
            ticks: {
              color: colors.text,
              font: { family: 'Inter', size: 10 },
              callback: function(val) {
                return val >= 1000 ? 'R$ ' + (val / 1000).toFixed(0) + 'k' : 'R$ ' + val;
              }
            }
          }
        }
      }
    });
  },

  updateThemeColors() {
    if (App.state) {
      this.renderCategoryChart(App.getFilteredTransactions());
      this.renderHistoryChart(App.state.transactions, App.state.filters.month);
    }
  }
};

/**
 * Toast Notifications
 */
const Toast = {
  show(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast-anim flex items-center gap-2.5 px-3.5 py-2.5 rounded-xl shadow-lg border text-xs sm:text-sm font-medium text-white transition-all transform pointer-events-auto`;

    let bgClass = 'bg-slate-900 border-slate-700';
    let iconSvg = '';

    if (type === 'success') {
      bgClass = 'bg-emerald-600 border-emerald-500';
      iconSvg = `<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`;
    } else if (type === 'error') {
      bgClass = 'bg-rose-600 border-rose-500';
      iconSvg = `<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>`;
    } else if (type === 'warning') {
      bgClass = 'bg-amber-600 border-amber-500';
      iconSvg = `<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`;
    } else {
      bgClass = 'bg-blue-600 border-blue-500';
      iconSvg = `<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;
    }

    toast.className += ` ${bgClass}`;
    toast.innerHTML = `
      ${iconSvg}
      <span class="flex-1">${Utils.escapeHtml(message)}</span>
      <button type="button" class="text-white/80 hover:text-white p-0.5" onclick="this.parentElement.remove()">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-8px)';
      setTimeout(() => toast.remove(), 250);
    }, duration);
  }
};

/**
 * Autenticação e Desbloqueio (AuthUI)
 */
const AuthUI = {
  mode: 'login',
  failedAttempts: 0,
  idleTimer: null,
  busy: false,

  el(id) {
    return document.getElementById(id);
  },

  getSavedPassword() {
    try {
      let b64 = localStorage.getItem('fincontrol_auto_auth');
      if (!b64) {
        const match = document.cookie.match(/(?:^|;\s*)fincontrol_auto_auth=([^;]+)/);
        if (match) b64 = decodeURIComponent(match[1]);
      }
      if (b64) {
        return decodeURIComponent(atob(b64));
      }
    } catch (e) {
      console.warn('Erro ao ler credencial salva:', e);
    }
    return null;
  },

  savePassword(pwd) {
    try {
      const b64 = btoa(encodeURIComponent(pwd));
      localStorage.setItem('fincontrol_auto_auth', b64);
      document.cookie = `fincontrol_auto_auth=${encodeURIComponent(b64)}; max-age=31536000; path=/; SameSite=Strict`;
    } catch (e) {}
  },

  clearSavedPassword() {
    try {
      localStorage.removeItem('fincontrol_auto_auth');
      document.cookie = 'fincontrol_auto_auth=; max-age=0; path=/';
    } catch (e) {}
  },

  hasSavedPassword() {
    return !!this.getSavedPassword();
  },

  async init() {
    this.el('auth-form').addEventListener('submit', (e) => this.handleSubmit(e));
    this.el('auth-toggle-visibility').addEventListener('click', () => this.toggleVisibility());
    this.el('auth-forgot').addEventListener('click', () => this.handleForgot());
    this.el('auth-restore-toggle').addEventListener('click', () => {
      this.mode = this.mode === 'restore' ? 'setup' : 'restore';
      this.clearError();
      this.renderMode();
      this.el(this.mode === 'restore' ? 'auth-token' : 'auth-password').focus();
    });

    const reason = sessionStorage.getItem(LOCK_REASON_KEY);
    if (reason) {
      sessionStorage.removeItem(LOCK_REASON_KEY);
      const info = this.el('auth-info');
      info.textContent = reason;
      info.classList.remove('hidden');
    }

    if (!this.isCryptoAvailable()) return;

    // Se já houver senha salva para manter conectado, entra direto sem pedir senha!
    const autoPwd = this.getSavedPassword();
    if (autoPwd && CryptoVault.hasVault()) {
      try {
        const data = await CryptoVault.unlock(autoPwd);
        this.onSuccess(data);
        return;
      } catch (err) {
        console.warn('Auto-login falhou:', err);
        this.clearSavedPassword();
      }
    }

    this.mode = CryptoVault.hasVault() ? 'login' : 'setup';
    this.renderMode();
    this.show();
  },

  isCryptoAvailable() {
    if (CryptoVault.isSupported()) return true;
    this.showError('Navegador sem suporte a Web Crypto API.');
    this.el('auth-submit').disabled = true;
    this.show();
    return false;
  },

  renderMode() {
    const isSetup = this.mode === 'setup';
    const isRestore = this.mode === 'restore';
    const titles = { setup: 'Crie sua senha de acesso', login: 'Bem-vindo de volta', restore: 'Restaurar da nuvem' };
    const subtitles = {
      setup: 'Seus dados financeiros serão criptografados com esta senha.',
      login: 'Digite sua senha para desbloquear seus dados.',
      restore: 'Informe seu token do GitHub e a mesma senha do outro aparelho.'
    };
    const labels = { setup: 'Criar senha e entrar', login: 'Desbloquear', restore: 'Restaurar e entrar' };

    this.el('auth-title').textContent = titles[this.mode];
    this.el('auth-subtitle').textContent = subtitles[this.mode];
    this.el('auth-submit-label').textContent = labels[this.mode];
    this.el('auth-confirm-wrapper').classList.toggle('hidden', !isSetup);
    this.el('auth-token-wrapper').classList.toggle('hidden', !isRestore);
    this.el('auth-setup-notice').classList.toggle('hidden', !isSetup);
    this.el('auth-forgot').classList.toggle('hidden', this.mode !== 'login');
    this.el('auth-restore-toggle').classList.toggle('hidden', this.mode === 'login');
    this.el('auth-restore-toggle').textContent = isRestore
      ? '← Criar uma nova senha neste aparelho'
      : 'Já usa em outro aparelho? Restaurar da nuvem';
    this.el('auth-password').setAttribute('autocomplete', isSetup ? 'new-password' : 'current-password');
    this.el('auth-password-confirm').required = isSetup;
  },

  show() {
    this.el('auth-screen').classList.remove('hidden');
    this.el('app-root').classList.add('hidden');
    setTimeout(() => this.el('auth-password').focus(), 50);
  },

  hide() {
    this.el('auth-screen').classList.add('hidden');
    this.el('app-root').classList.remove('hidden');
  },

  showError(msg) {
    const el = this.el('auth-error');
    el.textContent = msg;
    el.classList.remove('hidden');
  },

  clearError() {
    this.el('auth-error').classList.add('hidden');
  },

  setLoading(loading) {
    this.busy = loading;
    this.el('auth-submit').disabled = loading;
    this.el('auth-spinner').classList.toggle('hidden', !loading);
  },

  toggleVisibility() {
    const inputs = [this.el('auth-password'), this.el('auth-password-confirm')];
    const show = inputs[0].type === 'password';
    inputs.forEach(i => { i.type = show ? 'text' : 'password'; });
    this.el('auth-eye-open').classList.toggle('hidden', show);
    this.el('auth-eye-closed').classList.toggle('hidden', !show);
  },

  async handleSubmit(e) {
    e.preventDefault();
    if (this.busy) return;
    this.clearError();

    const pwd = this.el('auth-password').value;
    const remember = this.el('auth-remember')?.checked !== false;

    if (this.mode === 'restore') {
      await this.handleRestore(pwd);
      return;
    }

    if (this.mode === 'setup') {
      const confirmPwd = this.el('auth-password-confirm').value;
      if (pwd.length < MIN_PASSWORD_LENGTH) {
        this.showError(`A senha deve ter no mínimo ${MIN_PASSWORD_LENGTH} caracteres.`);
        return;
      }
      if (pwd !== confirmPwd) {
        this.showError('As senhas não coincidem.');
        return;
      }

      this.setLoading(true);
      try {
        const legacy = StorageService.readLegacyPlain();
        const initial = legacy || StorageService.getDefaultData();
        await CryptoVault.create(pwd, initial);
        StorageService.removeLegacyPlain();
        if (remember) this.savePassword(pwd);
        this.onSuccess(initial, 'Senha criada com sucesso!');
      } catch (err) {
        console.error(err);
        this.showError('Não foi possível criar o cofre: ' + err.message);
      } finally {
        this.setLoading(false);
      }
      return;
    }

    // Modo login
    if (!pwd) {
      this.showError('Digite sua senha.');
      return;
    }

    this.setLoading(true);
    try {
      const data = await CryptoVault.unlock(pwd);
      this.failedAttempts = 0;
      if (remember) this.savePassword(pwd);
      else this.clearSavedPassword();
      this.onSuccess(data);
    } catch (err) {
      this.failedAttempts++;
      const delay = Math.min(250 * Math.pow(2, this.failedAttempts), 8000);
      await new Promise(r => setTimeout(r, delay));
      this.showError(err.code === 'BAD_PASSWORD' ? `Senha incorreta. (${this.failedAttempts})` : err.message);
      this.el('auth-password').select();
    } finally {
      this.setLoading(false);
    }
  },

  async handleRestore(pwd) {
    const token = this.el('auth-token').value.trim();
    const remember = this.el('auth-remember')?.checked !== false;
    if (!token || !pwd) {
      this.showError('Informe o token do GitHub e a senha.');
      return;
    }

    this.setLoading(true);
    try {
      await GistAPI.validateToken(token);
      const gistId = await GistAPI.findVaultGist(token);
      const remoteRaw = gistId ? await GistAPI.readVault(token, gistId) : null;
      if (!remoteRaw) {
        throw new Error('Nenhum dado do FinControl encontrado nesta conta do GitHub.');
      }

      localStorage.setItem(VAULT_KEY, remoteRaw);
      let data;
      try {
        data = await CryptoVault.unlock(pwd);
      } catch (e) {
        localStorage.removeItem(VAULT_KEY);
        throw new Error('Senha incorreta para os dados da nuvem.');
      }

      data.settings = { ...(data.settings || {}), sync: { token, gistId } };
      await StorageService.saveData(data);
      if (remember) this.savePassword(pwd);
      this.el('auth-token').value = '';
      this.onSuccess(data, 'Dados restaurados da nuvem com sucesso!');
    } catch (err) {
      console.error(err);
      this.showError(err.message);
    } finally {
      this.setLoading(false);
    }
  },

  onSuccess(data, message) {
    this.el('auth-password').value = '';
    this.el('auth-password-confirm').value = '';
    this.el('auth-info').classList.add('hidden');
    this.hide();
    App.onUnlocked(data);
    this.startIdleWatch();
    if (message) Toast.show(message, 'success', 5000);
  },

  async lock(reason, opts = {}) {
    try {
      if (!opts.skipSync) await SyncService.flushPending();
      await StorageService.flush();
    } finally {
      CryptoVault.lock();
      if (reason) sessionStorage.setItem(LOCK_REASON_KEY, reason);
      location.reload();
    }
  },

  startIdleWatch() {
    // Se estiver configurado para manter conectado, não bloqueia por inatividade
    if (this.hasSavedPassword()) return;

    const reset = () => {
      clearTimeout(this.idleTimer);
      this.idleTimer = setTimeout(() => {
        this.lock(`Sessão bloqueada após ${AUTO_LOCK_MINUTES} minutos de inatividade.`);
      }, AUTO_LOCK_MINUTES * 60 * 1000);
    };
    ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'].forEach(ev => {
      window.addEventListener(ev, reset, { passive: true });
    });
    reset();
  },

  handleForgot() {
    if (!confirm('Por segurança, NÃO existe recuperação de senha: os dados são criptografados com ela.\n\nA única opção é APAGAR todos os dados deste navegador e começar de novo.\n\nDeseja continuar?')) return;
    if (!confirm('Confirma a exclusão definitiva?')) return;

    StorageService.wipeAll();
    sessionStorage.setItem(LOCK_REASON_KEY, 'Dados apagados. Crie uma nova senha para começar.');
    location.reload();
  }
};

/**
 * Dados de Exemplo
 */
const SampleData = {
  generate(baseMonthStr) {
    const now = new Date();
    const currentYear = now.getFullYear();
    const currentMonthNum = String(now.getMonth() + 1).padStart(2, '0');
    const baseMonth = baseMonthStr || `${currentYear}-${currentMonthNum}`;
    const prevMonth = Utils.addMonths(baseMonth, -1);
    const prevMonth2 = Utils.addMonths(baseMonth, -2);

    return [
      { id: Utils.generateId(), description: 'Salário Mensal', amount: 6500.00, type: 'income', category: 'Salário', account: 'Conta Corrente', date: `${baseMonth}-05`, status: 'paid' },
      { id: Utils.generateId(), description: 'Projeto Freelance', amount: 1850.00, type: 'income', category: 'Freelance', account: 'Pix', date: `${baseMonth}-12`, status: 'paid' },
      { id: Utils.generateId(), description: 'Dividendos FIIs', amount: 240.50, type: 'income', category: 'Investimentos', account: 'Investimentos', date: `${baseMonth}-15`, status: 'paid' },
      { id: Utils.generateId(), description: 'Consultoria Remota', amount: 1200.00, type: 'income', category: 'Freelance', account: 'Pix', date: `${baseMonth}-26`, status: 'pending' },

      { id: Utils.generateId(), description: 'Aluguel do Apartamento', amount: 2100.00, type: 'expense', category: 'Moradia', account: 'Conta Corrente', date: `${baseMonth}-08`, status: 'paid' },
      { id: Utils.generateId(), description: 'Condomínio e IPTU', amount: 620.00, type: 'expense', category: 'Moradia', account: 'Boleto', date: `${baseMonth}-10`, status: 'paid' },
      { id: Utils.generateId(), description: 'Supermercado Mensal', amount: 840.30, type: 'expense', category: 'Alimentação', account: 'Cartão de Crédito', date: `${baseMonth}-07`, status: 'paid' },
      { id: Utils.generateId(), description: 'Jantar Restaurante', amount: 180.00, type: 'expense', category: 'Alimentação', account: 'Pix', date: `${baseMonth}-14`, status: 'paid' },
      { id: Utils.generateId(), description: 'Combustível Posto', amount: 250.00, type: 'expense', category: 'Transporte', account: 'Cartão de Crédito', date: `${baseMonth}-11`, status: 'paid' },
      { id: Utils.generateId(), description: 'Farmácia e Medicamentos', amount: 145.90, type: 'expense', category: 'Saúde', account: 'Cartão de Crédito', date: `${baseMonth}-18`, status: 'paid' },
      { id: Utils.generateId(), description: 'Streaming e Assinaturas', amount: 89.90, type: 'expense', category: 'Lazer', account: 'Cartão de Crédito', date: `${baseMonth}-20`, status: 'paid' },
      { id: Utils.generateId(), description: 'Curso de Especialização', amount: 350.00, type: 'expense', category: 'Educação', account: 'Boleto', date: `${baseMonth}-22`, status: 'pending' },

      // Meses Anteriores
      { id: Utils.generateId(), description: 'Salário Mensal', amount: 6500.00, type: 'income', category: 'Salário', account: 'Conta Corrente', date: `${prevMonth}-05`, status: 'paid' },
      { id: Utils.generateId(), description: 'Aluguel', amount: 2100.00, type: 'expense', category: 'Moradia', account: 'Conta Corrente', date: `${prevMonth}-08`, status: 'paid' },
      { id: Utils.generateId(), description: 'Supermercado', amount: 980.00, type: 'expense', category: 'Alimentação', account: 'Cartão de Crédito', date: `${prevMonth}-12`, status: 'paid' },

      { id: Utils.generateId(), description: 'Salário Mensal', amount: 6500.00, type: 'income', category: 'Salário', account: 'Conta Corrente', date: `${prevMonth2}-05`, status: 'paid' },
      { id: Utils.generateId(), description: 'Aluguel', amount: 2100.00, type: 'expense', category: 'Moradia', account: 'Conta Corrente', date: `${prevMonth2}-08`, status: 'paid' }
    ];
  }
};

/**
 * Aplicação Principal (Core Application)
 */
const App = {
  state: {
    transactions: [],
    filters: {
      month: Utils.getCurrentMonth(),
      type: 'all',
      category: 'all',
      status: 'all',
      search: ''
    },
    currentTab: 'overview',
    billsFilter: 'unpaid',
    hideValues: false,
    editingId: null,
    deletingId: null,
    deleted: {},
    settings: {
      budgets: {
        'Alimentação': 1200,
        'Moradia': 2800,
        'Transporte': 500,
        'Lazer': 400
      }
    }
  },

  init() {
    ThemeManager.init();
    this.populateCategorySelects();
    this.setupEventListeners();
    AuthUI.init();
  },

  onUnlocked(data) {
    this.state.transactions = data.transactions || [];
    this.state.deleted = data.deleted || {};
    this.state.settings = data.settings || {};
    if (!this.state.settings.budgets) {
      this.state.settings.budgets = {};
    }

    this.updateMonthSelector();
    this.render();
    SyncService.init();

    if (this.state.transactions.length === 0 && !SyncService.isEnabled()) {
      setTimeout(() => {
        Toast.show('Bem-vindo! Clique em "Dados de Exemplo" para explorar.', 'info', 5000);
      }, 700);
    }
  },

  getPersistPayload() {
    return {
      version: SCHEMA_VERSION,
      transactions: this.state.transactions,
      deleted: this.state.deleted,
      settings: this.state.settings
    };
  },

  applySyncedData(merged) {
    this.state.transactions = merged.transactions;
    this.state.deleted = merged.deleted;
    if (merged.settings && merged.settings.budgets) {
      this.state.settings.budgets = merged.settings.budgets;
    }
    this.render();
  },

  markDeleted(ids) {
    const now = Date.now();
    ids.forEach(id => { this.state.deleted[id] = now; });
  },

  // Alternância de Abas (Tabs)
  switchTab(tabId) {
    this.state.currentTab = tabId;

    ['overview', 'bills', 'transactions', 'reports', 'budgets'].forEach(tab => {
      const section = document.getElementById(`tab-${tab}`);
      if (section) section.classList.toggle('hidden', tab !== tabId);

      // Desktop nav styling
      const desktopBtn = document.querySelector(`[data-tab-btn="${tab}"]`);
      if (desktopBtn) {
        if (tab === tabId) {
          desktopBtn.className = 'px-3 py-1.5 rounded-lg transition-colors nav-tab-active bg-white dark:bg-slate-900 shadow-sm text-blue-600 dark:text-blue-400 font-bold flex items-center gap-1.5';
        } else {
          desktopBtn.className = 'px-3 py-1.5 rounded-lg hover:text-slate-900 dark:hover:text-white transition-colors flex items-center gap-1.5';
        }
      }

      // Mobile bottom nav styling
      const bottomBtn = document.querySelector(`[data-bottom-tab="${tab}"]`);
      if (bottomBtn) {
        if (tab === tabId) {
          bottomBtn.className = 'flex flex-col items-center justify-center flex-1 h-full bottom-tab-active text-blue-600 dark:text-blue-400 font-bold relative';
        } else {
          bottomBtn.className = 'flex flex-col items-center justify-center flex-1 h-full text-slate-400 dark:text-slate-500 hover:text-slate-700 relative';
        }
      }
    });

    if (tabId === 'bills') {
      this.renderBills();
    } else if (tabId === 'reports') {
      const filtered = this.getFilteredTransactions();
      ChartService.renderCategoryChart(filtered);
      ChartService.renderHistoryChart(this.state.transactions, this.state.filters.month);
      this.renderAnalytics(filtered);
    } else if (tabId === 'budgets') {
      this.renderBudgets();
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
  },

  // Alternar visualização dos valores (Olho)
  toggleHideValues() {
    this.state.hideValues = !this.state.hideValues;
    const openIcon = document.getElementById('eye-icon-open');
    const closedIcon = document.getElementById('eye-icon-closed');

    if (openIcon && closedIcon) {
      openIcon.classList.toggle('hidden', this.state.hideValues);
      closedIcon.classList.toggle('hidden', !this.state.hideValues);
    }

    this.render();
    Toast.show(this.state.hideValues ? 'Valores ocultados' : 'Valores visíveis', 'info', 1500);
  },

  formatDisplayValue(amount, prefix = '') {
    if (this.state.hideValues) {
      return '••••••';
    }
    return prefix + Utils.formatCurrency(amount);
  },

  setupEventListeners() {
    // Tema
    document.getElementById('btn-theme-toggle')?.addEventListener('click', () => {
      ThemeManager.toggle();
      ChartService.updateThemeColors();
    });

    // Ocultar/Mostrar valores
    document.getElementById('btn-toggle-visibility-values')?.addEventListener('click', () => {
      this.toggleHideValues();
    });

    // Modais Transação
    document.getElementById('btn-new-transaction')?.addEventListener('click', () => this.openTransactionModal());
    document.getElementById('btn-close-modal')?.addEventListener('click', () => this.closeTransactionModal());
    document.getElementById('btn-cancel-modal')?.addEventListener('click', () => this.closeTransactionModal());
    document.getElementById('form-transaction')?.addEventListener('submit', (e) => this.handleTransactionSubmit(e));

    // Checkbox de Repetição no Modal
    document.getElementById('tx-repeat-checkbox')?.addEventListener('change', (e) => {
      const fields = document.getElementById('tx-repeat-fields');
      if (fields) fields.classList.toggle('hidden', !e.target.checked);
      this.updateRepeatSummary();
    });

    document.querySelectorAll('input[name="tx-repeat-mode"]').forEach(radio => {
      radio.addEventListener('change', () => this.updateRepeatSummary());
    });

    document.getElementById('tx-repeat-count')?.addEventListener('input', () => this.updateRepeatSummary());
    document.getElementById('tx-amount')?.addEventListener('input', () => this.updateRepeatSummary());

    document.querySelectorAll('.btn-quick-repeat').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const count = e.currentTarget.getAttribute('data-count');
        const countInput = document.getElementById('tx-repeat-count');
        if (countInput && count) {
          countInput.value = count;
          this.updateRepeatSummary();
        }
      });
    });

    // Botão de Valor R$ 0 (Variável)
    document.getElementById('btn-set-zero-amount')?.addEventListener('click', () => {
      const amountInput = document.getElementById('tx-amount');
      if (amountInput) {
        amountInput.value = '0';
        this.updateRepeatSummary();
      }
    });

    // Sugestões de contas variáveis rápidas (Água, Energia, Mercado...)
    document.querySelectorAll('.btn-quick-desc').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const desc = e.currentTarget.getAttribute('data-desc');
        const cat = e.currentTarget.getAttribute('data-cat');
        const descInput = document.getElementById('tx-description');
        const catSelect = document.getElementById('tx-category');
        const amountInput = document.getElementById('tx-amount');

        if (descInput && desc) descInput.value = desc;
        if (catSelect && cat) catSelect.value = cat;
        if (amountInput && (!amountInput.value || parseFloat(amountInput.value) === 0)) {
          amountInput.value = '0';
          this.updateRepeatSummary();
        }
      });
    });

    // Navegação de Mês
    document.getElementById('btn-prev-month')?.addEventListener('click', () => {
      this.state.filters.month = Utils.addMonths(this.state.filters.month, -1);
      this.updateMonthSelector();
      this.render();
    });

    document.getElementById('btn-next-month')?.addEventListener('click', () => {
      this.state.filters.month = Utils.addMonths(this.state.filters.month, 1);
      this.updateMonthSelector();
      this.render();
    });

    document.getElementById('filter-month')?.addEventListener('change', (e) => {
      this.state.filters.month = e.target.value;
      this.updateMonthTitle();
      this.render();
    });

    // Filtros
    document.getElementById('filter-category')?.addEventListener('change', (e) => {
      this.state.filters.category = e.target.value;
      this.render();
    });

    document.getElementById('filter-status')?.addEventListener('change', (e) => {
      this.state.filters.status = e.target.value;
      this.render();
    });

    document.getElementById('filter-search')?.addEventListener('input', (e) => {
      this.state.filters.search = e.target.value.trim().toLowerCase();
      this.render();
    });

    document.getElementById('btn-clear-filters')?.addEventListener('click', () => this.clearFilters());

    // Backups
    document.getElementById('btn-export-json')?.addEventListener('click', () => this.exportJSON());
    document.getElementById('btn-export-csv')?.addEventListener('click', () => this.exportCSV());
    document.getElementById('btn-import-json')?.addEventListener('click', () => this.openImportModal());
    document.getElementById('btn-load-sample')?.addEventListener('click', () => this.loadSampleData());
    document.getElementById('btn-clear-all')?.addEventListener('click', () => this.confirmClearAll());

    // Segurança
    document.getElementById('btn-lock')?.addEventListener('click', () => {
      if (confirm('Deseja sair da sua conta e bloquear este aparelho?')) {
        AuthUI.clearSavedPassword();
        AuthUI.lock('Você saiu da sua conta.');
      }
    });
    document.getElementById('btn-change-password')?.addEventListener('click', () => this.openPasswordModal());
    document.getElementById('form-password')?.addEventListener('submit', (e) => this.handleChangePassword(e));
    document.getElementById('btn-cancel-password')?.addEventListener('click', () => this.closePasswordModal());

    // Sincronização
    document.getElementById('btn-sync')?.addEventListener('click', () => this.openSyncModal());
    document.getElementById('btn-close-sync')?.addEventListener('click', () => this.closeSyncModal());
    document.getElementById('btn-sync-connect')?.addEventListener('click', () => this.handleSyncConnect());
    document.getElementById('btn-sync-now')?.addEventListener('click', () => SyncService.syncNow({ silent: false }));
    document.getElementById('btn-sync-disconnect')?.addEventListener('click', () => this.handleSyncDisconnect());

    // Exclusão
    document.getElementById('btn-cancel-delete')?.addEventListener('click', () => this.closeDeleteModal());
    document.getElementById('btn-confirm-delete')?.addEventListener('click', () => this.executeDelete());

    // Importação
    document.getElementById('btn-close-import')?.addEventListener('click', () => this.closeImportModal());
    document.getElementById('btn-cancel-import')?.addEventListener('click', () => this.closeImportModal());
    document.getElementById('btn-process-import')?.addEventListener('click', () => this.handleImportSubmit());

    // Modal de Orçamento
    document.getElementById('form-budget')?.addEventListener('submit', (e) => this.handleBudgetSubmit(e));
    document.getElementById('btn-cancel-budget')?.addEventListener('click', () => this.closeBudgetModal());

    // Fechar modais com Escape
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.closeTransactionModal();
        this.closeDeleteModal();
        this.closeImportModal();
        this.closePasswordModal();
        this.closeSyncModal();
        this.closeBudgetModal();
      }
    });
  },

  populateCategorySelects() {
    const selects = ['tx-category', 'filter-category', 'budget-category'];
    selects.forEach(selectId => {
      const el = document.getElementById(selectId);
      if (!el) return;

      const isFilter = selectId === 'filter-category';
      let optionsHtml = isFilter ? '<option value="all">Todas as Categorias</option>' : '';

      CATEGORIES.forEach(cat => {
        optionsHtml += `<option value="${cat.name}">${cat.name}</option>`;
      });

      el.innerHTML = optionsHtml;
    });
  },

  updateMonthSelector() {
    const selectMonth = document.getElementById('filter-month');
    if (!selectMonth) return;

    const currentM = Utils.getCurrentMonth();
    const options = [];

    for (let i = -12; i <= 6; i++) {
      options.push(Utils.addMonths(currentM, i));
    }

    if (!options.includes(this.state.filters.month)) {
      options.push(this.state.filters.month);
      options.sort();
    }

    selectMonth.innerHTML = options.map(m => {
      const isSelected = m === this.state.filters.month ? 'selected' : '';
      return `<option value="${m}" ${isSelected}>${Utils.formatMonthYear(m)}</option>`;
    }).join('');

    this.updateMonthTitle();
  },

  updateMonthTitle() {
    const el = document.getElementById('current-month-display');
    if (el) {
      el.textContent = Utils.formatMonthYear(this.state.filters.month);
    }
  },

  setFilterType(type) {
    this.state.filters.type = type;
    const chips = ['all', 'income', 'expense'];
    chips.forEach(c => {
      const btn = document.querySelector(`[data-type-chip="${c}"]`);
      if (btn) {
        if (c === type) {
          btn.className = 'px-3 py-1 rounded-full font-semibold bg-blue-600 text-white whitespace-nowrap';
        } else {
          btn.className = 'px-3 py-1 rounded-full font-semibold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 whitespace-nowrap';
        }
      }
    });
    this.render();
  },

  setFilterStatus(status) {
    this.state.filters.status = this.state.filters.status === status ? 'all' : status;
    const btn = document.querySelector('[data-status-chip="pending"]');
    if (btn) {
      if (this.state.filters.status === 'pending') {
        btn.className = 'px-3 py-1 rounded-full font-semibold bg-amber-600 text-white whitespace-nowrap';
      } else {
        btn.className = 'px-3 py-1 rounded-full font-semibold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 whitespace-nowrap';
      }
    }
    const selectStatus = document.getElementById('filter-status');
    if (selectStatus) selectStatus.value = this.state.filters.status;
    this.render();
  },

  getFilteredTransactions() {
    const { month, type, category, status, search } = this.state.filters;

    return this.state.transactions.filter(t => {
      if (month && (!t.date || !t.date.startsWith(month))) return false;
      if (type !== 'all' && t.type !== type) return false;
      if (category !== 'all' && t.category !== category) return false;
      if (status !== 'all' && t.status !== status) return false;
      if (search && !t.description.toLowerCase().includes(search)) return false;
      return true;
    }).sort((a, b) => new Date(b.date) - new Date(a.date));
  },

  render() {
    const filteredTxs = this.getFilteredTransactions();
    this.renderKPIs(filteredTxs);
    this.renderTable(filteredTxs);
    this.renderMobileList(filteredTxs);
    this.renderRecentOverviewList(filteredTxs);
    this.renderBudgetsHeroProgress(filteredTxs);
    this.renderBills();

    if (this.state.currentTab === 'reports') {
      ChartService.renderCategoryChart(filteredTxs);
      ChartService.renderHistoryChart(this.state.transactions, this.state.filters.month);
      this.renderAnalytics(filteredTxs);
    } else if (this.state.currentTab === 'budgets') {
      this.renderBudgets();
    } else if (this.state.currentTab === 'bills') {
      this.renderBills();
    }
  },

  renderKPIs(filteredTxs) {
    let incomePaid = 0;
    let incomePending = 0;
    let expensePaid = 0;
    let expensePending = 0;

    filteredTxs.forEach(t => {
      const val = Number(t.amount) || 0;
      if (t.type === 'income') {
        if (t.status === 'paid') incomePaid += val;
        else incomePending += val;
      } else if (t.type === 'expense') {
        if (t.status === 'paid') expensePaid += val;
        else expensePending += val;
      }
    });

    const totalIncome = incomePaid + incomePending;
    const totalExpense = expensePaid + expensePending;
    const currentBalance = incomePaid - expensePaid;
    const projectedBalance = totalIncome - totalExpense;

    const elBalance = document.getElementById('kpi-balance');
    const elProjected = document.getElementById('kpi-projected');
    const elIncome = document.getElementById('kpi-income');
    const elExpense = document.getElementById('kpi-expense');

    if (elBalance) {
      elBalance.textContent = this.formatDisplayValue(currentBalance);
    }
    if (elProjected) {
      elProjected.textContent = this.formatDisplayValue(projectedBalance);
    }
    if (elIncome) {
      elIncome.textContent = this.formatDisplayValue(totalIncome);
    }
    if (elExpense) {
      elExpense.textContent = this.formatDisplayValue(totalExpense);
    }
  },

  // Lista Mobile Nativa de Transações (Extrato)
  renderMobileList(transactions) {
    const container = document.getElementById('mobile-transactions-list');
    if (!container) return;

    if (transactions.length === 0) {
      container.innerHTML = '';
      return;
    }

    container.innerHTML = transactions.map(t => {
      const isIncome = t.type === 'income';
      const isPaid = t.status === 'paid';
      const catObj = CATEGORIES.find(c => c.name.toLowerCase() === (t.category || '').toLowerCase());
      const catColor = catObj ? catObj.color : '#64748b';
      const accountBadge = t.account ? `<span class="px-1.5 py-0.5 rounded text-[10px] bg-slate-100 dark:bg-slate-800 text-slate-500 font-medium">${Utils.escapeHtml(t.account)}</span>` : '';

      const isZero = Number(t.amount) === 0;
      const amountFormatted = isZero
        ? `<span class="text-amber-500 font-bold">R$ 0,00 <span class="text-[10px] font-normal text-amber-600 dark:text-amber-300">(Variável)</span></span>`
        : ((isIncome ? '+ ' : '- ') + this.formatDisplayValue(t.amount));
      const amountColor = isIncome ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400';

      const statusBadge = isPaid
        ? `<button type="button" onclick="App.toggleStatus('${t.id}')" class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60 active:scale-95 transition-transform">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Pago
           </button>`
        : `<button type="button" onclick="App.toggleStatus('${t.id}')" class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60 active:scale-95 transition-transform">
            <span class="w-1.5 h-1.5 rounded-full bg-amber-500 status-pulse"></span> Pendente
           </button>`;

      return `
        <div class="p-3.5 flex items-center justify-between gap-3 active:bg-slate-50 dark:active:bg-slate-800/50 transition-colors">
          <div class="flex items-center gap-3 flex-1 min-w-0">
            <div class="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 text-white font-bold text-xs shadow-sm" style="background-color: ${catColor}">
              ${(t.category || 'O').substring(0, 2).toUpperCase()}
            </div>
            <div class="flex-1 min-w-0">
              <div class="font-semibold text-slate-900 dark:text-slate-100 text-xs sm:text-sm truncate">
                ${Utils.escapeHtml(t.description)}
              </div>
              <div class="flex items-center gap-1.5 mt-0.5">
                <span class="text-[11px] text-slate-400 font-medium">${Utils.formatDateBR(t.date)}</span>
                ${accountBadge}
              </div>
            </div>
          </div>

          <div class="text-right flex flex-col items-end gap-1 flex-shrink-0">
            <div class="text-xs sm:text-sm font-bold ${amountColor}">
              ${amountFormatted}
            </div>
            <div class="flex items-center gap-1.5">
              ${statusBadge}
              <button type="button" onclick="App.openEditModal('${t.id}')" class="p-1 text-slate-400 hover:text-blue-600">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/></svg>
              </button>
              <button type="button" onclick="App.openDeleteModal('${t.id}')" class="p-1 text-slate-400 hover:text-rose-600">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
              </button>
            </div>
          </div>
        </div>
      `;
    }).join('');
  },

  // Tabela Desktop
  renderTable(transactions) {
    const tbody = document.getElementById('transactions-table-body');
    const emptyState = document.getElementById('transactions-empty-state');
    const countBadge = document.getElementById('transactions-count-badge');

    if (countBadge) {
      countBadge.textContent = `${transactions.length} ${transactions.length === 1 ? 'item' : 'itens'}`;
    }

    if (!tbody) return;

    if (transactions.length === 0) {
      tbody.innerHTML = '';
      if (emptyState) emptyState.classList.remove('hidden');
      return;
    }

    if (emptyState) emptyState.classList.add('hidden');

    tbody.innerHTML = transactions.map(t => {
      const isIncome = t.type === 'income';
      const isPaid = t.status === 'paid';
      const catObj = CATEGORIES.find(c => c.name.toLowerCase() === (t.category || '').toLowerCase());
      const catColor = catObj ? catObj.color : '#64748b';

      const statusBadge = isPaid
        ? `<button type="button" onclick="App.toggleStatus('${t.id}')" class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60 hover:bg-emerald-100">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Pago
           </button>`
        : `<button type="button" onclick="App.toggleStatus('${t.id}')" class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-amber-50 dark:bg-amber-950/50 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60 hover:bg-amber-100">
            <span class="w-1.5 h-1.5 rounded-full bg-amber-500 status-pulse"></span> Pendente
           </button>`;

      const isZero = Number(t.amount) === 0;
      const amountFormatted = isZero
        ? `<span class="text-amber-500 font-bold">R$ 0,00 <span class="text-[11px] font-normal text-amber-600 dark:text-amber-300">(Variável)</span></span>`
        : ((isIncome ? '+ ' : '- ') + this.formatDisplayValue(t.amount));
      const amountColor = isIncome ? 'text-emerald-600 dark:text-emerald-400 font-bold' : 'text-rose-600 dark:text-rose-400 font-bold';

      return `
        <tr class="table-row-hover border-b border-slate-200 dark:border-slate-800/80 hover:bg-slate-50/70 dark:hover:bg-slate-800/40 text-xs sm:text-sm">
          <td class="py-3 px-4 whitespace-nowrap text-slate-500 font-medium">
            ${Utils.formatDateBR(t.date)}
          </td>
          <td class="py-3 px-4 font-semibold text-slate-900 dark:text-slate-100">
            ${Utils.escapeHtml(t.description)}
          </td>
          <td class="py-3 px-4">
            <div class="flex items-center gap-1.5">
              <span class="w-2.5 h-2.5 rounded-full" style="background-color: ${catColor}"></span>
              <span class="text-slate-700 dark:text-slate-300">${Utils.escapeHtml(t.category)}</span>
            </div>
          </td>
          <td class="py-3 px-4 text-slate-500 text-xs">
            ${Utils.escapeHtml(t.account || 'Padrão')}
          </td>
          <td class="py-3 px-4 whitespace-nowrap">
            ${statusBadge}
          </td>
          <td class="py-3 px-4 text-right whitespace-nowrap ${amountColor}">
            ${amountFormatted}
          </td>
          <td class="py-3 px-4 text-right whitespace-nowrap">
            <button type="button" onclick="App.openEditModal('${t.id}')" class="p-1 text-slate-400 hover:text-blue-600">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/></svg>
            </button>
            <button type="button" onclick="App.openDeleteModal('${t.id}')" class="p-1 text-slate-400 hover:text-rose-600">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  // Últimos lançamentos na Visão Geral
  renderRecentOverviewList(transactions) {
    const list = document.getElementById('recent-transactions-list');
    if (!list) return;

    const recent = transactions.slice(0, 5);
    if (recent.length === 0) {
      list.innerHTML = `<div class="py-6 text-center text-xs text-slate-400">Nenhum lançamento no mês selecionado.</div>`;
      return;
    }

    list.innerHTML = recent.map(t => {
      const isIncome = t.type === 'income';
      const catObj = CATEGORIES.find(c => c.name.toLowerCase() === (t.category || '').toLowerCase());
      const catColor = catObj ? catObj.color : '#64748b';
      const amountColor = isIncome ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400';
      const amountFormatted = (isIncome ? '+ ' : '- ') + this.formatDisplayValue(t.amount);

      return `
        <div class="py-2.5 flex items-center justify-between gap-3 text-xs">
          <div class="flex items-center gap-2.5 flex-1 min-w-0">
            <span class="w-2.5 h-2.5 rounded-full flex-shrink-0" style="background-color: ${catColor}"></span>
            <div class="flex-1 min-w-0">
              <div class="font-semibold text-slate-800 dark:text-slate-200 truncate">${Utils.escapeHtml(t.description)}</div>
              <div class="text-[10px] text-slate-400">${Utils.formatDateBR(t.date)} • ${Utils.escapeHtml(t.category)}</div>
            </div>
          </div>
          <div class="font-bold ${amountColor} flex-shrink-0">
            ${amountFormatted}
          </div>
        </div>
      `;
    }).join('');
  },

  // Hero Budget Progress
  renderBudgetsHeroProgress(transactions) {
    const bar = document.getElementById('hero-budget-bar');
    const pctLabel = document.getElementById('hero-budget-percentage');
    const spentLabel = document.getElementById('hero-budget-spent');
    const limitLabel = document.getElementById('hero-budget-limit');

    if (!bar || !pctLabel) return;

    const budgets = (this.state.settings && this.state.settings.budgets) || {};
    const totalLimit = Object.values(budgets).reduce((a, b) => a + Number(b), 0);

    const totalExpense = transactions
      .filter(t => t.type === 'expense')
      .reduce((a, b) => a + Number(b.amount), 0);

    if (totalLimit <= 0) {
      pctLabel.textContent = 'Sem meta definida';
      bar.style.width = '0%';
      spentLabel.textContent = `Gasto: ${this.formatDisplayValue(totalExpense)}`;
      limitLabel.textContent = 'Toque em "Metas" para definir';
      return;
    }

    const pct = Math.min(Math.round((totalExpense / totalLimit) * 100), 100);
    pctLabel.textContent = `${pct}%`;
    bar.style.width = `${pct}%`;

    if (pct >= 100) {
      bar.className = 'h-full bg-rose-500 rounded-full transition-all duration-500';
    } else if (pct >= 80) {
      bar.className = 'h-full bg-amber-400 rounded-full transition-all duration-500';
    } else {
      bar.className = 'h-full bg-blue-500 rounded-full transition-all duration-500';
    }

    spentLabel.textContent = `Gasto: ${this.formatDisplayValue(totalExpense)}`;
    limitLabel.textContent = `Teto: ${this.formatDisplayValue(totalLimit)}`;
  },

  // =========================================================================
  // GESTÃO DE CONTAS A PAGAR & VENCIMENTOS (O que já pagou e o que falta)
  // =========================================================================

  setBillsFilter(filter) {
    this.state.billsFilter = filter;
    const chips = ['unpaid', 'overdue', 'paid', 'all'];
    const colors = {
      unpaid: 'bg-amber-600 text-white',
      overdue: 'bg-rose-600 text-white',
      paid: 'bg-emerald-600 text-white',
      all: 'bg-blue-600 text-white'
    };
    chips.forEach(c => {
      const btn = document.querySelector(`[data-bills-chip="${c}"]`);
      if (btn) {
        if (c === filter) {
          btn.className = `px-3 py-1.5 rounded-full font-bold whitespace-nowrap shadow-sm ${colors[c]}`;
        } else {
          btn.className = 'px-3 py-1.5 rounded-full font-bold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 whitespace-nowrap';
        }
      }
    });

    const titles = {
      unpaid: 'Contas que faltam pagar',
      overdue: 'Contas atrasadas / vencidas',
      paid: 'Contas já pagas neste mês',
      all: 'Todas as contas do mês'
    };
    const titleEl = document.getElementById('bills-filter-title');
    if (titleEl) titleEl.textContent = titles[filter] || 'Contas Pessoais';

    this.renderBills();
  },

  renderBills() {
    const month = this.state.filters.month;
    const today = new Date().toISOString().split('T')[0];

    const bills = this.state.transactions.filter(t => t.type === 'expense' && t.date && t.date.startsWith(month));

    const paidBills = bills.filter(t => t.status === 'paid');
    const unpaidBills = bills.filter(t => t.status === 'pending');
    const overdueBills = unpaidBills.filter(t => t.date < today);

    const totalPaid = paidBills.reduce((acc, cur) => acc + Number(cur.amount), 0);
    const totalUnpaid = unpaidBills.reduce((acc, cur) => acc + Number(cur.amount), 0);
    const totalOverdue = overdueBills.reduce((acc, cur) => acc + Number(cur.amount), 0);
    const totalAll = totalPaid + totalUnpaid;

    // Badges de notificação
    const unpaidCount = unpaidBills.length;
    const badgeDesktop = document.getElementById('badge-desktop-bills');
    const badgeBottom = document.getElementById('badge-bottom-bills');
    const badgeQuick = document.getElementById('badge-quick-bills');

    [badgeDesktop, badgeBottom, badgeQuick].forEach(badge => {
      if (!badge) return;
      if (unpaidCount > 0) {
        badge.textContent = unpaidCount;
        badge.classList.remove('hidden');
      } else {
        badge.classList.add('hidden');
      }
    });

    // Painel na Visão Geral (Overview)
    const ovText = document.getElementById('overview-bills-progress-text');
    const ovPct = document.getElementById('overview-bills-progress-pct');
    const ovBar = document.getElementById('overview-bills-progress-bar');
    const ovUnpaid = document.getElementById('overview-bills-unpaid');
    const ovUnpaidCount = document.getElementById('overview-bills-unpaid-count');
    const ovPaid = document.getElementById('overview-bills-paid');
    const ovPaidCount = document.getElementById('overview-bills-paid-count');
    const ovOverdueBox = document.getElementById('overview-bills-overdue-box');
    const ovOverdue = document.getElementById('overview-bills-overdue');
    const ovOverdueCount = document.getElementById('overview-bills-overdue-count');
    const ovUpcoming = document.getElementById('overview-upcoming-bills');

    const totalCount = bills.length;
    const pct = totalCount > 0 ? (paidBills.length / totalCount) * 100 : 0;

    if (ovText) ovText.textContent = `${paidBills.length} de ${totalCount} contas pagas`;
    if (ovPct) ovPct.textContent = `${Math.round(pct)}% pago`;
    if (ovBar) ovBar.style.width = `${pct}%`;

    if (ovUnpaid) ovUnpaid.textContent = this.formatDisplayValue(totalUnpaid);
    if (ovUnpaidCount) ovUnpaidCount.textContent = `${unpaidBills.length} contas pendentes`;

    if (ovPaid) ovPaid.textContent = this.formatDisplayValue(totalPaid);
    if (ovPaidCount) ovPaidCount.textContent = `${paidBills.length} contas quitadas`;

    if (ovOverdueBox) {
      if (overdueBills.length > 0) {
        ovOverdueBox.classList.remove('hidden');
        if (ovOverdue) ovOverdue.textContent = this.formatDisplayValue(totalOverdue);
        if (ovOverdueCount) ovOverdueCount.textContent = `${overdueBills.length} ${overdueBills.length === 1 ? 'conta vencida' : 'contas vencidas'}`;
      } else {
        ovOverdueBox.classList.add('hidden');
      }
    }

    if (ovUpcoming) {
      if (unpaidBills.length === 0) {
        ovUpcoming.innerHTML = `
          <div class="py-2.5 px-3 rounded-xl bg-emerald-50/70 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300 text-xs flex items-center gap-2">
            <svg class="w-4 h-4 text-emerald-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
            <span>Tudo pago! Todas as contas deste período já foram quitadas.</span>
          </div>
        `;
      } else {
        const sortedUnpaid = [...unpaidBills].sort((a, b) => new Date(a.date) - new Date(b.date)).slice(0, 3);
        ovUpcoming.innerHTML = sortedUnpaid.map(t => {
          const isOverdue = t.date < today;
          const isToday = t.date === today;
          let dueLabel = Utils.formatDateBR(t.date);
          let badgeClass = 'text-slate-500 bg-slate-100 dark:bg-slate-800';

          if (isOverdue) {
            dueLabel = 'Vencida!';
            badgeClass = 'text-rose-700 bg-rose-100 dark:bg-rose-950/60 dark:text-rose-300 font-bold';
          } else if (isToday) {
            dueLabel = 'Vence Hoje!';
            badgeClass = 'text-amber-800 bg-amber-100 dark:bg-amber-950/60 dark:text-amber-300 font-bold';
          }

          return `
            <div class="p-2.5 rounded-xl border border-slate-100 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-800/30 flex items-center justify-between gap-2 text-xs">
              <div class="flex-1 min-w-0">
                <div class="font-bold text-slate-800 dark:text-slate-200 truncate">${Utils.escapeHtml(t.description)}</div>
                <div class="flex items-center gap-1.5 mt-0.5">
                  <span class="px-1.5 py-0.2 rounded text-[10px] ${badgeClass}">${dueLabel}</span>
                  <span class="text-[10px] text-slate-400">${Utils.escapeHtml(t.category)}</span>
                </div>
              </div>
              <div class="text-right flex items-center gap-2 flex-shrink-0">
                <span class="font-bold ${Number(t.amount) === 0 ? 'text-amber-500' : 'text-rose-600 dark:text-rose-400'}">${Number(t.amount) === 0 ? 'R$ 0 (Variável)' : this.formatDisplayValue(t.amount)}</span>
                <button type="button" onclick="App.payBill('${t.id}')" title="Marcar como Paga" class="px-2.5 py-1 rounded-lg text-xs font-bold bg-emerald-600 hover:bg-emerald-700 text-white shadow-sm active:scale-95 transition-all">
                  Pagar
                </button>
              </div>
            </div>
          `;
        }).join('');
      }
    }

    // Totais na tela de Contas (tab-bills)
    const elTotUnpaid = document.getElementById('bills-total-unpaid');
    const elCntUnpaid = document.getElementById('bills-count-unpaid');
    const elTotPaid = document.getElementById('bills-total-paid');
    const elCntPaid = document.getElementById('bills-count-paid');
    const elTotOver = document.getElementById('bills-total-overdue');
    const elCntOver = document.getElementById('bills-count-overdue');
    const elTotAll = document.getElementById('bills-total-all');
    const elCntAll = document.getElementById('bills-count-all');

    if (elTotUnpaid) elTotUnpaid.textContent = this.formatDisplayValue(totalUnpaid);
    if (elCntUnpaid) elCntUnpaid.textContent = `${unpaidBills.length} contas a vencer`;

    if (elTotPaid) elTotPaid.textContent = this.formatDisplayValue(totalPaid);
    if (elCntPaid) elCntPaid.textContent = `${paidBills.length} contas quitadas`;

    if (elTotOver) elTotOver.textContent = this.formatDisplayValue(totalOverdue);
    if (elCntOver) elCntOver.textContent = `${overdueBills.length} contas atrasadas`;

    if (elTotAll) elTotAll.textContent = this.formatDisplayValue(totalAll);
    if (elCntAll) elCntAll.textContent = `${bills.length} contas no total`;

    // Lista Filtrada de Contas
    const listContainer = document.getElementById('bills-items-list');
    const emptyState = document.getElementById('bills-empty-state');
    if (!listContainer) return;

    let displayList = [];
    if (this.state.billsFilter === 'unpaid') {
      displayList = [...unpaidBills].sort((a, b) => new Date(a.date) - new Date(b.date));
    } else if (this.state.billsFilter === 'overdue') {
      displayList = [...overdueBills].sort((a, b) => new Date(a.date) - new Date(b.date));
    } else if (this.state.billsFilter === 'paid') {
      displayList = [...paidBills].sort((a, b) => new Date(b.date) - new Date(a.date));
    } else {
      displayList = [...bills].sort((a, b) => new Date(a.date) - new Date(b.date));
    }

    if (displayList.length === 0) {
      listContainer.innerHTML = '';
      emptyState?.classList.remove('hidden');
      return;
    }

    emptyState?.classList.add('hidden');

    listContainer.innerHTML = displayList.map(t => {
      const isPaid = t.status === 'paid';
      const isOverdue = !isPaid && t.date < today;
      const isToday = !isPaid && t.date === today;
      const catObj = CATEGORIES.find(c => c.name.toLowerCase() === (t.category || '').toLowerCase());
      const catColor = catObj ? catObj.color : '#64748b';

      let dueText = '';
      let badgeStyle = '';

      if (isPaid) {
        dueText = `✓ Paga (${Utils.formatDateBR(t.date)})`;
        badgeStyle = 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300';
      } else if (isOverdue) {
        const diffDays = Math.max(1, Math.floor((new Date(today) - new Date(t.date)) / (1000 * 60 * 60 * 24)));
        dueText = `🚨 Atrasada há ${diffDays} dia(s)`;
        badgeStyle = 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 font-bold status-pulse';
      } else if (isToday) {
        dueText = '⏰ Vence Hoje!';
        badgeStyle = 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 font-bold status-pulse';
      } else {
        const diffDays = Math.floor((new Date(t.date) - new Date(today)) / (1000 * 60 * 60 * 24));
        dueText = `⏳ Vence em ${diffDays} dia(s) (${Utils.formatDateBR(t.date)})`;
        badgeStyle = 'bg-blue-50 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300';
      }

      const actionButton = !isPaid
        ? `<button type="button" onclick="App.payBill('${t.id}')" class="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-emerald-600 hover:bg-emerald-700 active:bg-emerald-800 text-white shadow-sm active:scale-95 transition-all flex items-center gap-1">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
            Pagar
           </button>`
        : `<button type="button" onclick="App.toggleStatus('${t.id}')" title="Reabrir conta como pendente" class="px-2.5 py-1 rounded-xl text-xs font-medium text-slate-500 hover:text-amber-600 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
            Desfazer
           </button>`;

      return `
        <div class="p-3.5 sm:p-4 flex items-center justify-between gap-3 active:bg-slate-50 dark:active:bg-slate-800/40 transition-colors">
          <div class="flex items-center gap-3 flex-1 min-w-0">
            <div class="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 text-white font-bold text-xs shadow-sm" style="background-color: ${catColor}">
              ${(t.category || 'O').substring(0, 2).toUpperCase()}
            </div>
            <div class="flex-1 min-w-0">
              <div class="font-bold text-slate-900 dark:text-slate-100 text-xs sm:text-sm truncate">
                ${Utils.escapeHtml(t.description)}
              </div>
              <div class="flex flex-wrap items-center gap-1.5 mt-1">
                <span class="px-2 py-0.5 rounded-full text-[10px] font-semibold ${badgeStyle}">
                  ${dueText}
                </span>
                <span class="text-[10px] text-slate-400">
                  ${Utils.escapeHtml(t.category)} • ${Utils.escapeHtml(t.account || 'Conta Corrente')}
                </span>
              </div>
            </div>
          </div>

          <div class="text-right flex items-center gap-3 flex-shrink-0">
            <div class="text-xs sm:text-sm font-extrabold ${Number(t.amount) === 0 ? 'text-amber-500' : (isPaid ? 'text-slate-500 line-through' : 'text-rose-600 dark:text-rose-400')}">
              ${Number(t.amount) === 0 ? 'R$ 0,00 <span class="text-[10px] font-normal text-amber-600 dark:text-amber-300 block sm:inline">(Variável)</span>' : this.formatDisplayValue(t.amount)}
            </div>
            ${actionButton}
            <div class="flex items-center">
              <button type="button" onclick="App.openEditModal('${t.id}')" class="p-1 text-slate-400 hover:text-blue-600">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/></svg>
              </button>
            </div>
          </div>
        </div>
      `;
    }).join('');
  },

  payBill(id) {
    const tx = this.state.transactions.find(t => t.id === id);
    if (!tx) return;

    if (Number(tx.amount) === 0) {
      const input = prompt(`A conta "${tx.description}" está com valor R$ 0,00 (variável).\nInforme o valor pago da fatura (ex: 85,50):`);
      if (input === null) return; // cancelado
      const parsed = parseFloat(input.replace(',', '.'));
      if (isNaN(parsed) || parsed < 0) {
        Toast.show('Valor inválido. A conta não foi baixada.', 'warning');
        return;
      }
      tx.amount = parsed;
    }

    tx.status = 'paid';
    tx.updatedAt = Date.now();
    this.saveAndSync();
    Toast.show(`Conta "${tx.description}" marcada como PAGA! 🎉`, 'success', 3000);
  },

  // Aba de Orçamentos e Metas
  renderBudgets() {
    const container = document.getElementById('budgets-list-container');
    if (!container) return;

    const filtered = this.getFilteredTransactions();
    const expenses = filtered.filter(t => t.type === 'expense');

    const spentByCategory = {};
    expenses.forEach(t => {
      const cat = t.category || 'Outros';
      spentByCategory[cat] = (spentByCategory[cat] || 0) + Number(t.amount);
    });

    const budgets = (this.state.settings && this.state.settings.budgets) || {};

    container.innerHTML = CATEGORIES.map(cat => {
      const spent = spentByCategory[cat.name] || 0;
      const limit = budgets[cat.name] || 0;
      const pct = limit > 0 ? Math.min(Math.round((spent / limit) * 100), 100) : 0;

      let barColor = 'bg-emerald-500';
      if (pct >= 100) barColor = 'bg-rose-500';
      else if (pct >= 75) barColor = 'bg-amber-500';

      return `
        <div class="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40 space-y-2">
          <div class="flex items-center justify-between text-xs">
            <div class="flex items-center gap-2">
              <span class="w-3 h-3 rounded-full" style="background-color: ${cat.color}"></span>
              <span class="font-bold text-slate-800 dark:text-slate-200">${cat.name}</span>
            </div>
            <button type="button" onclick="App.openBudgetModalFor('${cat.name}', ${limit})" class="text-blue-600 dark:text-blue-400 hover:underline font-semibold text-[11px]">
              ${limit > 0 ? 'Alterar Limite' : '+ Definir Limite'}
            </button>
          </div>

          <div class="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-2 overflow-hidden">
            <div class="h-full ${barColor} rounded-full transition-all duration-300" style="width: ${limit > 0 ? pct : 0}%"></div>
          </div>

          <div class="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
            <span>Gasto: <strong>${this.formatDisplayValue(spent)}</strong></span>
            <span>Limite: <strong>${limit > 0 ? this.formatDisplayValue(limit) : 'Não definido'}</strong> ${limit > 0 ? `(${pct}%)` : ''}</span>
          </div>
        </div>
      `;
    }).join('');
  },

  // Métricas da Aba de Relatórios
  renderAnalytics(filteredTxs) {
    let income = 0;
    let expense = 0;
    let highest = { amount: 0, description: '-' };

    filteredTxs.forEach(t => {
      const val = Number(t.amount) || 0;
      if (t.type === 'income') {
        income += val;
      } else if (t.type === 'expense') {
        expense += val;
        if (val > highest.amount) {
          highest = { amount: val, description: t.description };
        }
      }
    });

    const savingsPct = income > 0 ? Math.max(0, Math.round(((income - expense) / income) * 100)) : 0;
    const now = new Date();
    const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
    const dailyAvg = expense > 0 ? (expense / daysInMonth) : 0;

    const elSavings = document.getElementById('report-savings-rate');
    const elDaily = document.getElementById('report-daily-average');
    const elHigh = document.getElementById('report-highest-expense');
    const elHighName = document.getElementById('report-highest-expense-name');

    if (elSavings) elSavings.textContent = `${savingsPct}%`;
    if (elDaily) elDaily.textContent = this.formatDisplayValue(dailyAvg);
    if (elHigh) elHigh.textContent = this.formatDisplayValue(highest.amount);
    if (elHighName) elHighName.textContent = highest.description;
  },

  openTransactionModal(editId = null) {
    const modal = document.getElementById('modal-transaction');
    const form = document.getElementById('form-transaction');
    const title = document.getElementById('modal-transaction-title');
    const repeatWrapper = document.getElementById('tx-repeat-wrapper');
    if (!modal || !form) return;

    form.reset();
    this.state.editingId = editId;

    if (repeatWrapper) {
      repeatWrapper.classList.toggle('hidden', !!editId);
      const repeatCheckbox = document.getElementById('tx-repeat-checkbox');
      if (repeatCheckbox) repeatCheckbox.checked = false;
      document.getElementById('tx-repeat-fields')?.classList.add('hidden');
      const fixedRadio = document.querySelector('input[name="tx-repeat-mode"][value="fixed"]');
      if (fixedRadio) fixedRadio.checked = true;
      const countInput = document.getElementById('tx-repeat-count');
      if (countInput) countInput.value = '12';
    }

    if (editId) {
      const tx = this.state.transactions.find(t => t.id === editId);
      if (!tx) return;

      if (title) title.textContent = 'Editar Lançamento';
      document.getElementById('tx-id').value = tx.id;
      document.getElementById('tx-description').value = tx.description;
      document.getElementById('tx-amount').value = tx.amount;
      document.getElementById('tx-type').value = tx.type;
      document.getElementById('tx-category').value = tx.category;
      document.getElementById('tx-account').value = tx.account || 'Conta Corrente';
      document.getElementById('tx-date').value = tx.date;
      document.getElementById('tx-status').value = tx.status;
    } else {
      if (title) title.textContent = 'Novo Lançamento';
      document.getElementById('tx-id').value = '';
      const today = new Date().toISOString().split('T')[0];
      const defaultDate = today.startsWith(this.state.filters.month) ? today : `${this.state.filters.month}-01`;
      document.getElementById('tx-date').value = defaultDate;
      document.getElementById('tx-type').value = 'expense';
      document.getElementById('tx-account').value = 'Conta Corrente';
      document.getElementById('tx-status').value = 'paid';
    }

    modal.classList.remove('hidden');
    modal.classList.add('flex');
    setTimeout(() => document.getElementById('tx-description').focus(), 80);
  },

  openTransactionModalWithType(type) {
    this.openTransactionModal();
    const typeSelect = document.getElementById('tx-type');
    if (typeSelect) typeSelect.value = type;
  },

  closeTransactionModal() {
    const modal = document.getElementById('modal-transaction');
    if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }
    this.state.editingId = null;
  },

  updateRepeatSummary() {
    const isRepeat = document.getElementById('tx-repeat-checkbox')?.checked;
    if (!isRepeat) return;

    const mode = document.querySelector('input[name="tx-repeat-mode"]:checked')?.value || 'fixed';
    const countInput = document.getElementById('tx-repeat-count');
    let count = parseInt(countInput?.value || '12', 10);
    if (isNaN(count) || count < 2) count = 2;
    if (count > 60) count = 60;

    const amountInput = document.getElementById('tx-amount');
    const amount = parseFloat(amountInput?.value) || 0;

    const iconEl = document.getElementById('tx-repeat-summary-icon');
    const textEl = document.getElementById('tx-repeat-summary-text');

    if (!textEl) return;

    if (mode === 'fixed') {
      if (iconEl) iconEl.textContent = '🔄';
      const formattedAmount = this.formatDisplayValue(amount);
      if (amount === 0) {
        textEl.innerHTML = `Lançamento fixo de <strong>R$ 0,00 (Variável)</strong> todo mês durante <strong>${count} meses</strong>.<br><span class="text-[10px] opacity-80">Ideal para contas como água, energia e mercado (você preenche o valor exato no mês em que a fatura chegar).</span>`;
      } else {
        const totalAmount = this.formatDisplayValue(amount * count);
        textEl.innerHTML = `Lançamento fixo de <strong>${formattedAmount}</strong> todo mês durante <strong>${count} meses</strong> (Total acumulado: ${totalAmount}).`;
      }
    } else {
      if (iconEl) iconEl.textContent = '💳';
      const partAmount = count > 0 ? Math.round((amount / count) * 100) / 100 : 0;
      const formattedPart = this.formatDisplayValue(partAmount);
      textEl.innerHTML = `Dividido em <strong>${count} parcelas de ${formattedPart}</strong> cada (de 1/${count} até ${count}/${count}).`;
    }
  },

  handleTransactionSubmit(e) {
    e.preventDefault();

    const id = document.getElementById('tx-id').value;
    const description = document.getElementById('tx-description').value.trim();
    const amount = parseFloat(document.getElementById('tx-amount').value);
    const type = document.getElementById('tx-type').value;
    const category = document.getElementById('tx-category').value;
    const account = document.getElementById('tx-account').value;
    const date = document.getElementById('tx-date').value;
    const status = document.getElementById('tx-status').value;

    const isRepeat = document.getElementById('tx-repeat-checkbox')?.checked;
    const repeatMode = document.querySelector('input[name="tx-repeat-mode"]:checked')?.value || 'fixed';
    let repeatCount = parseInt(document.getElementById('tx-repeat-count')?.value || '12', 10);
    if (isNaN(repeatCount) || repeatCount < 2) repeatCount = 2;
    if (repeatCount > 60) repeatCount = 60;

    if (!description || isNaN(amount) || amount < 0 || !date) {
      Toast.show('Preencha os campos obrigatórios corretamente.', 'warning');
      return;
    }

    if (this.state.editingId) {
      const index = this.state.transactions.findIndex(t => t.id === this.state.editingId);
      if (index !== -1) {
        this.state.transactions[index] = {
          ...this.state.transactions[index],
          description,
          amount,
          type,
          category,
          account,
          date,
          status,
          updatedAt: Date.now()
        };
        Toast.show('Lançamento atualizado!', 'success');
      }
    } else {
      if (isRepeat && repeatCount > 1) {
        const now = Date.now();
        if (repeatMode === 'installment') {
          // Parcelamento (divide o valor total)
          const partAmount = Math.round((amount / repeatCount) * 100) / 100;
          for (let i = 0; i < repeatCount; i++) {
            const installmentDate = Utils.addMonths(date, i);
            const newTx = {
              id: Utils.generateId(),
              description: `${description} (${i + 1}/${repeatCount})`,
              amount: partAmount,
              type,
              category,
              account,
              date: installmentDate,
              status: i === 0 ? status : 'pending',
              updatedAt: now + i
            };
            this.state.transactions.unshift(newTx);
          }
          Toast.show(`${repeatCount} parcelas cadastradas com sucesso!`, 'success');
        } else {
          // Conta Fixa Recorrente (mesmo valor todo mês)
          for (let i = 0; i < repeatCount; i++) {
            const repeatDate = Utils.addMonths(date, i);
            const newTx = {
              id: Utils.generateId(),
              description,
              amount,
              type,
              category,
              account,
              date: repeatDate,
              status: i === 0 ? status : 'pending',
              updatedAt: now + i
            };
            this.state.transactions.unshift(newTx);
          }
          Toast.show(amount === 0 ? `Conta variável criada para os próximos ${repeatCount} meses!` : `Conta fixa repetida para os próximos ${repeatCount} meses!`, 'success');
        }
      } else {
        const newTx = {
          id: Utils.generateId(),
          description,
          amount,
          type,
          category,
          account,
          date,
          status,
          updatedAt: Date.now()
        };
        this.state.transactions.unshift(newTx);
        Toast.show('Lançamento cadastrado!', 'success');
      }

      const txMonth = date.substring(0, 7);
      if (txMonth !== this.state.filters.month) {
        this.state.filters.month = txMonth;
        this.updateMonthSelector();
      }
    }

    this.saveAndSync();
    this.closeTransactionModal();
  },

  openEditModal(id) {
    this.openTransactionModal(id);
  },

  openDeleteModal(id) {
    const tx = this.state.transactions.find(t => t.id === id);
    if (!tx) return;

    this.state.deletingId = id;
    const modal = document.getElementById('modal-delete');
    const descEl = document.getElementById('delete-modal-description');
    const valEl = document.getElementById('delete-modal-amount');

    if (descEl) descEl.textContent = tx.description;
    if (valEl) valEl.textContent = Utils.formatCurrency(tx.amount);

    if (modal) {
      modal.classList.remove('hidden');
      modal.classList.add('flex');
    }
  },

  closeDeleteModal() {
    const modal = document.getElementById('modal-delete');
    if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }
    this.state.deletingId = null;
  },

  executeDelete() {
    if (!this.state.deletingId) return;

    this.markDeleted([this.state.deletingId]);
    this.state.transactions = this.state.transactions.filter(t => t.id !== this.state.deletingId);
    this.saveAndSync();
    this.closeDeleteModal();
    Toast.show('Lançamento excluído.', 'info');
  },

  toggleStatus(id) {
    const tx = this.state.transactions.find(t => t.id === id);
    if (!tx) return;

    if (tx.status === 'pending') {
      if (Number(tx.amount) === 0) {
        const input = prompt(`A conta "${tx.description}" está com valor R$ 0,00 (variável).\nInforme o valor pago (ex: 85,50):`);
        if (input === null) return; // cancelado
        const parsed = parseFloat(input.replace(',', '.'));
        if (isNaN(parsed) || parsed < 0) {
          Toast.show('Valor inválido.', 'warning');
          return;
        }
        tx.amount = parsed;
      }
      tx.status = 'paid';
    } else {
      tx.status = 'pending';
    }

    tx.updatedAt = Date.now();
    this.saveAndSync();
    Toast.show(`Status: ${tx.status === 'paid' ? 'Pago' : 'Pendente'}`, 'info', 1800);
  },

  clearFilters() {
    this.state.filters.type = 'all';
    this.state.filters.category = 'all';
    this.state.filters.status = 'all';
    this.state.filters.search = '';

    const filterCategory = document.getElementById('filter-category');
    const filterStatus = document.getElementById('filter-status');
    const filterSearch = document.getElementById('filter-search');

    if (filterCategory) filterCategory.value = 'all';
    if (filterStatus) filterStatus.value = 'all';
    if (filterSearch) filterSearch.value = '';

    this.setFilterType('all');
    Toast.show('Filtros limpos', 'info', 1500);
  },

  saveAndSync() {
    StorageService.saveData(this.getPersistPayload());
    this.render();
    if (SyncService.isEnabled()) {
      SyncService.schedule(true); // Envio IMEDIATO à nuvem após cada modificação
    }
  },

  // Orçamentos Modal
  openBudgetModal() {
    const modal = document.getElementById('modal-budget');
    if (modal) {
      modal.classList.remove('hidden');
      modal.classList.add('flex');
    }
  },

  openBudgetModalFor(categoryName, currentLimit) {
    this.openBudgetModal();
    const catSelect = document.getElementById('budget-category');
    const limitInput = document.getElementById('budget-limit');
    if (catSelect) catSelect.value = categoryName;
    if (limitInput) limitInput.value = currentLimit > 0 ? currentLimit : '';
  },

  closeBudgetModal() {
    const modal = document.getElementById('modal-budget');
    if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }
  },

  handleBudgetSubmit(e) {
    e.preventDefault();
    const category = document.getElementById('budget-category').value;
    const limit = parseFloat(document.getElementById('budget-limit').value);

    if (!category || isNaN(limit) || limit < 0) {
      Toast.show('Informe um valor de limite válido.', 'warning');
      return;
    }

    if (!this.state.settings.budgets) {
      this.state.settings.budgets = {};
    }

    this.state.settings.budgets[category] = limit;
    this.saveAndSync();
    this.closeBudgetModal();
    Toast.show(`Limite de ${category} salvo!`, 'success');
  },

  // Backup & Importação
  exportJSON() {
    const payload = {
      app: 'Controle Financeiro Pessoal',
      version: SCHEMA_VERSION,
      exportedAt: new Date().toISOString(),
      transactionsCount: this.state.transactions.length,
      transactions: this.state.transactions,
      settings: this.state.settings
    };

    const jsonStr = JSON.stringify(payload, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const today = new Date().toISOString().split('T')[0];

    a.href = url;
    a.download = `fincontrol-backup-${today}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    Toast.show('Backup JSON exportado!', 'success');
  },

  exportCSV() {
    if (this.state.transactions.length === 0) {
      Toast.show('Não há lançamentos para exportar.', 'warning');
      return;
    }

    const header = ['ID', 'Data', 'Tipo', 'Categoria', 'Conta', 'Descrição', 'Valor', 'Status'];
    const rows = this.state.transactions.map(t => [
      `"${t.id}"`,
      `"${Utils.formatDateBR(t.date)}"`,
      `"${t.type === 'income' ? 'Receita' : 'Despesa'}"`,
      `"${(t.category || '').replace(/"/g, '""')}"`,
      `"${(t.account || '').replace(/"/g, '""')}"`,
      `"${(t.description || '').replace(/"/g, '""')}"`,
      `"${Number(t.amount || 0).toFixed(2).replace('.', ',')}"`,
      `"${t.status === 'paid' ? 'Pago' : 'Pendente'}"`
    ]);

    const csvContent = '\uFEFF' + [header.join(';'), ...rows.map(r => r.join(';'))].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const today = new Date().toISOString().split('T')[0];

    a.href = url;
    a.download = `fincontrol-${today}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    Toast.show('Planilha CSV exportada!', 'success');
  },

  openImportModal() {
    const modal = document.getElementById('modal-import');
    const fileInput = document.getElementById('import-file-input');
    if (fileInput) fileInput.value = '';
    if (modal) {
      modal.classList.remove('hidden');
      modal.classList.add('flex');
    }
  },

  closeImportModal() {
    const modal = document.getElementById('modal-import');
    if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }
  },

  handleImportSubmit() {
    const fileInput = document.getElementById('import-file-input');
    const mode = document.querySelector('input[name="import-mode"]:checked')?.value || 'replace';

    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
      Toast.show('Selecione um arquivo .json para importar.', 'warning');
      return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = (e) => {
      try {
        const json = JSON.parse(e.target.result);
        const importedList = Array.isArray(json.transactions) ? json.transactions : (Array.isArray(json) ? json : null);

        if (!importedList) {
          throw new Error('Formato inválido.');
        }

        const validTxs = [];
        for (const item of importedList) {
          if (!item.description || isNaN(Number(item.amount))) continue;
          validTxs.push({
            id: item.id || Utils.generateId(),
            description: String(item.description),
            amount: Math.abs(Number(item.amount)),
            type: item.type === 'income' ? 'income' : 'expense',
            category: item.category || 'Outros',
            account: item.account || 'Conta Corrente',
            date: item.date || new Date().toISOString().split('T')[0],
            status: item.status === 'pending' ? 'pending' : 'paid',
            updatedAt: Date.now()
          });
        }

        if (validTxs.length === 0) {
          Toast.show('Nenhuma transação válida encontrada.', 'error');
          return;
        }

        if (mode === 'replace') {
          const importedIds = new Set(validTxs.map(t => t.id));
          this.markDeleted(this.state.transactions.map(t => t.id).filter(id => !importedIds.has(id)));
          this.state.transactions = validTxs;
        } else {
          const existingIds = new Set(this.state.transactions.map(t => t.id));
          const newEntries = validTxs.map(t => {
            if (existingIds.has(t.id)) {
              return { ...t, id: Utils.generateId() };
            }
            return t;
          });
          this.state.transactions = [...newEntries, ...this.state.transactions];
        }

        if (json.settings && json.settings.budgets) {
          this.state.settings.budgets = { ...this.state.settings.budgets, ...json.settings.budgets };
        }

        this.saveAndSync();
        this.closeImportModal();
        Toast.show(`${validTxs.length} transações importadas com sucesso!`, 'success');
      } catch (err) {
        console.error('Falha na importação:', err);
        Toast.show('Arquivo inválido: ' + err.message, 'error');
      }
    };

    reader.readAsText(file);
  },

  // Alteração de Senha
  openPasswordModal() {
    const modal = document.getElementById('modal-password');
    const form = document.getElementById('form-password');
    if (form) form.reset();
    if (modal) {
      modal.classList.remove('hidden');
      modal.classList.add('flex');
      setTimeout(() => document.getElementById('pwd-current').focus(), 50);
    }
  },

  closePasswordModal() {
    const modal = document.getElementById('modal-password');
    if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }
  },

  async handleChangePassword(e) {
    e.preventDefault();
    const current = document.getElementById('pwd-current').value;
    const newPwd = document.getElementById('pwd-new').value;
    const confirmPwd = document.getElementById('pwd-confirm').value;
    const btn = document.getElementById('btn-save-password');

    if (newPwd.length < MIN_PASSWORD_LENGTH) {
      Toast.show(`A nova senha deve ter no mínimo ${MIN_PASSWORD_LENGTH} caracteres.`, 'warning');
      return;
    }
    if (newPwd !== confirmPwd) {
      Toast.show('A confirmação não coincide com a nova senha.', 'warning');
      return;
    }

    btn.disabled = true;
    try {
      await StorageService.flush();
      const valid = await CryptoVault.verifyPassword(current);
      if (!valid) {
        Toast.show('Senha atual incorreta.', 'error');
        return;
      }
      await CryptoVault.changePassword(newPwd, {
        ...this.getPersistPayload(),
        updatedAt: new Date().toISOString()
      });
      AuthUI.savePassword(newPwd);
      SyncService.pushOnly();
      this.closePasswordModal();
      Toast.show(SyncService.isEnabled()
        ? 'Senha alterada! Use a nova senha nos outros aparelhos.'
        : 'Senha alterada com sucesso!', 'success', 5000);
    } catch (err) {
      console.error(err);
      Toast.show('Erro ao alterar senha: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  },

  loadSampleData() {
    const now = Date.now();
    const samples = SampleData.generate(this.state.filters.month).map(t => ({ ...t, updatedAt: now }));
    this.markDeleted(this.state.transactions.map(t => t.id));
    this.state.transactions = samples;
    this.saveAndSync();
    Toast.show('Dados de exemplo carregados!', 'success');
  },

  confirmClearAll() {
    if (confirm('Tem certeza de que deseja apagar TODOS os lançamentos?')) {
      this.markDeleted(this.state.transactions.map(t => t.id));
      this.state.transactions = [];
      this.saveAndSync();
      Toast.show('Todos os dados foram apagados.', 'info');
    }
  },

  // Sincronização
  openSyncModal() {
    const modal = document.getElementById('modal-sync');
    const enabled = SyncService.isEnabled();
    document.getElementById('sync-setup').classList.toggle('hidden', enabled);
    document.getElementById('sync-connected').classList.toggle('hidden', !enabled);
    
    // Recupera token salvo anteriormente de localStorage ou cookies
    let savedToken = localStorage.getItem('fincontrol_saved_gh_token') || '';
    if (!savedToken) {
      const match = document.cookie.match(/(?:^|;\s*)fincontrol_gh_token=([^;]+)/);
      if (match) savedToken = decodeURIComponent(match[1]);
    }
    document.getElementById('sync-token').value = savedToken;
    document.getElementById('sync-password').value = '';
    document.getElementById('sync-overwrite').checked = false;
    document.getElementById('sync-error').classList.add('hidden');

    if (enabled) {
      const link = document.getElementById('sync-gist-link');
      link.href = `https://gist.github.com/${encodeURIComponent(SyncService.config.gistId)}`;
    }
    SyncService.setStatus(SyncService.status, SyncService.statusDetail);

    modal.classList.remove('hidden');
    modal.classList.add('flex');
  },

  closeSyncModal() {
    const modal = document.getElementById('modal-sync');
    if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }
  },

  async handleSyncConnect() {
    const token = document.getElementById('sync-token').value.trim();
    const password = document.getElementById('sync-password').value;
    const overwrite = document.getElementById('sync-overwrite').checked;
    const errorEl = document.getElementById('sync-error');
    const btn = document.getElementById('btn-sync-connect');

    errorEl.classList.add('hidden');
    if (!token || !password) {
      errorEl.textContent = 'Informe o token do GitHub e a senha.';
      errorEl.classList.remove('hidden');
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Conectando...';
    SyncService.setStatus('syncing');
    try {
      await SyncService.connect(token, password, overwrite);
      
      // Salva token em localStorage e cookies para permanência no dispositivo
      try {
        localStorage.setItem('fincontrol_saved_gh_token', token);
        document.cookie = `fincontrol_gh_token=${encodeURIComponent(token)}; max-age=31536000; path=/; SameSite=Strict`;
      } catch (e) {}

      this.closeSyncModal();
      Toast.show('Sincronização ativada! Cada modificação será salva na nuvem automaticamente.', 'success', 5000);
    } catch (err) {
      console.error(err);
      SyncService.setStatus(SyncService.isEnabled() ? 'error' : 'off', err.message);
      errorEl.textContent = err.message;
      errorEl.classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Conectar e sincronizar';
    }
  },

  async handleSyncDisconnect() {
    if (!confirm('Desativar a sincronização neste aparelho?')) return;
    try {
      localStorage.removeItem('fincontrol_saved_gh_token');
      document.cookie = 'fincontrol_gh_token=; max-age=0; path=/';
    } catch (e) {}
    await SyncService.disconnect();
    this.closeSyncModal();
    Toast.show('Sincronização desativada neste aparelho.', 'info');
  }
};

// Inicialização
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
