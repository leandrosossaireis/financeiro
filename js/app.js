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

  // Subtrair ou adicionar meses a uma string "YYYY-MM"
  addMonths(yearMonthStr, count) {
    const [y, m] = yearMonthStr.split('-').map(Number);
    const d = new Date(y, m - 1 + count, 1);
    const ny = d.getFullYear();
    const nm = String(d.getMonth() + 1).padStart(2, '0');
    return `${ny}-${nm}`;
  }
};

/**
 * Camada de Persistência (Storage Service)
 * Suporta LocalStorage com tratamento de erros e validação de schema
 */
const StorageService = {
  // Fila de gravação: garante que escritas criptografadas (assíncronas) ocorram em ordem
  _queue: Promise.resolve(),

  // Normaliza/valida a estrutura do banco de dados
  normalize(parsed) {
    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.transactions)) {
      console.warn('Estrutura de dados inválida. Inicializando padrão.');
      return this.getDefaultData();
    }
    return {
      version: parsed.version || SCHEMA_VERSION,
      updatedAt: parsed.updatedAt || new Date().toISOString(),
      transactions: parsed.transactions
    };
  },

  // Lê dados antigos não criptografados (versões anteriores do app) para migração
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

  // Salva os dados criptografados no cofre (assíncrono, enfileirado)
  saveData(data) {
    const payload = {
      version: SCHEMA_VERSION,
      updatedAt: new Date().toISOString(),
      transactions: Array.isArray(data.transactions) ? data.transactions : []
    };
    this._queue = this._queue
      .then(() => CryptoVault.encryptAndStore(payload))
      .catch(err => {
        console.error('Erro ao salvar dados criptografados (possível limite de cota):', err);
        Toast.show('Erro ao salvar os dados. Faça um backup em JSON.', 'error');
      });
    return this._queue;
  },

  // Aguarda todas as gravações pendentes
  flush() {
    return this._queue;
  },

  getDefaultData() {
    return {
      version: SCHEMA_VERSION,
      updatedAt: new Date().toISOString(),
      transactions: []
    };
  },

  // Remove TODOS os dados (cofre + legado)
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
 * - Chave derivada da senha via PBKDF2-SHA256 (310.000 iterações + salt aleatório)
 * - Dados cifrados com AES-256-GCM (confidencialidade + integridade)
 * - A senha e a chave NUNCA são gravadas; a chave existe apenas em memória enquanto desbloqueado
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

  // Cria um novo cofre (primeiro acesso ou troca de senha)
  async create(password, data) {
    this.salt = crypto.getRandomValues(new Uint8Array(16));
    this.iterations = PBKDF2_ITERATIONS;
    this.key = await this.deriveKey(password, this.salt, this.iterations);
    await this.encryptAndStore(data);
  },

  // Desbloqueia o cofre existente. Lança erro com code BAD_PASSWORD se a senha estiver errada.
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
    const iv = crypto.getRandomValues(new Uint8Array(12)); // IV único a cada gravação
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
 * Tela de Login / Criação de Senha e Bloqueio Automático
 */
const AuthUI = {
  mode: 'login', // 'setup' (primeiro acesso) | 'login'
  failedAttempts: 0,
  idleTimer: null,
  busy: false,

  el(id) {
    return document.getElementById(id);
  },

  init() {
    this.el('auth-form').addEventListener('submit', (e) => this.handleSubmit(e));
    this.el('auth-toggle-visibility').addEventListener('click', () => this.toggleVisibility());
    this.el('auth-forgot').addEventListener('click', () => this.handleForgot());

    // Mensagem pós-bloqueio (ex: inatividade)
    const reason = sessionStorage.getItem(LOCK_REASON_KEY);
    if (reason) {
      sessionStorage.removeItem(LOCK_REASON_KEY);
      const info = this.el('auth-info');
      info.textContent = reason;
      info.classList.remove('hidden');
    }

    if (!this.isCryptoAvailable()) return;

    this.mode = CryptoVault.hasVault() ? 'login' : 'setup';
    this.renderMode();
    this.show();
  },

  isCryptoAvailable() {
    if (CryptoVault.isSupported()) return true;
    this.showError('Seu navegador não suporta a criptografia necessária (Web Crypto API). Acesse pelo endereço HTTPS do GitHub Pages ou use um navegador atualizado.');
    this.el('auth-submit').disabled = true;
    this.show();
    return false;
  },

  renderMode() {
    const isSetup = this.mode === 'setup';
    this.el('auth-title').textContent = isSetup ? 'Crie sua senha de acesso' : 'Bem-vindo de volta';
    this.el('auth-subtitle').textContent = isSetup
      ? 'Seus dados financeiros serão criptografados com esta senha.'
      : 'Digite sua senha para desbloquear seus dados.';
    this.el('auth-submit-label').textContent = isSetup ? 'Criar senha e entrar' : 'Desbloquear';
    this.el('auth-confirm-wrapper').classList.toggle('hidden', !isSetup);
    this.el('auth-setup-notice').classList.toggle('hidden', !isSetup);
    this.el('auth-forgot').classList.toggle('hidden', isSetup);
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
    this.el('auth-toggle-visibility').setAttribute('aria-label', show ? 'Ocultar senha' : 'Mostrar senha');
    this.el('auth-eye-open').classList.toggle('hidden', show);
    this.el('auth-eye-closed').classList.toggle('hidden', !show);
  },

  async handleSubmit(e) {
    e.preventDefault();
    if (this.busy) return;
    this.clearError();

    const pwd = this.el('auth-password').value;

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
        // Migra dados antigos (não criptografados), se existirem
        const legacy = StorageService.readLegacyPlain();
        const initial = legacy || StorageService.getDefaultData();
        await CryptoVault.create(pwd, initial);
        StorageService.removeLegacyPlain();
        this.onSuccess(initial, legacy
          ? 'Senha criada! Seus dados existentes agora estão criptografados.'
          : 'Senha criada! Seus dados serão salvos criptografados.');
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
      this.onSuccess(data);
    } catch (err) {
      this.failedAttempts++;
      // Atraso progressivo contra tentativas repetidas
      const delay = Math.min(250 * Math.pow(2, this.failedAttempts), 8000);
      await new Promise(r => setTimeout(r, delay));
      this.showError(err.code === 'BAD_PASSWORD'
        ? `Senha incorreta. (tentativa ${this.failedAttempts})`
        : 'Não foi possível abrir os dados: ' + err.message);
      this.el('auth-password').select();
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

  // Bloqueia: aguarda gravações, descarta a chave e recarrega a página (limpa a memória)
  async lock(reason) {
    try {
      await StorageService.flush();
    } finally {
      CryptoVault.lock();
      if (reason) sessionStorage.setItem(LOCK_REASON_KEY, reason);
      location.reload();
    }
  },

  startIdleWatch() {
    const reset = () => {
      clearTimeout(this.idleTimer);
      this.idleTimer = setTimeout(() => {
        this.lock(`Sessão bloqueada automaticamente após ${AUTO_LOCK_MINUTES} minutos de inatividade.`);
      }, AUTO_LOCK_MINUTES * 60 * 1000);
    };
    ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'].forEach(ev => {
      window.addEventListener(ev, reset, { passive: true });
    });
    reset();
  },

  handleForgot() {
    const ok1 = confirm(
      'Por segurança, NÃO existe recuperação de senha: os dados são criptografados com ela.\n\n' +
      'A única opção é APAGAR todos os dados deste navegador e começar de novo ' +
      '(você poderá importar um backup JSON depois).\n\nDeseja continuar?'
    );
    if (!ok1) return;
    const ok2 = confirm('Confirma a exclusão DEFINITIVA de todos os lançamentos deste navegador?');
    if (!ok2) return;

    StorageService.wipeAll();
    sessionStorage.setItem(LOCK_REASON_KEY, 'Dados apagados. Crie uma nova senha para começar.');
    location.reload();
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

    // Listener para preferência do sistema caso o usuário não tenha fixado
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

    // Apenas despesas do período
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

    // Agrupar por categoria
    const categoryTotals = {};
    expenses.forEach(t => {
      const cat = t.category || 'Outros';
      categoryTotals[cat] = (categoryTotals[cat] || 0) + Number(t.amount);
    });

    const labels = Object.keys(categoryTotals);
    const data = Object.values(categoryTotals);

    // Mapear cores
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
              font: { family: 'Inter', size: 12 },
              padding: 14,
              usePointStyle: true,
              pointStyle: 'circle'
            }
          },
          tooltip: {
            backgroundColor: colors.tooltipBg,
            titleColor: colors.tooltipText,
            bodyColor: colors.tooltipText,
            padding: 10,
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
        cutout: '68%'
      }
    });
  },

  renderHistoryChart(allTransactions, currentMonthStr) {
    const canvas = document.getElementById('chartHistory');
    if (!canvas) return;

    // Calcular os últimos 6 meses a partir do mês selecionado
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
            borderRadius: 6,
            maxBarThickness: 28
          },
          {
            label: 'Despesas',
            data: expenseData,
            backgroundColor: '#f43f5e',
            borderRadius: 6,
            maxBarThickness: 28
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: 'index',
          intersect: false
        },
        plugins: {
          legend: {
            position: 'top',
            align: 'end',
            labels: {
              color: colors.text,
              font: { family: 'Inter', size: 12 },
              usePointStyle: true,
              pointStyle: 'circle'
            }
          },
          tooltip: {
            backgroundColor: colors.tooltipBg,
            titleColor: colors.tooltipText,
            bodyColor: colors.tooltipText,
            padding: 10,
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
            ticks: {
              color: colors.text,
              font: { family: 'Inter', size: 11 }
            }
          },
          y: {
            grid: { color: colors.grid, drawBorder: false },
            ticks: {
              color: colors.text,
              font: { family: 'Inter', size: 11 },
              callback: function(val) {
                if (val >= 1000) {
                  return 'R$ ' + (val / 1000).toFixed(0) + 'k';
                }
                return 'R$ ' + val;
              }
            }
          }
        }
      }
    });
  },

  updateThemeColors() {
    // Re-renderizar gráficos para adotar as cores do novo tema
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
    toast.className = `toast-anim flex items-center gap-3 px-4 py-3 rounded-xl shadow-lg border text-sm font-medium text-white transition-all transform pointer-events-auto`;

    let bgClass = 'bg-slate-900 dark:bg-slate-800 border-slate-700';
    let iconSvg = '';

    if (type === 'success') {
      bgClass = 'bg-emerald-600 border-emerald-500';
      iconSvg = `<svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`;
    } else if (type === 'error') {
      bgClass = 'bg-rose-600 border-rose-500';
      iconSvg = `<svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>`;
    } else if (type === 'warning') {
      bgClass = 'bg-amber-600 border-amber-500';
      iconSvg = `<svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`;
    } else {
      bgClass = 'bg-blue-600 border-blue-500';
      iconSvg = `<svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;
    }

    toast.className += ` ${bgClass}`;
    toast.innerHTML = `
      ${iconSvg}
      <span class="flex-1">${Utils.escapeHtml(message)}</span>
      <button type="button" class="text-white/80 hover:text-white ml-2 p-1 focus:outline-none" onclick="this.parentElement.remove()">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-10px)';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }
};

/**
 * Dados de Exemplo para Teste Imediato (Sample Data)
 */
const SampleData = {
  generate(baseMonthStr) {
    const now = new Date();
    const currentYear = now.getFullYear();
    const currentMonthNum = String(now.getMonth() + 1).padStart(2, '0');
    const baseMonth = baseMonthStr || `${currentYear}-${currentMonthNum}`;

    const prevMonth = Utils.addMonths(baseMonth, -1);
    const prevMonth2 = Utils.addMonths(baseMonth, -2);
    const prevMonth3 = Utils.addMonths(baseMonth, -3);

    return [
      // Mês Atual
      { id: Utils.generateId(), description: 'Salário Mensal', amount: 6500.00, type: 'income', category: 'Salário', date: `${baseMonth}-05`, status: 'paid' },
      { id: Utils.generateId(), description: 'Projeto Freelance Website', amount: 1850.00, type: 'income', category: 'Freelance', date: `${baseMonth}-12`, status: 'paid' },
      { id: Utils.generateId(), description: 'Dividendos de Ações', amount: 240.50, type: 'income', category: 'Investimentos', date: `${baseMonth}-15`, status: 'paid' },
      { id: Utils.generateId(), description: 'Consultoria Remota', amount: 1200.00, type: 'income', category: 'Freelance', date: `${baseMonth}-26`, status: 'pending' },

      { id: Utils.generateId(), description: 'Aluguel do Apartamento', amount: 2100.00, type: 'expense', category: 'Moradia', date: `${baseMonth}-08`, status: 'paid' },
      { id: Utils.generateId(), description: 'Condomínio e IPTU', amount: 620.00, type: 'expense', category: 'Moradia', date: `${baseMonth}-10`, status: 'paid' },
      { id: Utils.generateId(), description: 'Compras de Supermercado', amount: 840.30, type: 'expense', category: 'Alimentação', date: `${baseMonth}-07`, status: 'paid' },
      { id: Utils.generateId(), description: 'Jantar Restaurante Italiano', amount: 180.00, type: 'expense', category: 'Alimentação', date: `${baseMonth}-14`, status: 'paid' },
      { id: Utils.generateId(), description: 'Combustível Posto Ipiranga', amount: 250.00, type: 'expense', category: 'Transporte', date: `${baseMonth}-11`, status: 'paid' },
      { id: Utils.generateId(), description: 'Uber e Estacionamento', amount: 95.40, type: 'expense', category: 'Transporte', date: `${baseMonth}-16`, status: 'paid' },
      { id: Utils.generateId(), description: 'Farmácia e Vitaminas', amount: 145.90, type: 'expense', category: 'Saúde', date: `${baseMonth}-18`, status: 'paid' },
      { id: Utils.generateId(), description: 'Assinaturas de Streaming', amount: 89.90, type: 'expense', category: 'Lazer', date: `${baseMonth}-20`, status: 'paid' },
      { id: Utils.generateId(), description: 'Curso de Especialização', amount: 350.00, type: 'expense', category: 'Educação', date: `${baseMonth}-22`, status: 'pending' },
      { id: Utils.generateId(), description: 'Manutenção Veicular', amount: 480.00, type: 'expense', category: 'Transporte', date: `${baseMonth}-27`, status: 'pending' },

      // Mês Anterior (-1)
      { id: Utils.generateId(), description: 'Salário Mensal', amount: 6500.00, type: 'income', category: 'Salário', date: `${prevMonth}-05`, status: 'paid' },
      { id: Utils.generateId(), description: 'Freelance Design', amount: 1400.00, type: 'income', category: 'Freelance', date: `${prevMonth}-15`, status: 'paid' },
      { id: Utils.generateId(), description: 'Aluguel do Apartamento', amount: 2100.00, type: 'expense', category: 'Moradia', date: `${prevMonth}-08`, status: 'paid' },
      { id: Utils.generateId(), description: 'Supermercado Mês', amount: 1120.00, type: 'expense', category: 'Alimentação', date: `${prevMonth}-12`, status: 'paid' },
      { id: Utils.generateId(), description: 'Manutenção Elétrica', amount: 340.00, type: 'expense', category: 'Moradia', date: `${prevMonth}-18`, status: 'paid' },

      // 2 Meses Atrás (-2)
      { id: Utils.generateId(), description: 'Salário Mensal', amount: 6500.00, type: 'income', category: 'Salário', date: `${prevMonth2}-05`, status: 'paid' },
      { id: Utils.generateId(), description: 'Aluguel do Apartamento', amount: 2100.00, type: 'expense', category: 'Moradia', date: `${prevMonth2}-08`, status: 'paid' },
      { id: Utils.generateId(), description: 'Supermercado', amount: 980.00, type: 'expense', category: 'Alimentação', date: `${prevMonth2}-11`, status: 'paid' },
      { id: Utils.generateId(), description: 'Revisão Carro', amount: 650.00, type: 'expense', category: 'Transporte', date: `${prevMonth2}-22`, status: 'paid' },

      // 3 Meses Atrás (-3)
      { id: Utils.generateId(), description: 'Salário Mensal', amount: 6500.00, type: 'income', category: 'Salário', date: `${prevMonth3}-05`, status: 'paid' },
      { id: Utils.generateId(), description: 'Bônus Performance', amount: 2000.00, type: 'income', category: 'Salário', date: `${prevMonth3}-10`, status: 'paid' },
      { id: Utils.generateId(), description: 'Aluguel do Apartamento', amount: 2100.00, type: 'expense', category: 'Moradia', date: `${prevMonth3}-08`, status: 'paid' },
      { id: Utils.generateId(), description: 'Viagem de Fim de Semana', amount: 1450.00, type: 'expense', category: 'Lazer', date: `${prevMonth3}-18`, status: 'paid' }
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
    editingId: null,
    deletingId: null
  },

  init() {
    ThemeManager.init();
    this.populateCategorySelects();
    this.setupEventListeners();

    // Nenhum dado é carregado antes da autenticação
    AuthUI.init();
  },

  // Chamado pelo AuthUI após desbloqueio bem-sucedido
  onUnlocked(data) {
    this.state.transactions = data.transactions || [];
    this.updateMonthSelector();
    this.render();

    if (this.state.transactions.length === 0) {
      setTimeout(() => {
        Toast.show('Bem-vindo! Clique em "Dados de Exemplo" para explorar a interface.', 'info', 5000);
      }, 700);
    }
  },

  setupEventListeners() {
    // Toggle de tema
    const btnTheme = document.getElementById('btn-theme-toggle');
    if (btnTheme) {
      btnTheme.addEventListener('click', () => {
        ThemeManager.toggle();
        ChartService.updateThemeColors();
      });
    }

    // Modal de Transação (Abrir / Fechar)
    const btnNewTransaction = document.getElementById('btn-new-transaction');
    if (btnNewTransaction) {
      btnNewTransaction.addEventListener('click', () => this.openTransactionModal());
    }

    const btnCloseModal = document.getElementById('btn-close-modal');
    const btnCancelModal = document.getElementById('btn-cancel-modal');
    if (btnCloseModal) btnCloseModal.addEventListener('click', () => this.closeTransactionModal());
    if (btnCancelModal) btnCancelModal.addEventListener('click', () => this.closeTransactionModal());

    // Formulário de Transação (Submit)
    const formTx = document.getElementById('form-transaction');
    if (formTx) {
      formTx.addEventListener('submit', (e) => this.handleTransactionSubmit(e));
    }

    // Navegação de Mês
    const btnPrevMonth = document.getElementById('btn-prev-month');
    const btnNextMonth = document.getElementById('btn-next-month');
    const selectMonth = document.getElementById('filter-month');

    if (btnPrevMonth) {
      btnPrevMonth.addEventListener('click', () => {
        this.state.filters.month = Utils.addMonths(this.state.filters.month, -1);
        this.updateMonthSelector();
        this.render();
      });
    }

    if (btnNextMonth) {
      btnNextMonth.addEventListener('click', () => {
        this.state.filters.month = Utils.addMonths(this.state.filters.month, 1);
        this.updateMonthSelector();
        this.render();
      });
    }

    if (selectMonth) {
      selectMonth.addEventListener('change', (e) => {
        this.state.filters.month = e.target.value;
        this.updateMonthTitle();
        this.render();
      });
    }

    // Filtros
    const filterType = document.getElementById('filter-type');
    const filterCategory = document.getElementById('filter-category');
    const filterStatus = document.getElementById('filter-status');
    const filterSearch = document.getElementById('filter-search');
    const btnClearFilters = document.getElementById('btn-clear-filters');

    if (filterType) {
      filterType.addEventListener('change', (e) => {
        this.state.filters.type = e.target.value;
        this.render();
      });
    }

    if (filterCategory) {
      filterCategory.addEventListener('change', (e) => {
        this.state.filters.category = e.target.value;
        this.render();
      });
    }

    if (filterStatus) {
      filterStatus.addEventListener('change', (e) => {
        this.state.filters.status = e.target.value;
        this.render();
      });
    }

    if (filterSearch) {
      filterSearch.addEventListener('input', (e) => {
        this.state.filters.search = e.target.value.trim().toLowerCase();
        this.render();
      });
    }

    if (btnClearFilters) {
      btnClearFilters.addEventListener('click', () => this.clearFilters());
    }

    // Botões de Backup / Portabilidade
    const btnExportJson = document.getElementById('btn-export-json');
    const btnExportCsv = document.getElementById('btn-export-csv');
    const btnImportJson = document.getElementById('btn-import-json');
    const btnLoadSample = document.getElementById('btn-load-sample');
    const btnClearAll = document.getElementById('btn-clear-all');

    if (btnExportJson) btnExportJson.addEventListener('click', () => this.exportJSON());
    if (btnExportCsv) btnExportCsv.addEventListener('click', () => this.exportCSV());
    if (btnImportJson) btnImportJson.addEventListener('click', () => this.openImportModal());
    if (btnLoadSample) btnLoadSample.addEventListener('click', () => this.loadSampleData());
    if (btnClearAll) btnClearAll.addEventListener('click', () => this.confirmClearAll());

    // Segurança: bloquear sessão e alterar senha
    const btnLock = document.getElementById('btn-lock');
    const btnChangePassword = document.getElementById('btn-change-password');
    const formPassword = document.getElementById('form-password');
    const btnCancelPassword = document.getElementById('btn-cancel-password');

    if (btnLock) btnLock.addEventListener('click', () => AuthUI.lock('Sessão bloqueada.'));
    if (btnChangePassword) btnChangePassword.addEventListener('click', () => this.openPasswordModal());
    if (formPassword) formPassword.addEventListener('submit', (e) => this.handleChangePassword(e));
    if (btnCancelPassword) btnCancelPassword.addEventListener('click', () => this.closePasswordModal());

    // Modal de Confirmação de Exclusão
    const btnCancelDelete = document.getElementById('btn-cancel-delete');
    const btnConfirmDelete = document.getElementById('btn-confirm-delete');
    if (btnCancelDelete) btnCancelDelete.addEventListener('click', () => this.closeDeleteModal());
    if (btnConfirmDelete) btnConfirmDelete.addEventListener('click', () => this.executeDelete());

    // Modal de Importação
    const btnCloseImport = document.getElementById('btn-close-import');
    const btnCancelImport = document.getElementById('btn-cancel-import');
    const btnProcessImport = document.getElementById('btn-process-import');
    const importFileInput = document.getElementById('import-file-input');

    if (btnCloseImport) btnCloseImport.addEventListener('click', () => this.closeImportModal());
    if (btnCancelImport) btnCancelImport.addEventListener('click', () => this.closeImportModal());
    if (btnProcessImport) btnProcessImport.addEventListener('click', () => this.handleImportSubmit());

    // Fechar modais ao teclar Escape ou clicar no backdrop
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.closeTransactionModal();
        this.closeDeleteModal();
        this.closeImportModal();
        this.closePasswordModal();
      }
    });

    ['modal-transaction', 'modal-delete', 'modal-import', 'modal-password'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener('click', (e) => {
          if (e.target === el) {
            this.closeTransactionModal();
            this.closeDeleteModal();
            this.closeImportModal();
            this.closePasswordModal();
          }
        });
      }
    });
  },

  populateCategorySelects() {
    const selects = ['tx-category', 'filter-category'];
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

    // Gerar opções de meses: 12 meses antes e 6 meses depois do atual
    const currentM = Utils.getCurrentMonth();
    const options = [];

    for (let i = -12; i <= 6; i++) {
      const mStr = Utils.addMonths(currentM, i);
      options.push(mStr);
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

  getFilteredTransactions() {
    const { month, type, category, status, search } = this.state.filters;

    return this.state.transactions.filter(t => {
      // Filtro por mês (YYYY-MM)
      if (month && (!t.date || !t.date.startsWith(month))) {
        return false;
      }
      // Filtro por tipo
      if (type !== 'all' && t.type !== type) {
        return false;
      }
      // Filtro por categoria
      if (category !== 'all' && t.category !== category) {
        return false;
      }
      // Filtro por status
      if (status !== 'all' && t.status !== status) {
        return false;
      }
      // Busca textual por descrição
      if (search && !t.description.toLowerCase().includes(search)) {
        return false;
      }
      return true;
    }).sort((a, b) => new Date(b.date) - new Date(a.date));
  },

  render() {
    const filteredTxs = this.getFilteredTransactions();
    this.renderKPIs(filteredTxs);
    this.renderTable(filteredTxs);
    ChartService.renderCategoryChart(filteredTxs);
    ChartService.renderHistoryChart(this.state.transactions, this.state.filters.month);
  },

  renderKPIs(filteredTxs) {
    let incomePaid = 0;
    let incomePending = 0;
    let expensePaid = 0;
    let expensePending = 0;

    filteredTxs.forEach(t => {
      const val = Number(t.amount) || 0;
      if (t.type === 'income') {
        if (t.status === 'paid') {
          incomePaid += val;
        } else {
          incomePending += val;
        }
      } else if (t.type === 'expense') {
        if (t.status === 'paid') {
          expensePaid += val;
        } else {
          expensePending += val;
        }
      }
    });

    const totalIncome = incomePaid + incomePending;
    const totalExpense = expensePaid + expensePending;
    const currentBalance = incomePaid - expensePaid;
    const projectedBalance = totalIncome - totalExpense;

    // Atualizar DOM
    const elBalance = document.getElementById('kpi-balance');
    const elProjected = document.getElementById('kpi-projected');
    const elIncome = document.getElementById('kpi-income');
    const elExpense = document.getElementById('kpi-expense');

    if (elBalance) {
      elBalance.textContent = Utils.formatCurrency(currentBalance);
      elBalance.className = `text-2xl sm:text-3xl font-extrabold ${currentBalance >= 0 ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`;
    }

    if (elProjected) {
      elProjected.textContent = Utils.formatCurrency(projectedBalance);
      elProjected.className = `text-2xl sm:text-3xl font-extrabold ${projectedBalance >= 0 ? 'text-blue-600 dark:text-blue-400' : 'text-rose-600 dark:text-rose-400'}`;
    }

    if (elIncome) {
      elIncome.textContent = Utils.formatCurrency(totalIncome);
    }

    if (elExpense) {
      elExpense.textContent = Utils.formatCurrency(totalExpense);
    }

    // Sub-textos informativos
    const elBalanceSub = document.getElementById('kpi-balance-sub');
    if (elBalanceSub) {
      elBalanceSub.textContent = `Apenas realizados no mês`;
    }

    const elProjectedSub = document.getElementById('kpi-projected-sub');
    if (elProjectedSub) {
      const pendingDiff = (incomePending - expensePending);
      elProjectedSub.textContent = pendingDiff === 0 
        ? 'Sem pendências restantes' 
        : `Inclui pendências (${Utils.formatCurrency(pendingDiff)})`;
    }
  },

  renderTable(transactions) {
    const tbody = document.getElementById('transactions-table-body');
    const emptyState = document.getElementById('transactions-empty-state');
    const countBadge = document.getElementById('transactions-count-badge');

    if (countBadge) {
      countBadge.textContent = `${transactions.length} ${transactions.length === 1 ? 'lançamento' : 'lançamentos'}`;
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

      const typeBadge = isIncome
        ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300">
            <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M7 11l5-5m0 0l5 5m-5-5v12"/></svg>
            Receita
           </span>`
        : `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300">
            <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M17 13l-5 5m0 0l-5-5m5 5V6"/></svg>
            Despesa
           </span>`;

      const statusBadge = isPaid
        ? `<button type="button" onclick="App.toggleStatus('${t.id}')" title="Clique para marcar como Pendente" class="group inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60 hover:bg-emerald-100 dark:hover:bg-emerald-900/50 transition-colors">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            <span>Pago</span>
            <svg class="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity ml-0.5 text-emerald-600 dark:text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/></svg>
           </button>`
        : `<button type="button" onclick="App.toggleStatus('${t.id}')" title="Clique para marcar como Pago" class="group inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-50 dark:bg-amber-950/50 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60 hover:bg-amber-100 dark:hover:bg-amber-900/50 transition-colors">
            <span class="w-1.5 h-1.5 rounded-full bg-amber-500 status-pulse"></span>
            <span>Pendente</span>
            <svg class="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity ml-0.5 text-amber-600 dark:text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
           </button>`;

      const amountFormatted = (isIncome ? '+ ' : '- ') + Utils.formatCurrency(t.amount);
      const amountColor = isIncome 
        ? 'text-emerald-600 dark:text-emerald-400 font-semibold' 
        : 'text-rose-600 dark:text-rose-400 font-semibold';

      return `
        <tr class="table-row-hover border-b border-slate-200 dark:border-slate-800/80 hover:bg-slate-50/70 dark:hover:bg-slate-800/40 text-sm">
          <td class="py-3.5 px-4 whitespace-nowrap text-slate-500 dark:text-slate-400 font-medium">
            ${Utils.formatDateBR(t.date)}
          </td>
          <td class="py-3.5 px-4">
            <div class="font-medium text-slate-900 dark:text-slate-100 break-words max-w-xs">
              ${Utils.escapeHtml(t.description)}
            </div>
            <div class="sm:hidden mt-1 flex items-center gap-2">
              <span class="inline-block w-2 h-2 rounded-full" style="background-color: ${catColor}"></span>
              <span class="text-xs text-slate-500 dark:text-slate-400">${Utils.escapeHtml(t.category)}</span>
            </div>
          </td>
          <td class="py-3.5 px-4 hidden sm:table-cell">
            <div class="flex items-center gap-2">
              <span class="w-2.5 h-2.5 rounded-full flex-shrink-0" style="background-color: ${catColor}"></span>
              <span class="text-slate-700 dark:text-slate-300">${Utils.escapeHtml(t.category)}</span>
            </div>
          </td>
          <td class="py-3.5 px-4 hidden md:table-cell">
            ${typeBadge}
          </td>
          <td class="py-3.5 px-4 whitespace-nowrap">
            ${statusBadge}
          </td>
          <td class="py-3.5 px-4 text-right whitespace-nowrap ${amountColor}">
            ${amountFormatted}
          </td>
          <td class="py-3.5 px-4 text-right whitespace-nowrap">
            <div class="inline-flex items-center gap-1">
              <button type="button" onclick="App.openEditModal('${t.id}')" title="Editar transação" class="p-1.5 rounded-lg text-slate-500 hover:text-blue-600 dark:text-slate-400 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-slate-800 transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/></svg>
              </button>
              <button type="button" onclick="App.openDeleteModal('${t.id}')" title="Excluir transação" class="p-1.5 rounded-lg text-slate-500 hover:text-rose-600 dark:text-slate-400 dark:hover:text-rose-400 hover:bg-rose-50 dark:hover:bg-slate-800 transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  },

  openTransactionModal(editId = null) {
    const modal = document.getElementById('modal-transaction');
    const form = document.getElementById('form-transaction');
    const title = document.getElementById('modal-transaction-title');
    if (!modal || !form) return;

    form.reset();
    this.state.editingId = editId;

    if (editId) {
      const tx = this.state.transactions.find(t => t.id === editId);
      if (!tx) return;

      if (title) title.textContent = 'Editar Lançamento';
      document.getElementById('tx-id').value = tx.id;
      document.getElementById('tx-description').value = tx.description;
      document.getElementById('tx-amount').value = tx.amount;
      document.getElementById('tx-type').value = tx.type;
      document.getElementById('tx-category').value = tx.category;
      document.getElementById('tx-date').value = tx.date;
      document.getElementById('tx-status').value = tx.status;
    } else {
      if (title) title.textContent = 'Novo Lançamento';
      document.getElementById('tx-id').value = '';
      
      // Data padrão: hoje se estiver no mês filtrado, ou primeiro dia do mês filtrado
      const today = new Date().toISOString().split('T')[0];
      const defaultDate = today.startsWith(this.state.filters.month) ? today : `${this.state.filters.month}-01`;
      document.getElementById('tx-date').value = defaultDate;
      document.getElementById('tx-type').value = 'expense';
      document.getElementById('tx-status').value = 'paid';
    }

    modal.classList.remove('hidden');
    modal.classList.add('flex');
    setTimeout(() => {
      document.getElementById('tx-description').focus();
    }, 100);
  },

  closeTransactionModal() {
    const modal = document.getElementById('modal-transaction');
    if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }
    this.state.editingId = null;
  },

  handleTransactionSubmit(e) {
    e.preventDefault();

    const id = document.getElementById('tx-id').value;
    const description = document.getElementById('tx-description').value.trim();
    const amount = parseFloat(document.getElementById('tx-amount').value);
    const type = document.getElementById('tx-type').value;
    const category = document.getElementById('tx-category').value;
    const date = document.getElementById('tx-date').value;
    const status = document.getElementById('tx-status').value;

    if (!description) {
      Toast.show('Por favor, informe a descrição.', 'warning');
      return;
    }

    if (isNaN(amount) || amount <= 0) {
      Toast.show('Informe um valor numérico positivo válido.', 'warning');
      return;
    }

    if (!date) {
      Toast.show('Informe a data do lançamento.', 'warning');
      return;
    }

    if (this.state.editingId) {
      // Editar
      const index = this.state.transactions.findIndex(t => t.id === this.state.editingId);
      if (index !== -1) {
        this.state.transactions[index] = {
          ...this.state.transactions[index],
          description,
          amount,
          type,
          category,
          date,
          status
        };
        Toast.show('Lançamento atualizado com sucesso!', 'success');
      }
    } else {
      // Novo
      const newTx = {
        id: Utils.generateId(),
        description,
        amount,
        type,
        category,
        date,
        status
      };
      this.state.transactions.unshift(newTx);
      Toast.show('Lançamento cadastrado com sucesso!', 'success');

      // Se a data cadastrada for de outro mês, ajustar o filtro para visualizar o novo item
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

    this.state.transactions = this.state.transactions.filter(t => t.id !== this.state.deletingId);
    this.saveAndSync();
    this.closeDeleteModal();
    Toast.show('Lançamento excluído com sucesso.', 'info');
  },

  toggleStatus(id) {
    const tx = this.state.transactions.find(t => t.id === id);
    if (!tx) return;

    tx.status = tx.status === 'paid' ? 'pending' : 'paid';
    this.saveAndSync();
    Toast.show(`Status alterado para "${tx.status === 'paid' ? 'Pago' : 'Pendente'}"`, 'info', 2000);
  },

  clearFilters() {
    this.state.filters.type = 'all';
    this.state.filters.category = 'all';
    this.state.filters.status = 'all';
    this.state.filters.search = '';

    document.getElementById('filter-type').value = 'all';
    document.getElementById('filter-category').value = 'all';
    document.getElementById('filter-status').value = 'all';
    document.getElementById('filter-search').value = '';

    this.render();
    Toast.show('Filtros redefinidos.', 'info', 2000);
  },

  saveAndSync() {
    StorageService.saveData({ transactions: this.state.transactions });
    this.render();
  },

  // =========================================================================
  // PORTABILIDADE & BACKUP (JSON / CSV / AMOSTRA)
  // =========================================================================

  exportJSON() {
    const payload = {
      app: 'Controle Financeiro Pessoal',
      version: SCHEMA_VERSION,
      exportedAt: new Date().toISOString(),
      transactionsCount: this.state.transactions.length,
      transactions: this.state.transactions
    };

    const jsonStr = JSON.stringify(payload, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const today = new Date().toISOString().split('T')[0];

    a.href = url;
    a.download = `controle-financeiro-backup-${today}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    Toast.show('Backup JSON exportado com sucesso!', 'success');
  },

  exportCSV() {
    if (this.state.transactions.length === 0) {
      Toast.show('Não há lançamentos para exportar.', 'warning');
      return;
    }

    // Padrão Brasil com separador ';' e UTF-8 BOM para Excel / Sheets
    const header = ['ID', 'Data', 'Tipo', 'Categoria', 'Descrição', 'Valor', 'Status'];
    const rows = this.state.transactions.map(t => [
      `"${t.id}"`,
      `"${Utils.formatDateBR(t.date)}"`,
      `"${t.type === 'income' ? 'Receita' : 'Despesa'}"`,
      `"${(t.category || '').replace(/"/g, '""')}"`,
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
    a.download = `controle-financeiro-${today}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    Toast.show('Planilha CSV exportada com sucesso!', 'success');
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
          throw new Error('Formato inválido: lista de transações não encontrada.');
        }

        // Validação e normalização dos itens
        const validTxs = [];
        for (const item of importedList) {
          if (!item.description || isNaN(Number(item.amount))) continue;
          validTxs.push({
            id: item.id || Utils.generateId(),
            description: String(item.description),
            amount: Math.abs(Number(item.amount)),
            type: item.type === 'income' ? 'income' : 'expense',
            category: item.category || 'Outros',
            date: item.date || new Date().toISOString().split('T')[0],
            status: item.status === 'pending' ? 'pending' : 'paid'
          });
        }

        if (validTxs.length === 0) {
          Toast.show('Nenhuma transação válida encontrada no arquivo.', 'error');
          return;
        }

        if (mode === 'replace') {
          this.state.transactions = validTxs;
        } else {
          // Mesclar evitando IDs duplicados
          const existingIds = new Set(this.state.transactions.map(t => t.id));
          const newEntries = validTxs.map(t => {
            if (existingIds.has(t.id)) {
              return { ...t, id: Utils.generateId() };
            }
            return t;
          });
          this.state.transactions = [...newEntries, ...this.state.transactions];
        }

        this.saveAndSync();
        this.closeImportModal();
        Toast.show(`${validTxs.length} transações importadas com sucesso!`, 'success');
      } catch (err) {
        console.error('Falha ao processar arquivo JSON:', err);
        Toast.show('Arquivo inválido ou corrompido: ' + err.message, 'error');
      }
    };

    reader.readAsText(file);
  },

  // =========================================================================
  // SEGURANÇA: ALTERAÇÃO DE SENHA
  // =========================================================================

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
        version: SCHEMA_VERSION,
        updatedAt: new Date().toISOString(),
        transactions: this.state.transactions
      });
      this.closePasswordModal();
      Toast.show('Senha alterada com sucesso!', 'success');
    } catch (err) {
      console.error(err);
      Toast.show('Erro ao alterar a senha: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  },

  loadSampleData() {
    const samples = SampleData.generate(this.state.filters.month);
    this.state.transactions = samples;
    this.saveAndSync();
    Toast.show('Dados de exemplo carregados com sucesso!', 'success');
  },

  confirmClearAll() {
    if (confirm('Tem certeza de que deseja apagar TODOS os lançamentos? Essa ação não pode ser desfeita sem um backup prévio.')) {
      this.state.transactions = [];
      this.saveAndSync();
      Toast.show('Todos os dados foram apagados.', 'info');
    }
  }
};

// Inicializar aplicação ao carregar a página
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
