# 💳 FinControl — Controle Financeiro Pessoal

Uma aplicação web moderna, elegante e completa de **Controle Financeiro Pessoal**, desenvolvida para funcionar **100% no lado do cliente (client-side)** e otimizada para hospedagem estática gratuita no **GitHub Pages** (sem necessidade de back-end, banco de dados externo ou ferramentas de build).

---

## ✨ Principais Funcionalidades

### 1. 📊 Indicadores e Painel de Resumo (KPIs)
- **Saldo Atual Realizado:** Saldo de transações efetivadas (status *"Pago / Recebido"*).
- **Previsão de Saldo:** Projeção financeira completa considerando despesas e receitas agendadas (*"Pendentes"*).
- **Total de Receitas do Mês:** Visualização rápida dos ganhos planejados e realizados.
- **Total de Despesas do Mês:** Monitoramento de saídas e controle de gastos.

### 2. 📝 Gestão Completa de Lançamentos (CRUD)
- Formulário intuitivo para **criar e editar lançamentos**:
  - Descrição detalhada
  - Valor monetário em reais (R$)
  - Tipo (*Receita* ou *Despesa*)
  - Categoria (*Moradia, Alimentação, Transporte, Lazer, Saúde, Salário, Freelance, Investimentos, Educação, Outros*)
  - Data com navegação inteligente
  - Status (*Pago / Concluído* ou *Pendente / Agendado*)
- **Alternância de Status com 1 Clique:** Alterne entre *Pago* e *Pendente* diretamente na tabela sem abrir modais.
- **Edição e Exclusão Segura:** Modal de confirmação estilizado contra exclusões acidentais.

### 3. 🔍 Filtros e Busca em Tempo Real
- **Navegador de Mês/Ano:** Inicia automaticamente no mês atual, com botões de avanço/recuo rápido (`<` e `>`) e seletor dropdown.
- **Filtro por Tipo:** Exiba apenas receitas, apenas despesas ou todos.
- **Filtro por Categoria:** Isole despesas de alimentação, transporte, moradia, etc.
- **Filtro por Status:** Visualize apenas pendências ou apenas lançamentos quitados.
- **Busca Textual Instantânea:** Digite para filtrar descrições instantaneamente.

### 4. 📈 Dashboard Visual com Gráficos (Chart.js)
- **Gráfico de Rosca (Doughnut):** Mostra a divisão percentual e monetária das despesas por categoria no mês selecionado, com *empty state* amigável quando não houver gastos.
- **Gráfico de Barras Comparativo (6 Meses):** Histórico retroativo comparando o volume de Receitas vs. Despesas dos últimos seis meses.
- **Adaptação Dinâmica ao Tema:** Os gráficos ajustam as cores das legendas, textos e eixos automaticamente ao alternar entre tema claro e escuro.

### 5. 🌗 Tema Claro e Escuro (Dark Mode)
- Alternância instantânea com clique no botão do cabeçalho.
- Detecção automática da preferência do sistema operacional (`prefers-color-scheme`).
- Persistência da preferência no `localStorage`.

### 6. 💾 Portabilidade, Backup e Segurança
- **Exportar JSON:** Baixa todo o banco de dados local com metadados para segurança.
- **Importar JSON:** Permite restaurar o backup com opção de **Substituir tudo** ou **Mesclar com dados existentes** (com validação de schema e prevenção de IDs duplicados).
- **Exportar CSV:** Gera arquivo compatível com Excel e Google Sheets no padrão brasileiro (separador `;` e codificação UTF-8 com BOM `\uFEFF`).
- **Carregar Dados de Exemplo:** Preenche a base com lançamentos realistas cobrindo vários meses para testar imediatamente todos os gráficos e KPIs.
- **Segurança contra XSS:** Sanitização em tempo real de strings antes da injeção no DOM.

---

## 🛠️ Stack Tecnológica e Arquitetura

- **HTML5 Semântico:** Estrutura acessível com tags semânticas e conformidade W3C.
- **Tailwind CSS (via CDN):** Design system moderno, utilitário, com suporte nativo a `dark:` mode.
- **Chart.js (via CDN):** Gráficos interativos em canvas, leves e responsivos.
- **JavaScript (ES6+ Modular Vanilla):**
  - `Utils`: Funções de formatação BRL (`Intl.NumberFormat`), datas `DD/MM/AAAA` e sanitização XSS.
  - `StorageService`: Camada de persistência segura em `localStorage` com controle de versão de schema (`SCHEMA_VERSION = 1`).
  - `ThemeManager`: Gerenciamento e persistência de Dark/Light mode.
  - `ChartService`: Ciclo de vida e renderização dos gráficos Chart.js.
  - `Toast`: Feedback visual flutuante e não obstrutivo.
  - `App`: Gerenciador de estado, CRUD, filtros e eventos do DOM.
- **CSS3 Personalizado (`css/style.css`):** Scrollbars temáticas, micro-animações, animações de modal e glassmorphism.

---

## 📁 Estrutura de Pastas

```
Controle Financeiro/
│
├── index.html         # Estrutura principal da aplicação web
├── README.md          # Documentação do projeto e guia de deploy
├── css/
│   └── style.css      # Ajustes finos, animações e scrollbar customizada
└── js/
    └── app.js         # Lógica modular em ES6+, estado, gráficos e storage
```

---

## 🚀 Como Executar Localmente

Como a aplicação é 100% client-side e não requer build nem compilação, você pode executá-la de duas maneiras simples:

### Opção 1: Abrir diretamente no Navegador
1. Dê um duplo clique no arquivo `index.html`.
2. A aplicação será aberta no seu navegador padrão (`file:///.../index.html`) com todas as funções ativas.

### Opção 2: Usando um Servidor Local Simples

Caso queira usar um servidor local (ex: extensão *Live Server* do VS Code ou linha de comando):

```bash
# Com Python 3
python -m http.server 8000

# Ou com Node.js (npx serve)
npx serve .
```

Em seguida, acesse no navegador: `http://localhost:8000`

---

## 🌐 Passo a Passo para Deploy no GitHub Pages

O projeto está pronto para publicação gratuita no GitHub Pages:

### 1. Inicializar o repositório Git
No terminal da pasta do projeto, execute:

```bash
git init
git add .
git commit -m "feat: versão inicial do controle financeiro pessoal"
```

### 2. Criar repositório no GitHub
1. Acesse [github.com/new](https://github.com/new).
2. Dê um nome ao repositório (exemplo: `controle-financeiro` ou `fincontrol`).
3. Deixe o repositório como **Public**.
4. Não adicione README ou `.gitignore` (já criamos localmente).
5. Clique em **Create repository**.

### 3. Enviar os arquivos para o GitHub

```bash
git branch -M main
git remote add origin https://github.com/<SEU_USUARIO>/<NOME_DO_REPOSITORIO>.git
git push -u origin main
```

### 4. Ativar o GitHub Pages
1. No seu repositório no GitHub, clique na aba **Settings** (Configurações).
2. Na barra lateral esquerda, clique em **Pages** (dentro da seção *Code and automation*).
3. Na seção **Build and deployment**:
   - Em **Source**, selecione: `Deploy from a branch`.
   - Em **Branch**, selecione `main` e a pasta `/(root)`.
4. Clique em **Save**.
5. Aguarde cerca de 1 a 2 minutos. Uma mensagem no topo da página exibirá:
   > *"Your site is live at https://<SEU_USUARIO>.github.io/<NOME_DO_REPOSITORIO>/"*

Pronto! Seu Controle Financeiro Pessoal estará publicado e pronto para uso em qualquer computador, celular ou tablet.

---

## 🔒 Privacidade e Segurança dos Dados

### Login com senha + criptografia
- No **primeiro acesso**, você cria uma senha (mínimo 8 caracteres).
- Os dados são salvos **criptografados** com **AES-256-GCM**. A chave vem da sua senha via **PBKDF2-SHA256** (310.000 iterações e salt aleatório).
- A senha e a chave **nunca são gravadas**. A chave fica só na memória enquanto o app está desbloqueado.
- Botão de **cadeado** no cabeçalho para bloquear a sessão. Ela também é **bloqueada sozinha após 15 minutos sem uso**.
- **Alterar Senha** fica no menu *Backup*.
- Atraso progressivo após tentativas de senha erradas.
- Se você já tinha dados de uma versão anterior sem senha, eles são **migrados e criptografados** quando você cria a senha.

> ⚠️ **Não existe recuperação de senha.** Se você esquecer, os dados não podem ser abertos. A única saída é apagá-los e importar um backup. Faça **Backup > Exportar JSON** com frequência e guarde em local seguro (o arquivo exportado **não** é criptografado).

### Onde ficam os dados
- **Nenhum dado é enviado para servidores.** O GitHub Pages entrega apenas o código (HTML/CSS/JS), que é público. Seus lançamentos ficam no `localStorage` do seu navegador.
- Cada navegador/dispositivo tem seus próprios dados. Para levar os dados para outro aparelho, use Exportar/Importar JSON.

---

## 📄 Licença

Este projeto é disponibilizado sob a licença **MIT** — sinta-se livre para usar, estudar, modificar e distribuir conforme suas necessidades.
