/**
 * todo.sh — cliente do terminal.
 *
 * AppSec no cliente:
 *  - Nenhum uso de innerHTML/eval/Function (evita XSS por dado do servidor).
 *  - Token CSRF mantido apenas em memoria (nunca em localStorage/sessionStorage).
 *  - Toda decisao de autorizacao e' refeita no servidor; a UI e' apenas UX.
 */
'use strict';

(function initialise() {
  const api = createApiClient();
  const screen = document.getElementById('screen');
  const authScreen = document.getElementById('auth-screen');
  const terminal = document.getElementById('terminal');
  const form = document.getElementById('prompt-form');
  const input = document.getElementById('command');
  const authForm = document.getElementById('auth-form');
  const authMessage = document.getElementById('auth-message');
  const authEmail = document.getElementById('auth-email');
  const authPassword = document.getElementById('auth-password');
  const authSubmit = document.getElementById('auth-submit');
  const authRegister = document.getElementById('auth-register');

  const state = {
    user: null,
    csrfToken: null,
    todos: [],
    history: [],
    historyIndex: -1,
    busy: false,
  };

  /* ------------------------- API client ------------------------- */

  function createApiClient() {
    async function request(method, path, { body, csrf = true } = {}) {
      const headers = { Accept: 'application/json' };
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      if (csrf && state.csrfToken) headers['X-CSRF-Token'] = state.csrfToken;

      const response = await fetch(path, {
        method,
        headers,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        body: body === undefined ? undefined : JSON.stringify(body),
      });

      if (response.status === 204) return { status: response.status, data: null };
      let data = null;
      try {
        data = await response.json();
      } catch {
        data = null;
      }
      if (!response.ok) {
        const error = new Error((data && data.error && data.error.message) || 'Erro na requisição.');
        error.status = response.status;
        error.code = data && data.error ? data.error.code : 'UNKNOWN';
        throw error;
      }
      return { status: response.status, data };
    }

    return {
      session: () => request('GET', '/api/v1/session', { csrf: false }),
      login: (email, password) => request('POST', '/api/v1/auth/login', { body: { email, password }, csrf: false }),
      register: (email, password) => request('POST', '/api/v1/auth/register', { body: { email, password }, csrf: false }),
      logout: () => request('POST', '/api/v1/auth/logout'),
      list: (status) => request('GET', `/api/v1/todos?status=${encodeURIComponent(status)}&limit=100`, { csrf: false }),
      create: (todo) => request('POST', '/api/v1/todos', { body: todo }),
      update: (id, patch) => request('PATCH', `/api/v1/todos/${encodeURIComponent(id)}`, { body: patch }),
      remove: (id) => request('DELETE', `/api/v1/todos/${encodeURIComponent(id)}`),
    };
  }

  /* ------------------------- Render (sem innerHTML) ------------------------- */

  function write(text, className) {
    const line = document.createElement('span');
    line.className = `line ${className || 'line-info'}`;
    line.textContent = text; // textContent: nunca interpretamos HTML do servidor
    screen.appendChild(line);
    screen.scrollTop = screen.scrollHeight;
  }

  function writeNodes(nodes) {
    const line = document.createElement('span');
    line.className = 'line';
    nodes.forEach((node) => line.appendChild(node));
    screen.appendChild(line);
    screen.scrollTop = screen.scrollHeight;
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function clearScreen() {
    while (screen.firstChild) screen.removeChild(screen.firstChild);
  }

  /* ------------------------- Boot ------------------------- */

  const BANNER = [
    'todo.sh v1.0.0 — terminal To-Do List (Node.js sem dependências externas)',
    'Autenticado. Digite `help` para a lista de comandos.',
  ];

  async function boot() {
    try {
      const { data } = await api.session();
      if (data && data.authenticated) {
        state.user = data.user;
        state.csrfToken = data.csrfToken;
        showTerminal();
        BANNER.forEach((line) => write(line, 'line-dim'));
        await refresh('all');
        input.focus();
        return;
      }
    } catch {
      write('Falha ao contacting o servidor.', 'line-err');
    }
    showAuth();
  }

  function showAuth() {
    authScreen.hidden = false;
    terminal.hidden = true;
    clearScreen();
    authMessage.textContent = '';
    authEmail.focus();
  }

  function showTerminal() {
    authScreen.hidden = true;
    terminal.hidden = false;
    document.getElementById('terminal-user').textContent = state.user.email;
    document.getElementById('prompt-user').textContent = state.user.email.split('@')[0];
  }

  /* ------------------------- Auth ------------------------- */

  async function submitAuth(event, mode) {
    event.preventDefault();
    if (state.busy) return;
    const email = authEmail.value.trim();
    const password = authPassword.value;

    authMessage.classList.remove('ok');
    authMessage.textContent = '';
    authSubmit.disabled = true;
    authRegister.disabled = true;
    state.busy = true;

    try {
      await (mode === 'register' ? api.register(email, password) : api.login(email, password));
      const { data } = await api.session();
      state.user = data.user;
      state.csrfToken = data.csrfToken;
      authPassword.value = '';
      showTerminal();
      clearScreen();
      BANNER.forEach((line) => write(line, 'line-dim'));
      await refresh('all');
      input.focus();
    } catch (error) {
      authMessage.textContent = friendlyError(error);
    } finally {
      state.busy = false;
      authSubmit.disabled = false;
      authRegister.disabled = false;
    }
  }

  function friendlyError(error) {
    if (error.status === 429) return 'Limite de tentativas excedido. Aguarde alguns instantes.';
    if (error.status === 0) return 'Servidor inacessível.';
    return error.message || 'Falha na operação.';
  }

  /* ------------------------- Dados ------------------------- */

  async function refresh(status) {
    const { data } = await api.list(status);
    state.todos = data.items;
    return data;
  }

  function renderTodos(todos, emptyMessage) {
    if (todos.length === 0) {
      write(emptyMessage, 'line-dim');
      return;
    }
    todos.forEach((todo, index) => {
      const nodes = [];
      nodes.push(element('span', todo.done ? 'todo-done' : 'todo-open'));
      nodes.push(element('span', 'todo-id', `#${index + 1}`));
      nodes.push(element('span', 'todo-title', todo.title));
      nodes.push(element('span', 'todo-meta', `  (${todo.priority}${todo.description ? ' · ' + todo.description : ''})`));
      writeNodes(nodes);
    });
  }

  function findTodoId(reference) {
    const raw = String(reference || '').trim();
    if (/^\d+$/.test(raw)) {
      const index = Number.parseInt(raw, 10) - 1;
      const todo = state.todos[index];
      if (!todo) throw new Error(`Nenhuma tarefa com índice ${raw} nesta lista.`);
      return todo.id;
    }
    const byId = state.todos.find((todo) => todo.id === raw.toLowerCase());
    if (!byId) throw new Error('Tarefa não encontrada nesta lista.');
    return byId.id;
  }

  /* ------------------------- Comandos ------------------------- */

  const COMMANDS = {
    help: {
      usage: 'help',
      about: 'mostra esta ajuda',
      run: () => {
        write('Comandos disponíveis:', 'line-heading');
        Object.entries(COMMANDS)
          .sort(([a], [b]) => a.localeCompare(b))
          .forEach(([, cmd]) => write(`  ${cmd.usage.padEnd(28)} ${cmd.about}`, 'line-dim'));
      },
    },
    ls: {
      usage: 'ls [open|done|all]',
      about: 'lista tarefas',
      run: async (args) => {
        const status = args[0] || 'open';
        if (!['open', 'done', 'all'].includes(status)) throw new Error('Use: ls [open|done|all]');
        const data = await refresh(status);
        renderTodos(data.items, 'Nenhuma tarefa. Use `add <titulo>` para criar.');
        write(`${data.total} tarefa(s) · showing ${data.items.length}`, 'line-dim');
      },
    },
    add: {
      usage: 'add <titulo> [--pri high|normal|low] [--desc texto]',
      about: 'cria uma tarefa',
      run: async (args) => {
        const parsed = parseAddArgs(args);
        const { data } = await api.create(parsed);
        state.todos.unshift(data.todo);
        write(`[+] tarefa criada: ${data.todo.title}`, 'line-ok');
        write(`    id: ${data.todo.id}`, 'line-dim');
      },
    },
    done: {
      usage: 'done <#|id>',
      about: 'marca tarefa como concluída',
      run: async (args) => {
        if (args.length === 0) throw new Error('Uso: done <#|id>');
        const id = findTodoId(args[0]);
        const { data } = await api.update(id, { done: true });
        write(`[✓] concluída: ${data.todo.title}`, 'line-ok');
        await refresh('open');
      },
    },
    undone: {
      usage: 'undone <#|id>',
      about: 'reabre uma tarefa concluída',
      run: async (args) => {
        if (args.length === 0) throw new Error('Uso: undone <#|id>');
        const id = findTodoId(args[0]);
        const { data } = await api.update(id, { done: false });
        write(`[↺] reaberta: ${data.todo.title}`, 'line-warn');
        await refresh('open');
      },
    },
    edit: {
      usage: 'edit <#|id> <novo titulo>',
      about: 'altera o título de uma tarefa',
      run: async (args) => {
        if (args.length < 2) throw new Error('Uso: edit <#|id> <novo titulo>');
        const id = findTodoId(args[0]);
        const title = args.slice(1).join(' ').slice(0, 120);
        const { data } = await api.update(id, { title });
        write(`[*] atualizada: ${data.todo.title}`, 'line-ok');
        await refresh('open');
      },
    },
    rm: {
      usage: 'rm <#|id>',
      about: 'remove uma tarefa',
      run: async (args) => {
        if (args.length === 0) throw new Error('Uso: rm <#|id>');
        const id = findTodoId(args[0]);
        await api.remove(id);
        write('[-] tarefa removida', 'line-warn');
        await refresh('open');
      },
    },
    stats: {
      usage: 'stats',
      about: 'resumo quantitativo',
      run: async () => {
        const [open, done] = await Promise.all([refresh('open'), api.list('done').then((r) => r.data)]);
        write(`abertas: ${open.total} · concluídas: ${done.total}`, 'line-info');
        write(`sessão de ${state.user.email} · ${new Date().toLocaleString('pt-BR')}`, 'line-dim');
      },
    },
    whoami: {
      usage: 'whoami',
      about: 'usuário autenticado',
      run: () => write(`${state.user.email} (${state.user.id})`, 'line-info'),
    },
    date: {
      usage: 'date',
      about: 'data e hora atuais',
      run: () => write(new Date().toString(), 'line-dim'),
    },
    clear: {
      usage: 'clear',
      about: 'limpa a tela',
      run: () => clearScreen(),
    },
    logout: {
      usage: 'logout',
      about: 'encerra a sessão',
      run: async () => {
        await api.logout();
        state.user = null;
        state.csrfToken = null;
        state.todos = [];
        write('Sessão encerrada.', 'line-warn');
        setTimeout(showAuth, 300);
      },
    },
  };

  function parseAddArgs(args) {
    if (args.length === 0) throw new Error('Uso: add <titulo>');
    let priority = 'normal';
    let description;
    const words = [];
    for (let i = 0; i < args.length; i += 1) {
      if (args[i] === '--pri' || args[i] === '--priority') {
        priority = (args[i + 1] || '').toLowerCase();
        i += 1;
      } else if (args[i] === '--desc') {
        description = args.slice(i + 1).join(' ');
        i = args.length;
      } else {
        words.push(args[i]);
      }
    }
    if (!['low', 'normal', 'high'].includes(priority)) {
      throw new Error('Prioridade deve ser low, normal ou high.');
    }
    const title = words.join(' ').slice(0, 120);
    if (!title) throw new Error('Informe um título para a tarefa.');
    const payload = { title, priority };
    if (description) payload.description = description.slice(0, 1000);
    return payload;
  }

  function tokenize(raw) {
    const parts = [];
    let current = '';
    let quote = null;
    for (const char of raw) {
      if (quote) {
        if (char === quote) quote = null;
        else current += char;
      } else if (char === '"' || char === "'") {
        quote = char;
      } else if (/\s/.test(char)) {
        if (current) parts.push(current);
        current = '';
      } else {
        current += char;
      }
    }
    if (current) parts.push(current);
    return parts;
  }

  async function execute(raw) {
    write(`${document.getElementById('prompt-user').textContent}@todo:~$ ${raw}`, 'line-echo');
    const [name, ...args] = tokenize(raw);
    if (!name) return;

    const command = COMMANDS[name.toLowerCase()];
    if (!command) {
      write(`command not found: ${name}. Digite \`help\`.`, 'line-err');
      return;
    }
    try {
      await command.run(args);
    } catch (error) {
      if (error.status === 401) {
        write('Sessão expirada. Faça login novamente.', 'line-warn');
        setTimeout(showAuth, 500);
        return;
      }
      write(friendlyError(error), 'line-err');
    }
  }

  /* ------------------------- Eventos ------------------------- */

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const raw = input.value;
    input.value = '';
    if (raw.trim()) {
      state.history.push(raw);
      state.historyIndex = state.history.length;
      execute(raw);
    }
  });

  input.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowUp') {
      if (state.historyIndex > 0) {
        state.historyIndex -= 1;
        input.value = state.history[state.historyIndex];
      }
      event.preventDefault();
    } else if (event.key === 'ArrowDown') {
      if (state.historyIndex < state.history.length - 1) {
        state.historyIndex += 1;
        input.value = state.history[state.historyIndex];
      } else {
        state.historyIndex = state.history.length;
        input.value = '';
      }
      event.preventDefault();
    } else if (event.key === 'Tab') {
      const candidates = Object.keys(COMMANDS).filter((c) => c.startsWith(input.value.trim().toLowerCase()));
      if (candidates.length === 1) input.value = `${candidates[0]} `;
      event.preventDefault();
    } else if (event.key === 'l' && event.ctrlKey) {
      clearScreen();
      event.preventDefault();
    } else if (event.key === 'c' && event.ctrlKey) {
      write(`${input.value}^C`, 'line-echo');
      input.value = '';
      event.preventDefault();
    }
  });

  authForm.addEventListener('submit', (event) => submitAuth(event, 'login'));
  authRegister.addEventListener('click', (event) => submitAuth(event, 'register'));
  screen.addEventListener('click', () => input.focus());

  boot();
}());