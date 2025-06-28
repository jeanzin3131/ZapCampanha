// Sistema de Campanhas WhatsApp - Arquivo único server.js
// Desenvolvido com Express, WhatsApp-Web.js e SQLite3

const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');

// Configurações
const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = './banco.db';

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configuração de sessão
app.use(session({
    secret: 'whatsapp-campaign-secret-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 horas
}));

// Variáveis globais
let whatsappClient = null;
let isWhatsAppReady = false;
let grupos = [];
let ultimosEnvios = new Map(); // Para controle anti-spam

// ==================== BANCO DE DADOS ====================

class Database {
    constructor() {
        this.db = new sqlite3.Database(DB_PATH);
        this.init();
    }

    init() {
        // Criar tabelas se não existirem
        this.db.serialize(() => {
            // Tabela de clientes
            this.db.run(`
                CREATE TABLE IF NOT EXISTS clientes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nome TEXT NOT NULL,
                    telefone TEXT UNIQUE NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    status TEXT DEFAULT 'ativo',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Tabela de campanhas
            this.db.run(`
                CREATE TABLE IF NOT EXISTS campanhas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cliente_id INTEGER,
                    titulo TEXT NOT NULL,
                    mensagem TEXT NOT NULL,
                    intervalo_minutos INTEGER DEFAULT 60,
                    status TEXT DEFAULT 'ativa',
                    ultimo_disparo DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cliente_id) REFERENCES clientes (id)
                )
            `);

            // Tabela de logs de envio
            this.db.run(`
                CREATE TABLE IF NOT EXISTS logs_envio (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campanha_id INTEGER,
                    grupo TEXT,
                    status TEXT,
                    erro TEXT,
                    data_envio DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (campanha_id) REFERENCES campanhas (id)
                )
            `);

            // Inserir cliente admin padrão se não existir
            this.db.get("SELECT * FROM clientes WHERE telefone = 'admin'", (err, row) => {
                if (!row) {
                    this.db.run(`
                        INSERT INTO clientes (nome, telefone, token, status) 
                        VALUES ('Administrador', 'admin', 'admin123', 'ativo')
                    `);
                    console.log('🔧 Cliente admin criado: telefone=admin, token=admin123');
                }
            });

            // Inserir cliente de teste se não existir
            this.db.get("SELECT * FROM clientes WHERE telefone = '5511999999999'", (err, row) => {
                if (!row) {
                    this.db.run(`
                        INSERT INTO clientes (nome, telefone, token, status) 
                        VALUES ('Cliente Teste', '5511999999999', 'teste123', 'ativo')
                    `);
                    console.log('🧪 Cliente teste criado: telefone=5511999999999, token=teste123');
                }
            });
        });

        console.log('💾 Banco de dados inicializado');
    }

    // Métodos para clientes
    getClienteByCredentials(telefone, token, callback) {
        this.db.get(
            "SELECT * FROM clientes WHERE telefone = ? AND token = ? AND status = 'ativo'",
            [telefone, token],
            callback
        );
    }

    getAllClientes(callback) {
        this.db.all("SELECT * FROM clientes ORDER BY created_at DESC", callback);
    }

    updateClienteStatus(id, status, callback) {
        this.db.run("UPDATE clientes SET status = ? WHERE id = ?", [status, id], callback);
    }

    createCliente(nome, telefone, token, callback) {
        this.db.run(
            "INSERT INTO clientes (nome, telefone, token, status) VALUES (?, ?, ?, 'ativo')",
            [nome, telefone, token],
            callback
        );
    }

    updateCliente(id, nome, telefone, token, callback) {
        this.db.run(
            "UPDATE clientes SET nome = ?, telefone = ?, token = ? WHERE id = ?",
            [nome, telefone, token, id],
            callback
        );
    }

    getClienteById(id, callback) {
        this.db.get("SELECT * FROM clientes WHERE id = ?", [id], callback);
    }

    // Métodos para campanhas
    getCampanhasByCliente(clienteId, callback) {
        this.db.all(
            "SELECT * FROM campanhas WHERE cliente_id = ? ORDER BY created_at DESC",
            [clienteId],
            callback
        );
    }

    getCampanhasAtivas(callback) {
        this.db.all(
            `SELECT c.*, cl.nome as cliente_nome 
             FROM campanhas c 
             JOIN clientes cl ON c.cliente_id = cl.id 
             WHERE c.status = 'ativa' AND cl.status = 'ativo'`,
            callback
        );
    }

    createCampanha(clienteId, titulo, mensagem, intervalo, callback) {
        this.db.run(
            "INSERT INTO campanhas (cliente_id, titulo, mensagem, intervalo_minutos) VALUES (?, ?, ?, ?)",
            [clienteId, titulo, mensagem, intervalo],
            callback
        );
    }

    updateCampanhaStatus(id, status, callback) {
        this.db.run("UPDATE campanhas SET status = ? WHERE id = ?", [status, id], callback);
    }

    updateUltimoDisparo(campanhaId, callback) {
        this.db.run(
            "UPDATE campanhas SET ultimo_disparo = CURRENT_TIMESTAMP WHERE id = ?",
            [campanhaId],
            callback
        );
    }

    // Métodos para logs
    addLog(campanhaId, grupo, status, erro = null, callback) {
        this.db.run(
            "INSERT INTO logs_envio (campanha_id, grupo, status, erro) VALUES (?, ?, ?, ?)",
            [campanhaId, grupo, status, erro],
            callback
        );
    }

    getLogsByCliente(clienteId, callback) {
        this.db.all(
            `SELECT l.*, c.titulo as campanha_titulo 
             FROM logs_envio l 
             JOIN campanhas c ON l.campanha_id = c.id 
             WHERE c.cliente_id = ? 
             ORDER BY l.data_envio DESC 
             LIMIT 100`,
            [clienteId],
            callback
        );
    }

    getLogsAdmin(callback) {
        this.db.all(
            `SELECT l.*, c.titulo as campanha_titulo, cl.nome as cliente_nome
             FROM logs_envio l 
             JOIN campanhas c ON l.campanha_id = c.id 
             JOIN clientes cl ON c.cliente_id = cl.id
             ORDER BY l.data_envio DESC 
             LIMIT 200`,
            callback
        );
    }
}

const db = new Database();

// ==================== WHATSAPP BOT ====================

function initWhatsAppBot() {
    console.log('🤖 Iniciando WhatsApp Bot...');
    
    try {
        whatsappClient = new Client({
            authStrategy: new LocalAuth({
                dataPath: './whatsapp-session'
            }),
            puppeteer: {
                headless: true,
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--single-process',
                    '--disable-gpu',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor',
                    '--ignore-certificate-errors',
                    '--ignore-ssl-errors',
                    '--ignore-certificate-errors-spki-list'
                ],
                timeout: 60000
            }
        });
    } catch (error) {
        console.error('❌ Erro ao criar cliente WhatsApp:', error);
        console.log('⚠️ Sistema continuará funcionando sem WhatsApp');
        return;
    }

    whatsappClient.on('qr', (qr) => {
        console.log('📱 QR Code recebido! Escaneie com seu WhatsApp:');
        qrcode.generate(qr, { small: true });
        console.log('💡 Dica: Se o QR Code não aparecer, verifique sua conexão com a internet');
    });

    whatsappClient.on('ready', async () => {
        console.log('✅ WhatsApp Bot conectado e pronto!');
        isWhatsAppReady = true;
        
        try {
            // Buscar todos os grupos
            const chats = await whatsappClient.getChats();
            grupos = chats.filter(chat => chat.isGroup);
            console.log(`📱 ${grupos.length} grupos encontrados`);
        } catch (error) {
            console.error('❌ Erro ao buscar grupos:', error);
            grupos = [];
        }
    });

    whatsappClient.on('authenticated', () => {
        console.log('🔐 WhatsApp autenticado com sucesso!');
    });

    whatsappClient.on('auth_failure', (msg) => {
        console.error('❌ Falha na autenticação:', msg);
        console.log('💡 Dica: Delete a pasta whatsapp-session e tente novamente');
    });

    whatsappClient.on('disconnected', (reason) => {
        console.log('📱 WhatsApp desconectado:', reason);
        isWhatsAppReady = false;
        grupos = [];
        
        // Tentar reconectar após 30 segundos
        setTimeout(() => {
            console.log('🔄 Tentando reconectar WhatsApp...');
            initWhatsAppBot();
        }, 30000);
    });

    // Atendimento no privado
    whatsappClient.on('message', async (message) => {
        try {
            // Só responder mensagens privadas (não de grupos)
            if (!message.from.includes('@g.us') && !message.fromMe) {
                const response = `Olá! 👋 Sou o robô de campanhas. 

Para contratar um plano, acesse nosso site ou responda com *quero assinar*.

🚀 *Recursos disponíveis:*
• Campanhas automáticas
• Disparo em massa
• Painel de controle
• Relatórios detalhados

Entre em contato conosco!`;

                await message.reply(response);
                console.log(`💬 Resposta automática enviada para: ${message.from}`);
            }
        } catch (error) {
            console.error('❌ Erro ao enviar resposta automática:', error);
        }
    });

    // Inicializar com tratamento de erro
    whatsappClient.initialize().catch(error => {
        console.error('❌ Erro ao inicializar WhatsApp:', error.message);
        
        if (error.message.includes('ERR_NAME_NOT_RESOLVED')) {
            console.log('🌐 Problema de conectividade detectado!');
            console.log('💡 Soluções possíveis:');
            console.log('   1. Verifique sua conexão com a internet');
            console.log('   2. Desative proxy/VPN temporariamente');
            console.log('   3. Verifique se o WhatsApp Web não está bloqueado');
            console.log('   4. Tente reiniciar o sistema mais tarde');
        }
        
        console.log('⚠️ Sistema continuará funcionando sem WhatsApp');
        console.log('📊 Você ainda pode usar o painel de administração');
    });
}

// ==================== FUNÇÕES DE DISPARO ====================

function substituirPlaceholders(mensagem, nomeCliente = '') {
    const agora = new Date();
    const data = agora.toLocaleDateString('pt-BR');
    const hora = agora.toLocaleTimeString('pt-BR');
    
    return mensagem
        .replace(/\{\{cliente\}\}/g, nomeCliente)
        .replace(/\{\{data\}\}/g, data)
        .replace(/\{\{hora\}\}/g, hora);
}

async function enviarMensagemParaGrupos(campanha, forcarDisparo = false) {
    if (!isWhatsAppReady) {
        console.log('❌ WhatsApp não está conectado');
        return { sucesso: 0, erro: grupos.length, detalhes: 'WhatsApp não conectado' };
    }

    if (grupos.length === 0) {
        console.log('❌ Nenhum grupo encontrado');
        return { sucesso: 0, erro: 0, detalhes: 'Nenhum grupo encontrado' };
    }

    const chaveAntiSpam = `campanha_${campanha.id}`;
    const agora = new Date();
    
    // Verificar anti-spam (só para disparos automáticos)
    if (!forcarDisparo) {
        const ultimoEnvio = ultimosEnvios.get(chaveAntiSpam);
        if (ultimoEnvio && (agora - ultimoEnvio) < (campanha.intervalo_minutos * 60 * 1000)) {
            console.log(`⏰ Campanha ${campanha.id} ainda no intervalo mínimo`);
            return { sucesso: 0, erro: 0, detalhes: 'Aguardando intervalo mínimo' };
        }
    }

    let sucessos = 0;
    let erros = 0;
    const mensagemFinal = substituirPlaceholders(campanha.mensagem, campanha.cliente_nome || '');

    console.log(`🚀 Iniciando disparo da campanha: ${campanha.titulo}`);

    for (const grupo of grupos) {
        try {
            await whatsappClient.sendMessage(grupo.id._serialized, mensagemFinal);
            sucessos++;
            
            // Log de sucesso
            db.addLog(campanha.id, grupo.name, 'enviado', null, (err) => {
                if (err) console.error('Erro ao salvar log:', err);
            });

            console.log(`✅ Mensagem enviada para: ${grupo.name}`);
            
            // Delay entre mensagens para evitar bloqueio
            await new Promise(resolve => setTimeout(resolve, 2000));
            
        } catch (error) {
            erros++;
            console.error(`❌ Erro ao enviar para ${grupo.name}:`, error.message);
            
            // Log de erro
            db.addLog(campanha.id, grupo.name, 'erro', error.message, (err) => {
                if (err) console.error('Erro ao salvar log:', err);
            });
        }
    }

    // Atualizar controle anti-spam e último disparo
    ultimosEnvios.set(chaveAntiSpam, agora);
    db.updateUltimoDisparo(campanha.id, (err) => {
        if (err) console.error('Erro ao atualizar último disparo:', err);
    });

    console.log(`📊 Disparo concluído - Sucessos: ${sucessos}, Erros: ${erros}`);
    return { sucesso: sucessos, erro: erros, detalhes: `${sucessos} enviados, ${erros} erros` };
}

// ==================== AGENDADOR DE CAMPANHAS ====================

function iniciarAgendador() {
    console.log('⏰ Agendador de campanhas iniciado');
    
    setInterval(() => {
        if (!isWhatsAppReady) return;

        db.getCampanhasAtivas((err, campanhas) => {
            if (err) {
                console.error('Erro ao buscar campanhas:', err);
                return;
            }

            const agora = new Date();
            
            campanhas.forEach(async (campanha) => {
                // Verificar se já passou o tempo mínimo desde o último disparo
                let podeDisparar = true;
                
                if (campanha.ultimo_disparo) {
                    const ultimoDisparo = new Date(campanha.ultimo_disparo);
                    const diferencaMinutos = (agora - ultimoDisparo) / (1000 * 60);
                    podeDisparar = diferencaMinutos >= campanha.intervalo_minutos;
                }

                if (podeDisparar) {
                    console.log(`🎯 Disparando campanha automática: ${campanha.titulo}`);
                    await enviarMensagemParaGrupos(campanha, false);
                }
            });
        });
    }, 60000); // Verificar a cada minuto
}

// ==================== MIDDLEWARES DE AUTENTICAÇÃO ====================

function requireAuth(req, res, next) {
    if (req.session && req.session.cliente) {
        next();
    } else {
        res.redirect('/login');
    }
}

function requireAdmin(req, res, next) {
    if (req.session && req.session.cliente && req.session.cliente.telefone === 'admin') {
        next();
    } else {
        res.status(403).send('Acesso negado - Apenas administradores');
    }
}

// ==================== ROTAS ====================

// Página de login
app.get('/login', (req, res) => {
    res.render('login', { erro: null });
});

app.post('/login', (req, res) => {
    const { telefone, token } = req.body;
    
    if (!telefone || !token) {
        return res.render('login', { erro: 'Telefone e token são obrigatórios' });
    }

    db.getClienteByCredentials(telefone, token, (err, cliente) => {
        if (err) {
            console.error('Erro na consulta:', err);
            return res.render('login', { erro: 'Erro interno do servidor' });
        }

        if (!cliente) {
            return res.render('login', { erro: 'Credenciais inválidas' });
        }

        req.session.cliente = cliente;
        
        // Redirecionar admin para painel admin
        if (cliente.telefone === 'admin') {
            res.redirect('/admin');
        } else {
            res.redirect('/');
        }
    });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Painel principal do cliente
app.get('/', requireAuth, (req, res) => {
    const clienteId = req.session.cliente.id;
    
    // Buscar campanhas do cliente
    db.getCampanhasByCliente(clienteId, (err, campanhas) => {
        if (err) {
            console.error('Erro ao buscar campanhas:', err);
            campanhas = [];
        }
        
        // Buscar logs do cliente
        db.getLogsByCliente(clienteId, (err2, logs) => {
            if (err2) {
                console.error('Erro ao buscar logs:', err2);
                logs = [];
            }
            
            res.render('dashboard', {
                cliente: req.session.cliente,
                campanhas: campanhas,
                logs: logs,
                whatsappStatus: isWhatsAppReady,
                gruposCount: grupos.length
            });
        });
    });
});

// Criar campanha
app.post('/campanha/criar', requireAuth, (req, res) => {
    const { titulo, mensagem, intervalo } = req.body;
    const clienteId = req.session.cliente.id;
    
    if (!titulo || !mensagem || !intervalo) {
        return res.status(400).json({ erro: 'Todos os campos são obrigatórios' });
    }

    db.createCampanha(clienteId, titulo, mensagem, intervalo, function(err) {
        if (err) {
            console.error('Erro ao criar campanha:', err);
            return res.status(500).json({ erro: 'Erro ao criar campanha' });
        }
        
        res.json({ sucesso: true, id: this.lastID });
    });
});

// Pausar/Ativar campanha
app.post('/campanha/:id/toggle', requireAuth, (req, res) => {
    const campanhaId = req.params.id;
    const { status } = req.body;
    
    if (!['ativa', 'pausada'].includes(status)) {
        return res.status(400).json({ erro: 'Status inválido' });
    }

    db.updateCampanhaStatus(campanhaId, status, (err) => {
        if (err) {
            console.error('Erro ao atualizar status:', err);
            return res.status(500).json({ erro: 'Erro ao atualizar status' });
        }
        
        res.json({ sucesso: true });
    });
});

// Disparar campanha agora
app.post('/campanha/:id/disparar', requireAuth, async (req, res) => {
    const campanhaId = req.params.id;
    
    // Buscar dados da campanha
    db.getCampanhasByCliente(req.session.cliente.id, async (err, campanhas) => {
        if (err) {
            return res.status(500).json({ erro: 'Erro ao buscar campanha' });
        }
        
        const campanha = campanhas.find(c => c.id == campanhaId);
        if (!campanha) {
            return res.status(404).json({ erro: 'Campanha não encontrada' });
        }
        
        const resultado = await enviarMensagemParaGrupos(campanha, true);
        res.json(resultado);
    });
});

// Painel Admin
app.get('/admin', requireAdmin, (req, res) => {
    db.getAllClientes((err, clientes) => {
        if (err) {
            console.error('Erro ao buscar clientes:', err);
            clientes = [];
        }
        
        db.getLogsAdmin((err2, logs) => {
            if (err2) {
                console.error('Erro ao buscar logs admin:', err2);
                logs = [];
            }
            
            res.render('admin', {
                clientes: clientes,
                logs: logs,
                whatsappStatus: isWhatsAppReady,
                gruposCount: grupos.length
            });
        });
    });
});

// Bloquear/Desbloquear cliente
app.post('/admin/cliente/:id/toggle', requireAdmin, (req, res) => {
    const clienteId = req.params.id;
    const { status } = req.body;
    
    if (!['ativo', 'bloqueado'].includes(status)) {
        return res.status(400).json({ erro: 'Status inválido' });
    }

    db.updateClienteStatus(clienteId, status, (err) => {
        if (err) {
            console.error('Erro ao atualizar status do cliente:', err);
            return res.status(500).json({ erro: 'Erro ao atualizar status' });
        }
        
        res.json({ sucesso: true });
    });
});

// Criar cliente
app.post('/admin/cliente/criar', requireAdmin, (req, res) => {
    const { nome, telefone, token } = req.body;
    
    if (!nome || !telefone || !token) {
        return res.status(400).json({ erro: 'Todos os campos são obrigatórios' });
    }

    // Validações básicas
    if (nome.length < 2) {
        return res.status(400).json({ erro: 'Nome deve ter pelo menos 2 caracteres' });
    }

    if (telefone.length < 10) {
        return res.status(400).json({ erro: 'Telefone deve ter pelo menos 10 dígitos' });
    }

    if (token.length < 4) {
        return res.status(400).json({ erro: 'Token deve ter pelo menos 4 caracteres' });
    }

    db.createCliente(nome, telefone, token, function(err) {
        if (err) {
            console.error('Erro ao criar cliente:', err);
            if (err.message.includes('UNIQUE constraint failed')) {
                if (err.message.includes('telefone')) {
                    return res.status(400).json({ erro: 'Este telefone já está cadastrado' });
                }
                if (err.message.includes('token')) {
                    return res.status(400).json({ erro: 'Este token já está em uso' });
                }
            }
            return res.status(500).json({ erro: 'Erro ao criar cliente' });
        }
        
        res.json({ sucesso: true, id: this.lastID });
    });
});

// Editar cliente
app.post('/admin/cliente/:id/editar', requireAdmin, (req, res) => {
    const clienteId = req.params.id;
    const { nome, telefone, token } = req.body;
    
    if (!nome || !telefone || !token) {
        return res.status(400).json({ erro: 'Todos os campos são obrigatórios' });
    }

    // Validações básicas
    if (nome.length < 2) {
        return res.status(400).json({ erro: 'Nome deve ter pelo menos 2 caracteres' });
    }

    if (telefone.length < 10) {
        return res.status(400).json({ erro: 'Telefone deve ter pelo menos 10 dígitos' });
    }

    if (token.length < 4) {
        return res.status(400).json({ erro: 'Token deve ter pelo menos 4 caracteres' });
    }

    db.updateCliente(clienteId, nome, telefone, token, (err) => {
        if (err) {
            console.error('Erro ao editar cliente:', err);
            if (err.message.includes('UNIQUE constraint failed')) {
                if (err.message.includes('telefone')) {
                    return res.status(400).json({ erro: 'Este telefone já está cadastrado por outro cliente' });
                }
                if (err.message.includes('token')) {
                    return res.status(400).json({ erro: 'Este token já está em uso por outro cliente' });
                }
            }
            return res.status(500).json({ erro: 'Erro ao editar cliente' });
        }
        
        res.json({ sucesso: true });
    });
});

// Obter dados do cliente para edição
app.get('/admin/cliente/:id', requireAdmin, (req, res) => {
    const clienteId = req.params.id;
    
    db.getClienteById(clienteId, (err, cliente) => {
        if (err) {
            console.error('Erro ao buscar cliente:', err);
            return res.status(500).json({ erro: 'Erro ao buscar cliente' });
        }
        
        if (!cliente) {
            return res.status(404).json({ erro: 'Cliente não encontrado' });
        }
        
        res.json(cliente);
    });
});

// Status da API
app.get('/api/status', (req, res) => {
    res.json({
        whatsapp: isWhatsAppReady,
        grupos: grupos.length,
        timestamp: new Date().toISOString()
    });
});

// Reiniciar WhatsApp (rota admin)
app.post('/admin/restart-whatsapp', requireAdmin, (req, res) => {
    console.log('🔄 Reiniciando WhatsApp por solicitação do admin...');
    
    if (whatsappClient) {
        try {
            whatsappClient.destroy();
        } catch (error) {
            console.log('⚠️ Erro ao destruir cliente anterior:', error.message);
        }
    }
    
    isWhatsAppReady = false;
    grupos = [];
    
    // Aguardar um pouco antes de reiniciar
    setTimeout(() => {
        initWhatsAppBot();
    }, 2000);
    
    res.json({ sucesso: true, mensagem: 'WhatsApp reiniciado' });
});



// Adicione estas rotas ao seu server.js (depois das suas rotas existentes)

// Obter dados do cliente para edição
app.get('/admin/cliente/:id', requireAdmin, (req, res) => {
    const clienteId = req.params.id;
    
    db.getClienteById(clienteId, (err, cliente) => {
        if (err) {
            console.error('Erro ao buscar cliente:', err);
            return res.status(500).json({ erro: 'Erro ao buscar cliente' });
        }
        
        if (!cliente) {
            return res.status(404).json({ erro: 'Cliente não encontrado' });
        }
        
        // Remover dados sensíveis antes de enviar
        const clienteSafe = {
            id: cliente.id,
            nome: cliente.nome,
            telefone: cliente.telefone,
            status: cliente.status,
            created_at: cliente.created_at
        };
        
        res.json(clienteSafe);
    });
});

// Criar cliente (corrigido)
app.post('/admin/cliente/criar', requireAdmin, (req, res) => {
    const { nome, telefone, token } = req.body;
    
    if (!nome || !telefone || !token) {
        return res.status(400).json({ erro: 'Todos os campos são obrigatórios' });
    }

    // Validações básicas
    if (nome.length < 2) {
        return res.status(400).json({ erro: 'Nome deve ter pelo menos 2 caracteres' });
    }

    if (telefone.length < 10) {
        return res.status(400).json({ erro: 'Telefone deve ter pelo menos 10 dígitos' });
    }

    if (token.length < 4) {
        return res.status(400).json({ erro: 'Token deve ter pelo menos 4 caracteres' });
    }

    db.createCliente(nome, telefone, token, function(err) {
        if (err) {
            console.error('Erro ao criar cliente:', err);
            if (err.message && err.message.includes('UNIQUE constraint failed')) {
                if (err.message.includes('telefone')) {
                    return res.status(400).json({ erro: 'Este telefone já está cadastrado' });
                }
                if (err.message.includes('token')) {
                    return res.status(400).json({ erro: 'Este token já está em uso' });
                }
            }
            return res.status(500).json({ erro: 'Erro ao criar cliente' });
        }
        
        res.json({ sucesso: true, id: this.lastID });
    });
});

// Editar cliente (corrigido)
app.post('/admin/cliente/:id/editar', requireAdmin, (req, res) => {
    const clienteId = req.params.id;
    const { nome, telefone, token } = req.body;
    
    if (!nome || !telefone) {
        return res.status(400).json({ erro: 'Nome e telefone são obrigatórios' });
    }

    // Validações básicas
    if (nome.length < 2) {
        return res.status(400).json({ erro: 'Nome deve ter pelo menos 2 caracteres' });
    }

    if (telefone.length < 10) {
        return res.status(400).json({ erro: 'Telefone deve ter pelo menos 10 dígitos' });
    }

    if (token && token.length < 4) {
        return res.status(400).json({ erro: 'Token deve ter pelo menos 4 caracteres' });
    }

    // Se não foi fornecido token, manter o atual
    if (!token || token.trim() === '') {
        // Atualizar apenas nome e telefone
        db.db.run(
            "UPDATE clientes SET nome = ?, telefone = ? WHERE id = ?",
            [nome, telefone, clienteId],
            function(err) {
                if (err) {
                    console.error('Erro ao editar cliente:', err);
                    if (err.message && err.message.includes('UNIQUE constraint failed')) {
                        if (err.message.includes('telefone')) {
                            return res.status(400).json({ erro: 'Este telefone já está cadastrado por outro cliente' });
                        }
                    }
                    return res.status(500).json({ erro: 'Erro ao editar cliente' });
                }
                
                res.json({ sucesso: true });
            }
        );
    } else {
        // Atualizar incluindo novo token
        db.updateCliente(clienteId, nome, telefone, token, (err) => {
            if (err) {
                console.error('Erro ao editar cliente:', err);
                if (err.message && err.message.includes('UNIQUE constraint failed')) {
                    if (err.message.includes('telefone')) {
                        return res.status(400).json({ erro: 'Este telefone já está cadastrado por outro cliente' });
                    }
                    if (err.message.includes('token')) {
                        return res.status(400).json({ erro: 'Este token já está em uso por outro cliente' });
                    }
                }
                return res.status(500).json({ erro: 'Erro ao editar cliente' });
            }
            
            res.json({ sucesso: true });
        });
    }
});

// Bloquear/Desbloquear cliente (se não existir)
app.post('/admin/cliente/:id/toggle', requireAdmin, (req, res) => {
    const clienteId = req.params.id;
    const { status } = req.body;
    
    if (!['ativo', 'bloqueado'].includes(status)) {
        return res.status(400).json({ erro: 'Status inválido' });
    }

    db.updateClienteStatus(clienteId, status, (err) => {
        if (err) {
            console.error('Erro ao atualizar status do cliente:', err);
            return res.status(500).json({ erro: 'Erro ao atualizar status' });
        }
        
        res.json({ sucesso: true });
    });
});

// Verificar se os métodos do banco existem, se não, adicionar:

// Adicionar ao objeto Database (se não existir):
if (!db.getClienteById) {
    db.getClienteById = function(id, callback) {
        this.db.get("SELECT * FROM clientes WHERE id = ?", [id], callback);
    };
}

if (!db.updateCliente) {
    db.updateCliente = function(id, nome, telefone, token, callback) {
        // Implementação simples sem hash (manter compatibilidade)
        this.db.run(
            "UPDATE clientes SET nome = ?, telefone = ?, token = ? WHERE id = ?",
            [nome, telefone, token, id],
            callback
        );
    };
}

// Para debugar, adicione esta rota temporária para testar:
app.get('/debug/cliente/:id', requireAdmin, (req, res) => {
    const clienteId = req.params.id;
    console.log('Debug: Buscando cliente ID:', clienteId);
    
    db.db.get("SELECT * FROM clientes WHERE id = ?", [clienteId], (err, row) => {
        console.log('Debug - Erro:', err);
        console.log('Debug - Resultado:', row);
        
        if (err) {
            return res.json({ erro: err.message, clienteId });
        }
        
        if (!row) {
            return res.json({ erro: 'Cliente não encontrado', clienteId });
        }
        
        res.json({ 
            debug: true, 
            clienteId,
            cliente: {
                id: row.id,
                nome: row.nome,
                telefone: row.telefone,
                status: row.status
            }
        });
    });
});

// ==================== CRIAR TEMPLATES EJS ====================

// Criar diretório views se não existir
if (!fs.existsSync('views')) {
    fs.mkdirSync('views');
}

// Função para salvar templates
function salvarTemplates() {
    // Template de login
    const loginTemplate = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Sistema de Campanhas</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { background: white; padding: 2rem; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); width: 100%; max-width: 400px; }
        .logo { text-align: center; margin-bottom: 2rem; color: #333; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: #555; font-weight: bold; }
        input { width: 100%; padding: 0.75rem; border: 2px solid #ddd; border-radius: 5px; font-size: 1rem; }
        input:focus { outline: none; border-color: #667eea; }
        .btn { width: 100%; padding: 0.75rem; background: #667eea; color: white; border: none; border-radius: 5px; font-size: 1rem; cursor: pointer; transition: background 0.3s; }
        .btn:hover { background: #5a67d8; }
        .erro { background: #fee; color: #c53030; padding: 0.75rem; border-radius: 5px; margin-bottom: 1rem; border: 1px solid #fed7d7; }
        .info { margin-top: 2rem; padding: 1rem; background: #f7fafc; border-radius: 5px; font-size: 0.9rem; color: #4a5568; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🚀 Campanhas WhatsApp</h1>
            <p>Sistema de Disparo Inteligente</p>
        </div>
        
        <% if (erro) { %>
            <div class="erro">❌ <%= erro %></div>
        <% } %>
        
        <form method="POST">
            <div class="form-group">
                <label for="telefone">Telefone:</label>
                <input type="text" id="telefone" name="telefone" placeholder="Ex: 5511999999999" required>
            </div>
            
            <div class="form-group">
                <label for="token">Token:</label>
                <input type="password" id="token" name="token" placeholder="Seu token de acesso" required>
            </div>
            
            <button type="submit" class="btn">Entrar</button>
        </form>
        
        <div class="info">
            <strong>🧪 Credenciais de teste:</strong><br>
            Telefone: <code>5511999999999</code><br>
            Token: <code>teste123</code><br><br>
            <strong>👨‍💻 Admin:</strong><br>
            Telefone: <code>admin</code><br>
            Token: <code>admin123</code><br><br>
            <strong>💡 Nota:</strong><br>
            O sistema funciona mesmo se o WhatsApp não conectar.<br>
            Você pode acessar todos os painéis normalmente!
        </div>
    </div>

    <!-- Modal Criar Cliente -->
    <div id="modalCriarCliente" class="modal" style="display: none;">
        <div class="modal-content">
            <span class="close" onclick="closeModal('modalCriarCliente')">&times;</span>
            <h2>👥 Novo Cliente</h2>
            <form id="formCriarCliente">
                <div class="form-group">
                    <label for="nomeNovo">Nome Completo:</label>
                    <input type="text" id="nomeNovo" name="nome" required placeholder="Ex: João Silva" minlength="2">
                    <small>Mínimo 2 caracteres</small>
                </div>
                
                <div class="form-group">
                    <label for="telefoneNovo">Telefone:</label>
                    <input type="text" id="telefoneNovo" name="telefone" required placeholder="Ex: 5511999999999" minlength="10">
                    <small>Digite apenas números (código do país + DDD + número)</small>
                </div>
                
                <div class="form-group">
                    <label for="tokenNovo">Token de Acesso:</label>
                    <input type="text" id="tokenNovo" name="token" required placeholder="Ex: cliente123" minlength="4">
                    <small>Senha que o cliente usará para fazer login (mínimo 4 caracteres)</small>
                </div>
                
                <div style="margin-top: 1.5rem;">
                    <button type="submit" class="btn btn-success">Criar Cliente</button>
                    <button type="button" class="btn btn-danger" onclick="closeModal('modalCriarCliente')">Cancelar</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Modal Editar Cliente -->
    <div id="modalEditarCliente" class="modal" style="display: none;">
        <div class="modal-content">
            <span class="close" onclick="closeModal('modalEditarCliente')">&times;</span>
            <h2>✏️ Editar Cliente</h2>
            <form id="formEditarCliente">
                <input type="hidden" id="clienteIdEdicao" name="id">
                
                <div class="form-group">
                    <label for="nomeEdicao">Nome Completo:</label>
                    <input type="text" id="nomeEdicao" name="nome" required placeholder="Ex: João Silva" minlength="2">
                    <small>Mínimo 2 caracteres</small>
                </div>
                
                <div class="form-group">
                    <label for="telefoneEdicao">Telefone:</label>
                    <input type="text" id="telefoneEdicao" name="telefone" required placeholder="Ex: 5511999999999" minlength="10">
                    <small>Digite apenas números (código do país + DDD + número)</small>
                </div>
                
                <div class="form-group">
                    <label for="tokenEdicao">Token de Acesso:</label>
                    <input type="text" id="tokenEdicao" name="token" required placeholder="Ex: cliente123" minlength="4">
                    <small>Senha que o cliente usará para fazer login (mínimo 4 caracteres)</small>
                </div>
                
                <div style="margin-top: 1.5rem;">
                    <button type="submit" class="btn btn-success">Salvar Alterações</button>
                    <button type="button" class="btn btn-danger" onclick="closeModal('modalEditarCliente')">Cancelar</button>
                </div>
            </form>
        </div>
    </div>

    <style>
        .modal { 
            display: none; 
            position: fixed; 
            top: 0; 
            left: 0; 
            width: 100%; 
            height: 100%; 
            background: rgba(0,0,0,0.5); 
            z-index: 1000; 
        }
        .modal-content { 
            background: white; 
            margin: 3% auto; 
            padding: 2rem; 
            width: 90%; 
            max-width: 500px; 
            border-radius: 8px; 
            max-height: 85vh; 
            overflow-y: auto; 
            position: relative;
        }
        .close { 
            float: right; 
            font-size: 1.5rem; 
            cursor: pointer; 
            color: #999; 
            line-height: 1;
            margin-bottom: 1rem;
        }
        .close:hover { color: #333; }
        .form-group { 
            margin-bottom: 1rem; 
            clear: both;
        }
        .form-group label { 
            display: block; 
            margin-bottom: 0.5rem; 
            font-weight: bold; 
            color: #2d3748; 
        }
        .form-group input { 
            width: 100%; 
            padding: 0.75rem; 
            border: 2px solid #e2e8f0; 
            border-radius: 4px; 
            font-size: 1rem; 
            transition: border-color 0.3s, box-shadow 0.3s; 
            box-sizing: border-box;
        }
        .form-group input:focus { 
            outline: none; 
            border-color: #4299e1; 
            box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.1); 
        }
        .form-group small { 
            color: #718096; 
            font-size: 0.85rem; 
            margin-top: 0.25rem; 
            display: block; 
        }
        .form-group input.error { 
            border-color: #e53e3e; 
            background-color: #fef5e7; 
        }
        .btn { 
            margin-right: 0.5rem; 
            transition: all 0.3s; 
        }
    </style>
</body>
</html>`;

    // Template do dashboard
    const dashboardTemplate = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - <%= cliente.nome %></title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .header { background: #2d3748; color: white; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .container { padding: 2rem; max-width: 1200px; margin: 0 auto; }
        .status-bar { display: flex; gap: 1rem; margin-bottom: 2rem; }
        .status-card { background: white; padding: 1rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); flex: 1; text-align: center; }
        .status-card.online { border-left: 4px solid #48bb78; }
        .status-card.offline { border-left: 4px solid #f56565; }
        .section { background: white; margin-bottom: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section-header { padding: 1rem 2rem; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center; }
        .section-content { padding: 2rem; }
        .btn { padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9rem; transition: all 0.3s; }
        .btn-primary { background: #4299e1; color: white; }
        .btn-success { background: #48bb78; color: white; }
        .btn-warning { background: #ed8936; color: white; }
        .btn-danger { background: #f56565; color: white; }
        .btn:hover { opacity: 0.8; }
        .table { width: 100%; border-collapse: collapse; }
        .table th, .table td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
        .table th { background: #f7fafc; font-weight: bold; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; font-weight: bold; }
        .form-group input, .form-group textarea { width: 100%; padding: 0.5rem; border: 1px solid #e2e8f0; border-radius: 4px; }
        .form-group textarea { min-height: 100px; resize: vertical; }
        .badge { padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }
        .badge-success { background: #c6f6d5; color: #22543d; }
        .badge-warning { background: #faf0e6; color: #c05621; }
        .badge-danger { background: #fed7d7; color: #c53030; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; }
        .modal-content { background: white; margin: 5% auto; padding: 2rem; width: 90%; max-width: 500px; border-radius: 8px; }
        .close { float: right; font-size: 1.5rem; cursor: pointer; }
        .empty-state { text-align: center; padding: 3rem; color: #718096; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🚀 Dashboard - <%= cliente.nome %></h1>
            <small>Sistema de Campanhas WhatsApp</small>
        </div>
        <div>
            <a href="/logout" style="color: white; text-decoration: none;">Sair</a>
        </div>
    </div>

    <div class="container">
        <div class="status-bar">
            <div class="status-card <%= whatsappStatus ? 'online' : 'offline' %>">
                <h3><%= whatsappStatus ? '🟢' : '🔴' %> WhatsApp</h3>
                <p><%= whatsappStatus ? 'Conectado' : 'Desconectado' %></p>
                <% if (!whatsappStatus) { %>
                    <small style="color: #e53e3e;">Verifique o terminal para QR Code</small>
                <% } %>
            </div>
            <div class="status-card">
                <h3>📱 Grupos</h3>
                <p><%= gruposCount %> grupos ativos</p>
                <% if (!whatsappStatus) { %>
                    <small style="color: #a0aec0;">Aguardando conexão</small>
                <% } %>
            </div>
            <div class="status-card">
                <h3>📊 Campanhas</h3>
                <p><%= campanhas.length %> campanhas criadas</p>
            </div>
        </div>

        <% if (!whatsappStatus) { %>
        <div style="background: #fed7d7; border: 1px solid #fc8181; color: #2d3748; padding: 1rem; border-radius: 8px; margin-bottom: 2rem;">
            <h3 style="margin-bottom: 0.5rem;">⚠️ WhatsApp Desconectado</h3>
            <p>O bot do WhatsApp não está conectado. Para usar as campanhas:</p>
            <ul style="margin: 0.5rem 0; padding-left: 1.5rem;">
                <li>Verifique se há um QR Code no terminal</li>
                <li>Escaneie o QR Code com seu WhatsApp</li>
                <li>Aguarde a mensagem de "conectado e pronto"</li>
                <li>Recarregue esta página</li>
            </ul>
            <p><strong>Dica:</strong> Se não aparecer QR Code, verifique sua conexão com a internet.</p>
        </div>
        <% } %>

        <div class="section">
            <div class="section-header">
                <h2>📢 Minhas Campanhas</h2>
                <button class="btn btn-primary" onclick="openModal('modalCampanha')">+ Nova Campanha</button>
            </div>
            <div class="section-content">
                <% if (campanhas.length === 0) { %>
                    <div class="empty-state">
                        <h3>📝 Nenhuma campanha criada</h3>
                        <p>Crie sua primeira campanha para começar a enviar mensagens!</p>
                        <button class="btn btn-primary" onclick="openModal('modalCampanha')">Criar Primeira Campanha</button>
                    </div>
                <% } else { %>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Título</th>
                                <th>Status</th>
                                <th>Intervalo</th>
                                <th>Último Disparo</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            <% campanhas.forEach(campanha => { %>
                                <tr>
                                    <td>
                                        <strong><%= campanha.titulo %></strong><br>
                                        <small><%= campanha.mensagem.substring(0, 50) %>...</small>
                                    </td>
                                    <td>
                                        <span class="badge <%= campanha.status === 'ativa' ? 'badge-success' : 'badge-warning' %>">
                                            <%= campanha.status === 'ativa' ? '✅ Ativa' : '⏸️ Pausada' %>
                                        </span>
                                    </td>
                                    <td><%= campanha.intervalo_minutos %> min</td>
                                    <td>
                                        <%= campanha.ultimo_disparo ? 
                                            new Date(campanha.ultimo_disparo).toLocaleString('pt-BR') : 
                                            'Nunca' %>
                                    </td>
                                    <td>
                                        <button class="btn <%= campanha.status === 'ativa' ? 'btn-warning' : 'btn-success' %>" 
                                                onclick="toggleCampanha(<%= campanha.id %>, '<%= campanha.status === 'ativa' ? 'pausada' : 'ativa' %>')">
                                            <%= campanha.status === 'ativa' ? 'Pausar' : 'Ativar' %>
                                        </button>
                                        <button class="btn btn-primary" onclick="dispararCampanha(<%= campanha.id %>)">
                                            🚀 Disparar Agora
                                        </button>
                                    </td>
                                </tr>
                            <% }); %>
                        </tbody>
                    </table>
                <% } %>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>📋 Histórico de Envios</h2>
                <button class="btn btn-primary" onclick="location.reload()">🔄 Atualizar</button>
            </div>
            <div class="section-content">
                <% if (logs.length === 0) { %>
                    <div class="empty-state">
                        <h3>📊 Nenhum envio registrado</h3>
                        <p>Os logs de envio aparecerão aqui após os primeiros disparos.</p>
                    </div>
                <% } else { %>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Data/Hora</th>
                                <th>Campanha</th>
                                <th>Grupo</th>
                                <th>Status</th>
                                <th>Erro</th>
                            </tr>
                        </thead>
                        <tbody>
                            <% logs.forEach(log => { %>
                                <tr>
                                    <td><%= new Date(log.data_envio).toLocaleString('pt-BR') %></td>
                                    <td><%= log.campanha_titulo %></td>
                                    <td><%= log.grupo %></td>
                                    <td>
                                        <span class="badge <%= log.status === 'enviado' ? 'badge-success' : 'badge-danger' %>">
                                            <%= log.status === 'enviado' ? '✅ Enviado' : '❌ Erro' %>
                                        </span>
                                    </td>
                                    <td><%= log.erro || '-' %></td>
                                </tr>
                            <% }); %>
                        </tbody>
                    </table>
                <% } %>
            </div>
        </div>
    </div>

    <div id="modalCampanha" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('modalCampanha')">&times;</span>
            <h2>📢 Nova Campanha</h2>
            <form id="formCampanha">
                <div class="form-group">
                    <label for="titulo">Título da Campanha:</label>
                    <input type="text" id="titulo" name="titulo" required placeholder="Ex: Promoção de Natal">
                </div>
                
                <div class="form-group">
                    <label for="mensagem">Mensagem:</label>
                    <textarea id="mensagem" name="mensagem" required placeholder="Digite sua mensagem aqui...

Use os placeholders:
{{cliente}} - Nome do cliente
{{data}} - Data atual
{{hora}} - Hora atual"></textarea>
                </div>
                
                <div class="form-group">
                    <label for="intervalo">Intervalo entre disparos (minutos):</label>
                    <input type="number" id="intervalo" name="intervalo" min="1" value="60" required>
                </div>
                
                <div style="margin-top: 1rem;">
                    <button type="submit" class="btn btn-success">Criar Campanha</button>
                    <button type="button" class="btn btn-danger" onclick="closeModal('modalCampanha')">Cancelar</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function openModal(modalId) {
            document.getElementById(modalId).style.display = 'block';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        document.getElementById('formCampanha').addEventListener('submit', function(e) {
            e.preventDefault();
            
            var formData = new FormData(e.target);
            var data = {};
            formData.forEach(function(value, key) {
                data[key] = value;
            });
            
            fetch('/campanha/criar', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.sucesso) {
                    alert('✅ Campanha criada com sucesso!');
                    location.reload();
                } else {
                    alert('❌ Erro: ' + result.erro);
                }
            })
            .catch(function(error) {
                alert('❌ Erro ao criar campanha: ' + error.message);
            });
        });

        function toggleCampanha(id, novoStatus) {
            fetch('/campanha/' + id + '/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: novoStatus })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.sucesso) {
                    alert('✅ Campanha ' + (novoStatus === 'ativa' ? 'ativada' : 'pausada') + ' com sucesso!');
                    location.reload();
                } else {
                    alert('❌ Erro: ' + result.erro);
                }
            })
            .catch(function(error) {
                alert('❌ Erro ao alterar status: ' + error.message);
            });
        }

        function dispararCampanha(id) {
            // Verificar se WhatsApp está conectado
            fetch('/api/status')
                .then(function(response) { return response.json(); })
                .then(function(status) {
                    if (!status.whatsapp) {
                        alert('❌ WhatsApp não está conectado!\\n\\nPara disparar campanhas:\\n1. Verifique o QR Code no terminal\\n2. Escaneie com seu WhatsApp\\n3. Aguarde a conexão\\n4. Tente novamente');
                        return;
                    }
                    
                    if (!confirm('🚀 Confirma o disparo imediato desta campanha para todos os grupos?')) {
                        return;
                    }
                    
                    fetch('/campanha/' + id + '/disparar', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    })
                    .then(function(response) { return response.json(); })
                    .then(function(result) {
                        alert('📊 Disparo concluído!\\n\\n✅ Sucessos: ' + result.sucesso + '\\n❌ Erros: ' + result.erro + '\\n\\nDetalhes: ' + result.detalhes);
                        setTimeout(function() { location.reload(); }, 2000);
                    })
                    .catch(function(error) {
                        alert('❌ Erro ao disparar campanha: ' + error.message);
                    });
                })
                .catch(function(error) {
                    alert('❌ Erro ao verificar status: ' + error.message);
                });
        }

        window.onclick = function(event) {
            var modals = document.querySelectorAll('.modal');
            for (var i = 0; i < modals.length; i++) {
                if (event.target === modals[i]) {
                    modals[i].style.display = 'none';
                }
            }
        }
    </script>
</body>
</html>`;

    // Template do admin
    const adminTemplate = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel Administrativo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .header { background: #1a202c; color: white; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .container { padding: 2rem; max-width: 1400px; margin: 0 auto; }
        .status-bar { display: flex; gap: 1rem; margin-bottom: 2rem; }
        .status-card { background: white; padding: 1rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); flex: 1; text-align: center; }
        .status-card.online { border-left: 4px solid #48bb78; }
        .status-card.offline { border-left: 4px solid #f56565; }
        .section { background: white; margin-bottom: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section-header { padding: 1rem 2rem; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center; background: #f7fafc; }
        .section-content { padding: 2rem; }
        .btn { padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9rem; transition: all 0.3s; margin: 0 0.25rem; }
        .btn-primary { background: #4299e1; color: white; }
        .btn-success { background: #48bb78; color: white; }
        .btn-warning { background: #ed8936; color: white; }
        .btn-danger { background: #f56565; color: white; }
        .btn:hover { opacity: 0.8; }
        .table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        .table th, .table td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
        .table th { background: #f7fafc; font-weight: bold; }
        .badge { padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }
        .badge-success { background: #c6f6d5; color: #22543d; }
        .badge-warning { background: #faf0e6; color: #c05621; }
        .badge-danger { background: #fed7d7; color: #c53030; }
        .badge-info { background: #bee3f8; color: #2c5282; }
        .empty-state { text-align: center; padding: 3rem; color: #718096; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2rem; font-weight: bold; color: #2d3748; }
        .stat-label { color: #718096; margin-top: 0.5rem; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>👨‍💻 Painel Administrativo</h1>
            <small>Gerenciar Sistema de Campanhas</small>
        </div>
        <div>
            <a href="/logout" style="color: white; text-decoration: none;">Sair</a>
        </div>
    </div>

    <div class="container">
        <div class="status-bar">
            <div class="status-card <%= whatsappStatus ? 'online' : 'offline' %>">
                <h3><%= whatsappStatus ? '🟢' : '🔴' %> WhatsApp Bot</h3>
                <p><%= whatsappStatus ? 'Conectado e Operacional' : 'Desconectado' %></p>
                <% if (!whatsappStatus) { %>
                    <button class="btn btn-warning" onclick="restartWhatsApp()" style="margin-top: 0.5rem;">🔄 Reiniciar</button>
                <% } %>
            </div>
            <div class="status-card">
                <h3>📱 Grupos WhatsApp</h3>
                <p><%= gruposCount %> grupos monitorados</p>
                <% if (!whatsappStatus) { %>
                    <small style="color: #e53e3e;">Aguardando conexão</small>
                <% } %>
            </div>
            <div class="status-card">
                <h3>👥 Clientes Ativos</h3>
                <p><%= clientes.filter(c => c.status === 'ativo').length %> de <%= clientes.length %></p>
            </div>
            <div class="status-card" style="background: #e6fffa; border-left: 4px solid #38b2ac;">
                <h3>🔧 Modo Teste</h3>
                <p>Sistema de edição ativo</p>
                <small style="color: #2c7a7b;">Clique em "✏️ Editar" para testar</small>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number"><%= clientes.length %></div>
                <div class="stat-label">Total de Clientes</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><%= logs.filter(l => l.status === 'enviado').length %></div>
                <div class="stat-label">Mensagens Enviadas</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><%= logs.filter(l => l.status === 'erro').length %></div>
                <div class="stat-label">Erros de Envio</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><%= logs.length %></div>
                <div class="stat-label">Total de Logs</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>👥 Gerenciar Clientes</h2>
                <div>
                    <button class="btn btn-success" onclick="criarModalNovoCliente()">+ Novo Cliente</button>
                    <button class="btn btn-primary" onclick="location.reload()">🔄 Atualizar</button>
                </div>
            </div>
            <div class="section-content">
                <% if (clientes.length === 0) { %>
                    <div class="empty-state">
                        <h3>👥 Nenhum cliente cadastrado</h3>
                        <p>Os clientes aparecerão aqui conforme se cadastrarem no sistema.</p>
                        <button class="btn btn-success" onclick="criarModalNovoCliente()">Cadastrar Primeiro Cliente</button>
                    </div>
                <% } else { %>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Nome</th>
                                <th>Telefone</th>
                                <th>Token</th>
                                <th>Status</th>
                                <th>Cadastro</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            <% clientes.forEach(cliente => { %>
                                <tr>
                                    <td><%= cliente.id %></td>
                                    <td><strong><%= cliente.nome %></strong></td>
                                    <td><%= cliente.telefone %></td>
                                    <td><code><%= cliente.token %></code></td>
                                    <td>
                                        <% if (cliente.telefone === 'admin') { %>
                                            <span class="badge badge-info">🔧 Admin</span>
                                        <% } else { %>
                                            <span class="badge <%= cliente.status === 'ativo' ? 'badge-success' : 'badge-danger' %>">
                                                <%= cliente.status === 'ativo' ? '✅ Ativo' : '🚫 Bloqueado' %>
                                            </span>
                                        <% } %>
                                    </td>
                                    <td><%= new Date(cliente.created_at).toLocaleDateString('pt-BR') %></td>
                                    <td>
                                        <% if (cliente.telefone !== 'admin') { %>
                                            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                                                <button class="btn btn-warning" onclick="editarCliente(<%= cliente.id %>)" 
                                                        title="Editar dados do cliente"
                                                        style="background: #f6ad55; border: 2px solid #ed8936; font-weight: bold;">
                                                    ✏️ Editar
                                                </button>
                                                <button class="btn <%= cliente.status === 'ativo' ? 'btn-danger' : 'btn-success' %>" 
                                                        onclick="toggleCliente(<%= cliente.id %>, '<%= cliente.status === 'ativo' ? 'bloqueado' : 'ativo' %>')"
                                                        title="<%= cliente.status === 'ativo' ? 'Bloquear cliente' : 'Ativar cliente' %>">
                                                    <%= cliente.status === 'ativo' ? '🚫 Bloquear' : '✅ Ativar' %>
                                                </button>
                                            </div>
                                        <% } else { %>
                                            <span class="badge badge-info">🔧 Sistema</span>
                                        <% } %>
                                    </td>
                                </tr>
                            <% }); %>
                        </tbody>
                    </table>
                <% } %>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>📊 Logs do Sistema</h2>
                <button class="btn btn-primary" onclick="location.reload()">🔄 Atualizar</button>
            </div>
            <div class="section-content">
                <% if (logs.length === 0) { %>
                    <div class="empty-state">
                        <h3>📊 Nenhum log registrado</h3>
                        <p>Os logs de atividade do sistema aparecerão aqui.</p>
                    </div>
                <% } else { %>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Data/Hora</th>
                                <th>Cliente</th>
                                <th>Campanha</th>
                                <th>Grupo</th>
                                <th>Status</th>
                                <th>Erro</th>
                            </tr>
                        </thead>
                        <tbody>
                            <% logs.slice(0, 50).forEach(log => { %>
                                <tr>
                                    <td><%= new Date(log.data_envio).toLocaleString('pt-BR') %></td>
                                    <td><%= log.cliente_nome %></td>
                                    <td><%= log.campanha_titulo %></td>
                                    <td><%= log.grupo %></td>
                                    <td>
                                        <span class="badge <%= log.status === 'enviado' ? 'badge-success' : 'badge-danger' %>">
                                            <%= log.status === 'enviado' ? '✅ Enviado' : '❌ Erro' %>
                                        </span>
                                    </td>
                                    <td>
                                        <% if (log.erro) { %>
                                            <small style="color: #e53e3e;"><%= log.erro.substring(0, 50) %>...</small>
                                        <% } else { %>
                                            -
                                        <% } %>
                                    </td>
                                </tr>
                            <% }); %>
                        </tbody>
                    </table>
                    <% if (logs.length > 50) { %>
                        <p style="text-align: center; margin-top: 1rem; color: #718096;">
                            Mostrando os 50 logs mais recentes de <%= logs.length %> total
                        </p>
                    <% } %>
                <% } %>
            </div>
        </div>
    </div>

    <script>
        function openModal(modalId) {
            document.getElementById(modalId).style.display = 'block';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
            // Limpar formulários ao fechar
            if (modalId === 'modalCriarCliente') {
                document.getElementById('formCriarCliente').reset();
            }
            if (modalId === 'modalEditarCliente') {
                document.getElementById('formEditarCliente').reset();
            }
        }

        function toggleCliente(id, novoStatus) {
            if (!confirm('Confirma ' + (novoStatus === 'ativo' ? 'ativar' : 'bloquear') + ' este cliente?')) {
                return;
            }
            
            fetch('/admin/cliente/' + id + '/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: novoStatus })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.sucesso) {
                    alert('✅ Cliente ' + (novoStatus === 'ativo' ? 'ativado' : 'bloqueado') + ' com sucesso!');
                    location.reload();
                } else {
                    alert('❌ Erro: ' + result.erro);
                }
            })
            .catch(function(error) {
                alert('❌ Erro ao alterar status: ' + error.message);
            });
        }

        function restartWhatsApp() {
            if (!confirm('🔄 Confirma o reinício do WhatsApp Bot?\\n\\nIsso pode levar alguns minutos...')) {
                return;
            }
            
            fetch('/admin/restart-whatsapp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.sucesso) {
                    alert('✅ WhatsApp reiniciado!\\n\\nVerifique o terminal para o QR Code.\\nA página será atualizada em 10 segundos.');
                    setTimeout(function() { location.reload(); }, 10000);
                } else {
                    alert('❌ Erro ao reiniciar: ' + (result.erro || 'Erro desconhecido'));
                }
            })
            .catch(function(error) {
                alert('❌ Erro ao reiniciar WhatsApp: ' + error.message);
            });
        }

        function editarCliente(id) {
            // Buscar dados do cliente
            fetch('/admin/cliente/' + id)
            .then(function(response) { return response.json(); })
            .then(function(cliente) {
                if (cliente.erro) {
                    alert('❌ Erro: ' + cliente.erro);
                    return;
                }
                
                // Preencher formulário de edição
                document.getElementById('clienteIdEdicao').value = cliente.id;
                document.getElementById('nomeEdicao').value = cliente.nome;
                document.getElementById('telefoneEdicao').value = cliente.telefone;
                document.getElementById('tokenEdicao').value = cliente.token;
                
                // Abrir modal
                openModal('modalEditarCliente');
            })
            .catch(function(error) {
                alert('❌ Erro ao buscar dados do cliente: ' + error.message);
            });
        }

        // Formulário de criar cliente
        document.getElementById('formCriarCliente').addEventListener('submit', function(e) {
            e.preventDefault();
            
            var formData = new FormData(e.target);
            var data = {};
            formData.forEach(function(value, key) {
                data[key] = value.trim();
            });
            
            // Validações adicionais no frontend
            if (data.nome.length < 2) {
                alert('❌ Nome deve ter pelo menos 2 caracteres');
                return;
            }
            
            if (data.telefone.length < 10) {
                alert('❌ Telefone deve ter pelo menos 10 dígitos');
                return;
            }
            
            if (data.token.length < 4) {
                alert('❌ Token deve ter pelo menos 4 caracteres');
                return;
            }
            
            fetch('/admin/cliente/criar', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.sucesso) {
                    alert('✅ Cliente criado com sucesso!');
                    closeModal('modalCriarCliente');
                    location.reload();
                } else {
                    alert('❌ Erro: ' + result.erro);
                }
            })
            .catch(function(error) {
                alert('❌ Erro ao criar cliente: ' + error.message);
            });
        });

        // Formulário de editar cliente
        document.getElementById('formEditarCliente').addEventListener('submit', function(e) {
            e.preventDefault();
            
            var formData = new FormData(e.target);
            var data = {};
            formData.forEach(function(value, key) {
                data[key] = value.trim();
            });
            
            var clienteId = data.id;
            
            // Validações adicionais no frontend
            if (data.nome.length < 2) {
                alert('❌ Nome deve ter pelo menos 2 caracteres');
                return;
            }
            
            if (data.telefone.length < 10) {
                alert('❌ Telefone deve ter pelo menos 10 dígitos');
                return;
            }
            
            if (data.token.length < 4) {
                alert('❌ Token deve ter pelo menos 4 caracteres');
                return;
            }
            
            fetch('/admin/cliente/' + clienteId + '/editar', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.sucesso) {
                    alert('✅ Cliente editado com sucesso!');
                    closeModal('modalEditarCliente');
                    location.reload();
                } else {
                    alert('❌ Erro: ' + result.erro);
                }
            })
            .catch(function(error) {
                alert('❌ Erro ao editar cliente: ' + error.message);
            });
        });

        // Fechar modal clicando fora
        window.onclick = function(event) {
            var modals = document.querySelectorAll('.modal');
            for (var i = 0; i < modals.length; i++) {
                if (event.target === modals[i]) {
                    modals[i].style.display = 'none';
                }
            }
        }

        // Máscara para telefone (apenas números)
        function setupTelefoneValidation(inputId) {
            document.getElementById(inputId).addEventListener('input', function(e) {
                e.target.value = e.target.value.replace(/[^0-9]/g, '');
                
                // Validação visual em tempo real
                if (e.target.value.length < 10) {
                    e.target.classList.add('error');
                } else {
                    e.target.classList.remove('error');
                }
            });
        }

        function setupTokenValidation(inputId) {
            document.getElementById(inputId).addEventListener('input', function(e) {
                // Validação visual em tempo real
                if (e.target.value.length < 4) {
                    e.target.classList.add('error');
                } else {
                    e.target.classList.remove('error');
                }
            });
        }

        function setupNomeValidation(inputId) {
            document.getElementById(inputId).addEventListener('input', function(e) {
                // Validação visual em tempo real
                if (e.target.value.length < 2) {
                    e.target.classList.add('error');
                } else {
                    e.target.classList.remove('error');
                }
            });
        }

        // Configurar validações quando a página carregar
        document.addEventListener('DOMContentLoaded', function() {
            setupTelefoneValidation('telefoneNovo');
            setupTelefoneValidation('telefoneEdicao');
            setupTokenValidation('tokenNovo');
            setupTokenValidation('tokenEdicao');
            setupNomeValidation('nomeNovo');
            setupNomeValidation('nomeEdicao');
        });
    </script>
</body>
</html>`;

    // Salvar templates
    fs.writeFileSync('views/login.ejs', loginTemplate);
    fs.writeFileSync('views/dashboard.ejs', dashboardTemplate);
    fs.writeFileSync('views/admin.ejs', adminTemplate);
    
    console.log('📄 Templates EJS criados com sucesso!');
}

// ==================== INICIALIZAÇÃO ====================

console.log('🚀 Iniciando Sistema de Campanhas WhatsApp...');

// Criar templates
salvarTemplates();

// Inicializar WhatsApp Bot
initWhatsAppBot();

// Inicializar agendador
iniciarAgendador();

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`🌐 Servidor rodando em http://localhost:${PORT}`);
    console.log('📋 Credenciais padrão:');
    console.log('   Cliente: telefone=5511999999999, token=teste123');
    console.log('   Admin: telefone=admin, token=admin123');
    console.log('💡 Acesse /login para começar');
    console.log('');
    console.log('⚠️  IMPORTANTE sobre o WhatsApp:');
    console.log('   • Se aparecer erro de conexão, o sistema continua funcionando');
    console.log('   • Acesse o painel admin mesmo sem WhatsApp conectado');
    console.log('   • Use o botão "Reiniciar" no painel para tentar reconectar');
    console.log('   • Campanhas só funcionam com WhatsApp conectado');
    console.log('');
});