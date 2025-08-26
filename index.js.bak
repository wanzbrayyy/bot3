const TelegramBot = require('node-telegram-bot-api');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const chalk = require('chalk').default;
const figlet = require('figlet');
const os = require('os');
const { exec } = require('child_process');
const mongoose = require('mongoose');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

const config = require('./config');
const Group = require('./models/group');
const User = require('./models/user');
const WebUser = require('./models/webUser');

console.log(chalk.red(figlet.textSync('ＲＥＤ BOT', { horizontalLayout: 'full' })));

const profilePicPath = path.join(__dirname, 'wanz', 'profile.jpg');
const PROMO_KEYWORDS_REGEX = /\b(sewa|need|buy|banned|beli|jual|promo|murah|userbot|qris|payment|order|diskon|termurah|butuh|akun|linkaja|dana)\b/i;
const LINK_REGEX = /(https?:\/\/[^\s]+)|(t\.me\/)/i;
const registrationTokens = new Map();
const loginStates = new Map();
const webLoginTokens = new Map();

if (!fs.existsSync(profilePicPath)) {
    console.error(chalk.red.bold('[Error] Gambar profil tidak ditemukan di path:'), profilePicPath);
    process.exit(1);
}

mongoose.connect(config.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', (err) => console.error(chalk.red.bold('[MongoDB] Connection Error:'), err));
db.once('open', () => console.log(chalk.green.bold('[MongoDB] Connected successfully')));

const app = express();
const port = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: config.mongoURI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

const authMiddleware = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
};

app.get('/', (req, res) => res.render('index', { title: 'Home' }));
app.get('/login', (req, res) => res.render('login', { title: 'Login', error: null }));
app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

app.post('/login', async (req, res) => {
    try {
        const { telegramUsername, password } = req.body;
        const user = await WebUser.findOne({ telegramUsername: telegramUsername });
        if (user && (await user.matchPassword(password))) {
            req.session.user = { id: user._id, telegramUsername: user.telegramUsername, telegramId: user.telegramId };
            res.redirect('/dashboard');
        } else {
            res.render('login', { title: 'Login', error: 'Username atau password salah' });
        }
    } catch (error) {
        res.render('login', { title: 'Login', error: 'Terjadi kesalahan server' });
    }
});

app.get('/daftar', (req, res) => {
    const { token } = req.query;
    if (registrationTokens.has(token)) {
        const { telegramId, telegramUsername } = registrationTokens.get(token);
        res.render('daftar', { title: 'Daftar', token, telegramId, telegramUsername, error: null });
    } else {
        res.status(400).send('<h1>Token Pendaftaran Tidak Valid atau Kedaluwarsa</h1>');
    }
});

app.post('/daftar', async (req, res) => {
    const { token, password, telegramUsername } = req.body;
    if (registrationTokens.has(token)) {
        const { telegramId } = registrationTokens.get(token);
        try {
            const existingUser = await WebUser.findOne({ telegramId });
            if (existingUser) {
                return res.render('daftar', { title: 'Daftar', token, telegramId, telegramUsername, error: 'Akun Telegram ini sudah terdaftar' });
            }
            await WebUser.create({ telegramId, telegramUsername, password });
            registrationTokens.delete(token);
            res.redirect('/login');
        } catch (error) {
            res.render('daftar', { title: 'Daftar', token, telegramId, telegramUsername, error: 'Gagal membuat akun' });
        }
    } else {
        res.status(400).send('<h1>Token Pendaftaran Tidak Valid atau Kedaluwarsa</h1>');
    }
});

app.get('/dashboard', authMiddleware, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalGroups = await Group.countDocuments();
        const uptime = process.uptime() / 3600;
        res.render('dashboard', { title: 'Dashboard', stats: { totalUsers, totalGroups, uptime } });
    } catch (error) {
        res.status(500).send('Error memuat data dashboard');
    }
});

app.get('/auth/bot-login', (req, res) => {
    const { token } = req.query;
    if (webLoginTokens.has(token)) {
        const userData = webLoginTokens.get(token);
        req.session.user = { id: userData.userId, telegramUsername: userData.telegramUsername, telegramId: userData.telegramId };
        webLoginTokens.delete(token);
        res.redirect('/dashboard');
    } else {
        res.status(401).send('<h1>Link login tidak valid atau sudah kedaluwarsa.</h1>');
    }
});

const bot = new TelegramBot(config.telegramToken, { polling: true });
bot.on('polling_error', (error) => {
    console.error(chalk.red.bold(`[Polling Error] Code: ${error.code} | Message: ${error.message}`));
});

let pkg = {};
try {
  pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
} catch (e) { console.error(chalk.red('[Error] Gagal membaca package.json:'), e); }

function formatInfoBot() {
  let deps = Object.keys(pkg.dependencies || {}).map(d => `🔹 ${d}: ${pkg.dependencies[d]}`).join('\n');
  return `
<b>🤖 Nama Bot:</b> ${config.botName}
<b>📌 Versi Bot:</b> ${pkg.version || '1.0.0'}
<b>🛠 Node.js:</b> ${process.version}
<b>💻 Platform:</b> ${os.type()} ${os.release()} (${os.arch()})
<b>📦 Dependencies:</b>
${deps || '-'}
`;
}

function mainMenu() {
  return {
    reply_markup: {
      inline_keyboard: [
        [{ text: 'ℹ️ Info Bot', callback_data: 'info_bot' }, { text: '👤 Owner', callback_data: 'owner' }],
        [{ text: '📖 Bantuan', callback_data: 'help' }, { text: '⚙️ System', callback_data: 'sys_info' }],
        [{ text: '🎮 Hiburan', callback_data: 'entertainment' }],
        [{ text: '❌ Tutup', callback_data: 'close' }]
      ]
    },
    parse_mode: 'HTML'
  };
}

const getAdmins = async (chatId) => {
    try {
        const admins = await bot.getChatAdministrators(chatId);
        return admins.map(admin => admin.user.id);
    } catch (error) {
        console.error(chalk.red(`[Error] Gagal mendapatkan admin untuk chat ${chatId}:`), error.message);
        return [];
    }
};

bot.onText(/\/start/, async (msg) => {
  console.log(chalk.green(`[Command] /start dari ${msg.from.id} di chat ${msg.chat.id}`));
  const teks = `
👋 Halo <b>${msg.from.first_name}</b>, 
Selamat datang di bot <b>${config.botName}</b>!
Pilih menu dibawah untuk eksplorasi atau ketik /register untuk mendaftar ke dashboard web.
`;
  await bot.sendPhoto(msg.chat.id, profilePicPath, {
      caption: teks,
      ...mainMenu()
  });
});

bot.onText(/\/register/, async (msg) => {
    const user = await WebUser.findOne({ telegramId: msg.from.id.toString() });
    if (user) {
        return bot.sendMessage(msg.chat.id, "Anda sudah terdaftar di website.");
    }
    const token = uuidv4();
    registrationTokens.set(token, { telegramId: msg.from.id.toString(), telegramUsername: msg.from.username });
    setTimeout(() => registrationTokens.delete(token), 1000 * 60 * 10);

    const link = `${config.webBaseUrl}/daftar?token=${token}`;
    bot.sendMessage(msg.chat.id, `Klik link ini untuk menyelesaikan pendaftaran di website:\n\n${link}\n\nLink ini hanya valid selama 10 menit.`, { disable_web_page_preview: true });
});

bot.onText(/\/login/, async (msg) => {
    if (msg.chat.type !== 'private') {
        return bot.sendMessage(msg.chat.id, "Perintah login hanya bisa digunakan di chat pribadi dengan bot.");
    }
    loginStates.set(msg.from.id, { step: 'awaiting_username' });
    bot.sendMessage(msg.chat.id, "Silakan masukkan username Telegram Anda.");
});

bot.on('callback_query', async (query) => {
  const chatId = query.message.chat.id;
  const messageId = query.message.message_id;
  const data = query.data;
  console.log(chalk.blue(`[Callback] Menerima data "${data}" dari ${query.from.id}`));

  try {
    switch (data) {
      case 'info_bot':
        await bot.editMessageCaption(formatInfoBot(), { chat_id: chatId, message_id: messageId, parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '🔙 Kembali', callback_data: 'back' }]] } });
        break;
      case 'owner':
        await bot.editMessageCaption(`👑 <b>Owner Bot</b>\nID: <code>${config.ownerId}</code>\nUsername: @wanzofc`, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '🔙 Kembali', callback_data: 'back' }]] } });
        break;
      case 'help':
        const helpText = `📖 <b>Panduan Bot</b>\n\n<b>Admin Grup:</b>\n/warn [on/off] - Mengaktifkan auto-moderasi\n/ban [reply] - Mute pengguna manual\n/unban [reply] - Unmute pengguna\n/del [reply] - Hapus pesan\n/setwelcome [pesan]\n/setgoodbye [pesan]\n\n<b>Pengguna:</b>\n/start\n/ping\n/rank\n/register\n/login`;
        await bot.editMessageCaption(helpText, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '🔙 Kembali', callback_data: 'back' }]] } });
        break;
      case 'sys_info':
        const cpus = os.cpus();
        const cpuModel = cpus && cpus.length > 0 ? cpus[0].model : 'Unknown CPU';
        await bot.editMessageCaption(`<b>⚙️ System Info</b>\nOS: ${os.type()}\nArch: ${os.arch()}\nCPU: ${cpuModel.trim()}\nRAM: ${(os.totalmem() / 1e9).toFixed(2)} GB\nUptime: ${(os.uptime() / 3600).toFixed(2)} jam`, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '🔙 Kembali', callback_data: 'back' }]] } });
        break;
      case 'entertainment':
        await bot.editMessageCaption('🎮 <b>Menu Hiburan</b>\nPilih salah satu:', { chat_id: chatId, message_id: messageId, parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '📜 Quote Acak', callback_data: 'get_quote' }], [{ text: '🔙 Kembali', callback_data: 'back' }]] } });
        break;
      case 'get_quote':
        const response = await axios.get('https://api.quotable.io/random');
        const quote = `"${response.data.content}"\n\n- <b>${response.data.author}</b>`;
        await bot.editMessageCaption(quote, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '📜 Lagi', callback_data: 'get_quote' }], [{ text: '🔙 Kembali', callback_data: 'entertainment' }]] }});
        break;
      case 'back':
        const backText = `
👋 Halo <b>${query.from.first_name}</b>, 
Selamat datang di bot <b>${config.botName}</b>!
`;
        await bot.editMessageCaption(backText, { chat_id: chatId, message_id: messageId, ...mainMenu() });
        break;
      case 'close':
        await bot.deleteMessage(chatId, messageId).catch(() => {});
        break;
      default:
        if (data.startsWith('verify_')) {
          const userIdToVerify = data.split('_')[1];
          if (query.from.id.toString() === userIdToVerify) {
            await User.updateOne({ userId: userIdToVerify, chatId }, { verified: true });
            await bot.answerCallbackQuery(query.id, { text: '✅ Verifikasi berhasil!' });
            await bot.deleteMessage(chatId, messageId).catch(() => {});
            await bot.sendMessage(chatId, `✅ <b>${query.from.first_name}</b>, verifikasi berhasil. Selamat bergabung!`, { parse_mode: 'HTML' });
            clearTimeout(verifyTimers[userIdToVerify]);
            delete verifyTimers[userIdToVerify];
          } else {
            await bot.answerCallbackQuery(query.id, { text: '⚠️ Tombol ini bukan untuk Anda.', show_alert: true });
          }
        } else {
          await bot.answerCallbackQuery(query.id, { text: 'Menu tidak dikenal!' });
        }
        break;
    }
  } catch (error) {
    console.error(chalk.red(`[Error] Gagal memproses callback "${data}":`), error.message || error);
  }
});

const handleAutoViolation = async (chatId, targetUser, reason) => {
    try {
        const user = await User.findOneAndUpdate({ userId: targetUser.id, chatId: chatId }, { $inc: { strikeCount: 1 } }, { upsert: true, new: true });
        if (user.strikeCount < 3) {
            await bot.sendMessage(chatId, `⚠️ <b>PERINGATAN OTOMATIS</b> ⚠️\n\nPengguna: <b>${targetUser.first_name}</b>\nPelanggaran: ${reason}\n\nAnda mendapat peringatan <b>${user.strikeCount}/3</b>.`, { parse_mode: 'HTML' });
        } else {
            const updatedUser = await User.findOneAndUpdate({ userId: targetUser.id, chatId: chatId }, { $set: { strikeCount: 0 }, $inc: { muteTier: 1 } }, { new: true });
            const tier = updatedUser.muteTier;
            let durationText = '', untilDate = 0;
            const nowInSeconds = Math.floor(Date.now() / 1000);
            if (tier === 1) { durationText = '5 menit'; untilDate = nowInSeconds + (5 * 60); }
            else if (tier === 2) { durationText = '1 jam'; untilDate = nowInSeconds + (60 * 60); }
            else if (tier === 3) { durationText = '1 hari'; untilDate = nowInSeconds + (24 * 60 * 60); }
            else { durationText = 'permanen'; untilDate = 0; }
            await bot.restrictChatMember(chatId, targetUser.id, { until_date: untilDate, can_send_messages: false });
            await bot.sendMessage(chatId, `🚔 <b>SANKSI OTOMATIS</b> 🚔\n\nPengguna: <b>${targetUser.first_name}</b>\nSanksi: Di-mute selama <b>${durationText}</b>.`, { parse_mode: 'HTML' });
        }
    } catch (e) {
        console.error(chalk.red.bold(`[Error] Gagal auto-moderasi user ${targetUser.id}:`), e.message);
    }
};

bot.on('message', async (msg) => {
    const chatId = msg.chat.id;
    const userId = msg.from.id;
    const text = msg.text || '';

    if (!msg.from || !msg.chat || msg.from.is_bot) return;

    const loginState = loginStates.get(userId);
    if (loginState) {
        if (loginState.step === 'awaiting_username') {
            loginStates.set(userId, { step: 'awaiting_password', username: text });
            bot.sendMessage(chatId, "Sekarang, masukkan password Anda.");
        } else if (loginState.step === 'awaiting_password') {
            await bot.deleteMessage(chatId, msg.message_id).catch(() => {});
            const { username } = loginState;
            const password = text;
            const webUser = await WebUser.findOne({ telegramUsername: username });

            if (webUser && (await webUser.matchPassword(password))) {
                const token = uuidv4();
                webLoginTokens.set(token, { userId: webUser._id, telegramUsername: webUser.telegramUsername, telegramId: webUser.telegramId });
                setTimeout(() => webLoginTokens.delete(token), 1000 * 60);
                const link = `${config.webBaseUrl}/auth/bot-login?token=${token}`;
                await bot.sendPhoto(chatId, profilePicPath, {
                    caption: `✅ Login berhasil! Klik tombol di bawah untuk membuka dashboard.\n\nLink ini hanya valid selama 60 detik.`,
                    reply_markup: {
                        inline_keyboard: [[{ text: 'Buka Dashboard', url: link }]]
                    }
                });
            } else {
                bot.sendMessage(chatId, "❌ Login gagal. Username atau password salah.");
            }
            loginStates.delete(userId);
        }
        return;
    }

    console.log(chalk.gray(`[Message] Dari ${userId} (${msg.from.first_name}) di ${chatId} (${msg.chat.title || 'Private'}): "${text}"`));
  
    if (msg.chat.type.endsWith('group')) {
        const group = await Group.findOne({ chatId });
        
        if (group && group.autoWarnEnabled) {
            const admins = await getAdmins(chatId);
            if (!admins.includes(userId)) {
                const hasLink = LINK_REGEX.test(text);
                const hasPromo = PROMO_KEYWORDS_REGEX.test(text);

                if (hasLink || hasPromo) {
                    const reason = hasLink ? 'Mengirim link' : 'Promosi Terdeteksi';
                    await bot.deleteMessage(chatId, msg.message_id).catch(() => {});
                    await handleAutoViolation(chatId, msg.from, reason);
                    return;
                }
            }
        }

        if (!text.startsWith(config.prefix)) {
            const xpToAdd = Math.floor(Math.random() * 10) + 15;
            await User.findOneAndUpdate({ userId, chatId }, { $inc: { xp: xpToAdd } }, { upsert: true, new: true }).then(user => {
                if (user) {
                    const xpNeeded = user.level * 300;
                    if (user.xp >= xpNeeded) {
                        user.level += 1; user.xp -= xpNeeded; user.save();
                        bot.sendMessage(chatId, `🎉 Selamat ${msg.from.first_name}! Kamu naik ke <b>Level ${user.level}</b>!`, { parse_mode: 'HTML' });
                    }
                }
            });
        }
    }

    if (!text.startsWith(config.prefix)) return;
    const args = text.slice(config.prefix.length).trim().split(/ +/);
    const cmd = args.shift().toLowerCase();
    
    console.log(chalk.green.bold(`[Command] /${cmd} oleh ${userId} dengan args: [${args.join(', ')}]`));
    
    try {
        if (cmd === 'ping') {
            const sent = await bot.sendMessage(chatId, '🏓 Pong...');
            await bot.editMessageText(`🏓 Pong! Latency: ${sent.date - msg.date}s`, { chat_id: chatId, message_id: sent.message_id });
        }
        
        if (cmd === 'exec' && userId == config.ownerId) {
            exec(args.join(' '), (err, stdout, stderr) => {
                if (err) return bot.sendMessage(chatId, `❌ Error: ${err.message}`);
                const output = stdout || 'No output';
                const errorOutput = stderr ? `⚠️ Stderr:\n<pre>${stderr}</pre>` : '';
                bot.sendMessage(chatId, `✅ Output:\n<pre>${output}</pre>\n${errorOutput}`, { parse_mode: 'HTML' });
            });
        }

        if (cmd === 'rank' || cmd === 'level') {
            const user = await User.findOne({ userId, chatId });
            if (user) {
                const xpNeeded = user.level * 300;
                await bot.sendMessage(chatId, `<b>Peringkat Anda</b>\n\n👤 Nama: ${msg.from.first_name}\n🎖️ Level: ${user.level}\n✨ XP: ${user.xp} / ${xpNeeded}`, { parse_mode: 'HTML' });
            } else {
                await bot.sendMessage(chatId, `Anda belum memiliki peringkat.`);
            }
        }
    } catch (error) {
        console.error(chalk.red.bold(`[Error] Gagal menjalankan perintah /${cmd}:`), error);
    }
});

const adminOnly = async (msg) => {
    if (!msg.chat.type.endsWith('group')) {
        bot.sendMessage(msg.chat.id, 'Perintah ini hanya bisa digunakan di dalam grup.');
        return false;
    }
    const admins = await getAdmins(msg.chat.id);
    if (!admins.includes(msg.from.id)) {
        bot.sendMessage(msg.chat.id, '❌ Anda harus menjadi admin.');
        return false;
    }
    return true;
};

bot.onText(/\/setwelcome (.+)/, async (msg, match) => { if (await adminOnly(msg)) { await Group.findOneAndUpdate({ chatId: msg.chat.id }, { welcome: match[1] }, { upsert: true }); bot.sendMessage(msg.chat.id, '✅ Welcome diatur.'); }});
bot.onText(/\/setgoodbye (.+)/, async (msg, match) => { if (await adminOnly(msg)) { await Group.findOneAndUpdate({ chatId: msg.chat.id }, { goodbye: match[1] }, { upsert: true }); bot.sendMessage(msg.chat.id, '✅ Goodbye diatur.'); }});
bot.onText(/\/warn (on|off)/i, async (msg, match) => { if (await adminOnly(msg)) { const status = match[1].toLowerCase() === 'on'; await Group.findOneAndUpdate({ chatId: msg.chat.id }, { autoWarnEnabled: status }, { upsert: true }); bot.sendMessage(msg.chat.id, `✅ Auto-moderasi: <b>${status ? 'ON' : 'OFF'}</b>`, { parse_mode: 'HTML' }); }});
bot.onText(/\/del/, async (msg) => { if (await adminOnly(msg) && msg.reply_to_message) { await bot.deleteMessage(msg.chat.id, msg.reply_to_message.message_id).catch(() => {}); await bot.deleteMessage(msg.chat.id, msg.message_id).catch(() => {}); }});
bot.onText(/\/ban/, async (msg) => { if (await adminOnly(msg) && msg.reply_to_message) { try { await bot.restrictChatMember(msg.chat.id, msg.reply_to_message.from.id, { can_send_messages: false }); bot.sendMessage(msg.chat.id, `✅ <b>${msg.reply_to_message.from.first_name}</b> di-mute.`, { parse_mode: 'HTML' }); } catch (e) { bot.sendMessage(msg.chat.id, `❌ Gagal mute: ${e.response?.body?.description || e.message}`); } }});
bot.onText(/\/unban/, async (msg) => { if (await adminOnly(msg) && msg.reply_to_message) { try { await bot.restrictChatMember(msg.chat.id, msg.reply_to_message.from.id, { can_send_messages: true, can_send_media_messages: true, can_send_other_messages: true, can_add_web_page_previews: true }); bot.sendMessage(msg.chat.id, `✅ <b>${msg.reply_to_message.from.first_name}</b> di-unmute.`, { parse_mode: 'HTML' }); } catch (e) { bot.sendMessage(msg.chat.id, `❌ Gagal unmute: ${e.response?.body?.description || e.message}`); } }});

let verifyTimers = {};
bot.on('new_chat_members', async (msg) => {
    const group = await Group.findOne({ chatId: msg.chat.id });
    if (!group || !group.welcome) return;
    for (let member of msg.new_chat_members) {
        await User.create({ userId: member.id, chatId: msg.chat.id, verified: false });
        const teks = group.welcome.replace(/{user}/g, `<a href="tg://user?id=${member.id}">${member.first_name}</a>`).replace(/{group}/g, msg.chat.title);
        const verificationMsg = await bot.sendMessage(msg.chat.id, teks, { parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '✅ Verifikasi Diri Anda', callback_data: 'verify_' + member.id }]] } });
        verifyTimers[member.id] = setTimeout(async () => {
            try {
                const user = await User.findOne({ userId: member.id, chatId: msg.chat.id });
                if (user && !user.verified) {
                    await bot.banChatMember(msg.chat.id, member.id);
                    await bot.unbanChatMember(msg.chat.id, member.id);
                    await bot.sendMessage(msg.chat.id, `⏱️ ${member.first_name} dikeluarkan karena tidak verifikasi.`);
                    await bot.deleteMessage(msg.chat.id, verificationMsg.message_id).catch(() => {});
                }
            } catch (e) {}
            delete verifyTimers[member.id];
        }, 60000);
    }
});

bot.on('left_chat_member', async (msg) => {
    const member = msg.left_chat_member;
    await User.deleteOne({ userId: member.id, chatId: msg.chat.id });
    const group = await Group.findOne({ chatId: msg.chat.id });
    if (!group || !group.goodbye) return;
    const teks = group.goodbye.replace(/{user}/g, `<b>${member.first_name}</b>`).replace(/{group}/g, msg.chat.title);
    await bot.sendMessage(msg.chat.id, teks, { parse_mode: 'HTML' });
});

app.listen(port, () => {
    console.log(chalk.cyan.bold(`[Web] Server berjalan di ${config.webBaseUrl}`));
});
console.log(chalk.green.bold(`\n[Bot] Bot ${config.botName} berhasil diaktifkan!`));