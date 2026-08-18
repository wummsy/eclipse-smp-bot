require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const {
  Client, GatewayIntentBits, PermissionFlagsBits, ChannelType,
  EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, SlashCommandBuilder
} = require('discord.js');

const required = ['DISCORD_TOKEN', 'DISCORD_CLIENT_ID', 'DISCORD_GUILD_ID', 'DISCORD_TICKET_CATEGORY_ID', 'DISCORD_SUPPORT_ROLE_ID', 'JWT_SECRET', 'WEB_ORIGIN'];
const missing = required.filter(key => !process.env[key]);
if (missing.length) {
  console.error(`Missing environment variables: ${missing.join(', ')}`);
  process.exit(1);
}

const PORT = Number(process.env.PORT || 3000);
const WEB_ORIGIN = process.env.WEB_ORIGIN.replace(/\/$/, '');
const API_URL = (process.env.API_PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const DB_PATH = process.env.DATABASE_PATH || path.join(__dirname, '..', 'data', 'eclipse-support.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT NOT NULL UNIQUE,
    access_hash TEXT NOT NULL,
    discord_user_id TEXT,
    discord_channel_id TEXT,
    name TEXT NOT NULL,
    contact TEXT,
    category TEXT NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    claimed_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    author_name TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(ticket_id) REFERENCES tickets(id)
  );
  CREATE INDEX IF NOT EXISTS idx_messages_ticket ON messages(ticket_id, id);
  CREATE INDEX IF NOT EXISTS idx_tickets_channel ON tickets(discord_channel_id);
`);

const q = {
  ticketByPublic: db.prepare('SELECT * FROM tickets WHERE public_id = ?'),
  ticketByChannel: db.prepare('SELECT * FROM tickets WHERE discord_channel_id = ?'),
  insertTicket: db.prepare(`INSERT INTO tickets (public_id, access_hash, discord_user_id, name, contact, category, subject)
    VALUES (@public_id, @access_hash, @discord_user_id, @name, @contact, @category, @subject)`),
  setChannel: db.prepare('UPDATE tickets SET discord_channel_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?'),
  insertMessage: db.prepare('INSERT INTO messages (ticket_id, source, author_name, body) VALUES (?, ?, ?, ?)'),
  messages: db.prepare('SELECT id, source, author_name, body, created_at FROM messages WHERE ticket_id = ? ORDER BY id ASC'),
  close: db.prepare("UPDATE tickets SET status = 'closed', updated_at = CURRENT_TIMESTAMP WHERE id = ?"),
  claim: db.prepare("UPDATE tickets SET claimed_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
};

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent]
});

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: WEB_ORIGIN, methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization', 'X-Ticket-Token'] }));
app.use(express.json({ limit: '32kb' }));
app.use('/api/', rateLimit({ windowMs: 10 * 60 * 1000, limit: 80, standardHeaders: true, legacyHeaders: false }));
app.use('/api/tickets', rateLimit({ windowMs: 15 * 60 * 1000, limit: 15, standardHeaders: true, legacyHeaders: false }));

const clean = (value, max = 500) => String(value || '').replace(/[<>]/g, '').trim().slice(0, max);
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const newId = () => `EC-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
const newToken = () => crypto.randomBytes(24).toString('base64url');
const bearerUser = req => {
  const value = req.headers.authorization;
  if (!value?.startsWith('Bearer ')) return null;
  try { return jwt.verify(value.slice(7), process.env.JWT_SECRET); } catch { return null; }
};
const ticketAllowed = (req, ticket) => {
  const user = bearerUser(req);
  if (user?.id && ticket.discord_user_id === user.id) return true;
  const token = req.headers['x-ticket-token'];
  return Boolean(token && crypto.timingSafeEqual(Buffer.from(hash(token)), Buffer.from(ticket.access_hash)));
};

app.get('/health', (_req, res) => res.json({ ok: true, bot: client.isReady(), service: 'eclipse-support' }));
app.get('/api/discord', async (_req, res) => {
  try {
    const guild = await client.guilds.fetch(process.env.DISCORD_GUILD_ID);
    res.json({ name: guild.name, members: guild.memberCount, invite: process.env.DISCORD_INVITE || 'https://discord.gg/35mxDRKzmB', online: client.isReady() });
  } catch { res.status(503).json({ online: false }); }
});

// Optional Discord OAuth login.
app.get('/auth/discord', (req, res) => {
  if (!process.env.DISCORD_CLIENT_SECRET) return res.status(501).send('Discord OAuth is not configured.');
  const state = jwt.sign({ purpose: 'oauth' }, process.env.JWT_SECRET, { expiresIn: '10m' });
  const params = new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, response_type: 'code', redirect_uri: `${API_URL}/auth/discord/callback`, scope: 'identify', state });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});
app.get('/auth/discord/callback', async (req, res) => {
  try {
    const state = jwt.verify(String(req.query.state || ''), process.env.JWT_SECRET);
    if (state.purpose !== 'oauth') throw new Error('Invalid state');
    const body = new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, client_secret: process.env.DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code: String(req.query.code || ''), redirect_uri: `${API_URL}/auth/discord/callback` });
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    if (!tokenResponse.ok) throw new Error('OAuth token exchange failed');
    const oauth = await tokenResponse.json();
    const userResponse = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${oauth.access_token}` } });
    const user = await userResponse.json();
    const session = jwt.sign({ id: user.id, username: user.global_name || user.username, avatar: user.avatar }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`${WEB_ORIGIN}/support.html#discord_token=${encodeURIComponent(session)}`);
  } catch (error) {
    console.error(error);
    res.redirect(`${WEB_ORIGIN}/support.html#discord_error=1`);
  }
});
app.get('/api/me', (req, res) => {
  const user = bearerUser(req);
  if (!user) return res.status(401).json({ error: 'Not signed in' });
  res.json({ id: user.id, username: user.username, avatar: user.avatar });
});

app.post('/api/tickets', async (req, res) => {
  try {
    if (clean(req.body.website, 100)) return res.status(400).json({ error: 'Invalid submission' }); // honeypot
    const user = bearerUser(req);
    const name = clean(user?.username || req.body.name, 50);
    const contact = clean(req.body.contact, 100);
    const category = clean(req.body.category, 30);
    const subject = clean(req.body.subject, 90);
    const message = clean(req.body.message, 1800);
    if (name.length < 2 || !['player-report', 'bug', 'appeal', 'purchase', 'other'].includes(category) || subject.length < 4 || message.length < 10) {
      return res.status(400).json({ error: 'Please complete all required fields.' });
    }

    const accessToken = newToken();
    const publicId = newId();
    const info = q.insertTicket.run({ public_id: publicId, access_hash: hash(accessToken), discord_user_id: user?.id || null, name, contact, category, subject });
    const ticketId = Number(info.lastInsertRowid);
    q.insertMessage.run(ticketId, 'player', name, message);

    const guild = await client.guilds.fetch(process.env.DISCORD_GUILD_ID);
    const overwrites = [
      { id: guild.roles.everyone.id, deny: [PermissionFlagsBits.ViewChannel] },
      { id: process.env.DISCORD_SUPPORT_ROLE_ID, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] },
      { id: client.user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ManageChannels] }
    ];
    if (user?.id) overwrites.push({ id: user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] });
    const channel = await guild.channels.create({
      name: `ticket-${publicId.toLowerCase()}`,
      type: ChannelType.GuildText,
      parent: process.env.DISCORD_TICKET_CATEGORY_ID,
      permissionOverwrites: overwrites,
      topic: `${publicId} | ${category} | ${name}`
    });
    q.setChannel.run(channel.id, ticketId);
    const embed = new EmbedBuilder().setColor(0xA742FF).setTitle(`${publicId} · ${subject}`).setDescription(message).addFields(
      { name: 'Player', value: user ? `<@${user.id}>` : name, inline: true },
      { name: 'Category', value: category, inline: true },
      { name: 'Contact', value: contact || 'Not provided', inline: true }
    ).setFooter({ text: 'Eclipse SMP Support' }).setTimestamp();
    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId(`claim:${publicId}`).setLabel('Claim').setStyle(ButtonStyle.Primary),
      new ButtonBuilder().setCustomId(`close:${publicId}`).setLabel('Close').setStyle(ButtonStyle.Danger)
    );
    await channel.send({ content: `<@&${process.env.DISCORD_SUPPORT_ROLE_ID}> New website ticket`, embeds: [embed], components: [row] });
    res.status(201).json({ id: publicId, token: accessToken, signedIn: Boolean(user) });
  } catch (error) {
    console.error('Create ticket failed:', error);
    res.status(500).json({ error: 'Ticket service is temporarily unavailable.' });
  }
});

app.get('/api/tickets/:id', (req, res) => {
  const ticket = q.ticketByPublic.get(clean(req.params.id, 20).toUpperCase());
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
  if (!ticketAllowed(req, ticket)) return res.status(403).json({ error: 'Access denied' });
  res.json({ ticket: { id: ticket.public_id, name: ticket.name, category: ticket.category, subject: ticket.subject, status: ticket.status, claimedBy: ticket.claimed_by, createdAt: ticket.created_at }, messages: q.messages.all(ticket.id) });
});

app.post('/api/tickets/:id/messages', async (req, res) => {
  const ticket = q.ticketByPublic.get(clean(req.params.id, 20).toUpperCase());
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
  if (!ticketAllowed(req, ticket)) return res.status(403).json({ error: 'Access denied' });
  if (ticket.status === 'closed') return res.status(409).json({ error: 'This ticket is closed' });
  const body = clean(req.body.message, 1800);
  if (body.length < 1) return res.status(400).json({ error: 'Message cannot be empty' });
  const user = bearerUser(req);
  q.insertMessage.run(ticket.id, 'player', user?.username || ticket.name, body);
  try {
    const channel = await client.channels.fetch(ticket.discord_channel_id);
    await channel.send({ embeds: [new EmbedBuilder().setColor(0xFF5E91).setAuthor({ name: `${user?.username || ticket.name} · Website reply` }).setDescription(body).setTimestamp()] });
  } catch (error) { console.error('Discord reply mirror failed:', error); }
  res.status(201).json({ ok: true });
});

client.once('ready', async () => {
  console.log(`Discord bot ready as ${client.user.tag}`);
  const commands = [
    new SlashCommandBuilder().setName('support').setDescription('Get the Eclipse SMP support link'),
    new SlashCommandBuilder().setName('close').setDescription('Close the current ticket')
  ].map(command => command.toJSON());
  try { await client.application.commands.set(commands, process.env.DISCORD_GUILD_ID); } catch (error) { console.error('Command registration failed:', error); }
});

client.on('messageCreate', message => {
  if (message.author.bot || !message.guild) return;
  const ticket = q.ticketByChannel.get(message.channel.id);
  if (!ticket || ticket.status === 'closed') return;
  const body = clean(message.content, 1800);
  const isStaff = message.member?.roles.cache.has(process.env.DISCORD_SUPPORT_ROLE_ID);
  if (body) q.insertMessage.run(ticket.id, isStaff ? 'staff' : 'player', message.member?.displayName || message.author.username, body);
});

client.on('interactionCreate', async interaction => {
  try {
    if (interaction.isChatInputCommand()) {
      if (interaction.commandName === 'support') return interaction.reply({ content: `${WEB_ORIGIN}/support.html`, ephemeral: true });
      if (interaction.commandName === 'close') {
        const ticket = q.ticketByChannel.get(interaction.channelId);
        if (!ticket) return interaction.reply({ content: 'This is not a ticket channel.', ephemeral: true });
        q.close.run(ticket.id);
        await interaction.reply('Ticket closed. This channel will be archived in 10 seconds.');
        setTimeout(() => interaction.channel.setName(`closed-${ticket.public_id.toLowerCase()}`).catch(() => {}), 10000);
      }
    }
    if (interaction.isButton()) {
      const [action, publicId] = interaction.customId.split(':');
      const ticket = q.ticketByPublic.get(publicId);
      if (!ticket) return interaction.reply({ content: 'Ticket not found.', ephemeral: true });
      if (action === 'claim') {
        q.claim.run(interaction.user.id, ticket.id);
        return interaction.update({ components: [new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId(`claim:${publicId}`).setLabel(`Claimed by ${interaction.user.username}`).setStyle(ButtonStyle.Secondary).setDisabled(true),
          new ButtonBuilder().setCustomId(`close:${publicId}`).setLabel('Close').setStyle(ButtonStyle.Danger)
        )] });
      }
      if (action === 'close') {
        q.close.run(ticket.id);
        await interaction.update({ content: `Closed by ${interaction.user}.`, components: [] });
        setTimeout(() => interaction.channel.setName(`closed-${publicId.toLowerCase()}`).catch(() => {}), 3000);
      }
    }
  } catch (error) { console.error('Interaction failed:', error); }
});

const server = app.listen(PORT, '0.0.0.0', () => console.log(`Support API listening on ${PORT}`));
client.login(process.env.DISCORD_TOKEN);

const shutdown = () => { server.close(); client.destroy(); db.close(); process.exit(0); };
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
