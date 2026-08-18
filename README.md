# Eclipse SMP Support Bot + Ticket API

This service connects `eclipsemc.site.je` to Discord. A website ticket creates a private Discord channel; replies synchronize in both directions.

## Features

- Guest tickets or optional Discord OAuth login
- Private Discord ticket channel per request
- Website ticket dashboard and replies
- Staff replies from Discord mirrored to the website
- Claim and Close buttons
- `/support` and `/close` slash commands
- Rate limiting, honeypot spam check, access tokens, and restricted CORS
- SQLite persistence on a Railway volume

## 1. Discord Developer Portal

Your bot already exists. In its application settings:

1. Open **Bot** and enable **Message Content Intent**.
2. Open **OAuth2 → General** and add this redirect after Railway is deployed:
   `https://YOUR-RAILWAY-DOMAIN/auth/discord/callback`
3. Invite the bot with scopes `bot` and `applications.commands`.
4. Bot permissions: View Channels, Send Messages, Read Message History, Manage Channels.
5. In your Discord server, create a private category for tickets and a Support Team role.
6. Enable Developer Mode in Discord, then copy the server, category, and role IDs.

## 2. Deploy on Railway

1. Put this `eclipse-support` folder in a GitHub repository.
2. In Railway choose **New Project → Deploy from GitHub repo**.
3. Add a persistent **Volume** mounted at `/data`.
4. Add every value from `.env.example` in Railway Variables.
5. Generate a public Railway domain.
6. Set `API_PUBLIC_URL` to that Railway domain.
7. Add the exact callback URL from step 2 to the Discord Developer Portal.
8. Redeploy and check `https://YOUR-DOMAIN/health`.

Never upload `.env` or expose `DISCORD_TOKEN`, `DISCORD_CLIENT_SECRET`, or `JWT_SECRET` in website files.

## 3. Connect the website

Edit `support-config.js`:

```js
window.ECLIPSE_SUPPORT_API = 'https://YOUR-RAILWAY-DOMAIN';
```

Upload the updated website files to your host. The website origin must exactly match `WEB_ORIGIN` (currently `https://eclipsemc.site.je`).

## 4. Add the Support navigation link

The prepared website package already includes `support.html`. Upload it with `support.css`, `support.js`, and `support-config.js`.

## Local development

```bash
cp .env.example .env
npm install
npm run dev
```

Open `http://localhost:3000/health`. For local website testing, set `WEB_ORIGIN` to your local site address and update `support-config.js`.

## Important hosting note

The Discord bot cannot run on normal static web hosting. It needs an always-on Node.js process. Railway is used for the bot/API while the public website remains on `eclipsemc.site.je`.
