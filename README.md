# TRS Food: website + backend

Zero dependencies. Needs Node 18 or newer.

## Run
    ADMIN_PASSCODE=choose-a-passcode node server.js

Open http://localhost:3000. The server serves the website and the API from the same address.
Data is stored in `data.json`, created on first run from `seed.json`. Back this file up.

## Deploy
Any host that runs Node works (Render, Railway, Fly.io, a VPS). Start command: `node server.js`.
Put it behind HTTPS (hosts do this for you) and keep `data.json` on a persistent disk or volume.
`ADMIN_PASSCODE` only sets the first passcode. After that, change it in Admin > Settings.

## What the backend does
- Customer accounts: passwords hashed with scrypt, signed login tokens (30 days)
- Admin: passcode login (1-day token), rate-limited to 10 failures per 15 minutes
- Menu, photos, news, offers and settings are saved on the server and shared with every visitor
- Orders: totals, promo code and delivery fee are recalculated on the server, so prices can't be tampered with
- Order status is set by admin and shows on the customer's tracker
- Reviews require a logged-in customer

## API
    GET   /api/state                 public menu, news, offers, settings, reviews
    POST  /api/register, /api/login  customer accounts
    GET   /api/me, /api/orders       customer (Bearer token)
    POST  /api/orders, /api/reviews  customer (Bearer token)
    POST  /api/admin/login           { passcode }
    PUT   /api/admin/state           admin: meals, news, offers, cfg, np (new passcode)
    GET   /api/admin/orders          admin
    PATCH /api/admin/orders/:id      admin: { st: 0-3 }

## Not included yet
- Real card payments. Card orders are recorded but nobody is charged. Add Stripe (or similar) in POST /api/orders before taking cards.
- Email/SMS notifications and password reset.
- Opening index.html on its own (without the server) still works as a local demo.
