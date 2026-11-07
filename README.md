# SUKH IMPLEMENT-Sales (server version)

Your finalised prototype, now with a real server: logins, one shared database, works on every device.
Node.js 22.13 or newer + Express + built-in SQLite. Nothing to compile.

## Run on your computer
    npm install
    set ADMIN_PASSWORD=ChooseAStrongOne      (Windows)   or   ADMIN_PASSWORD=... npm start   (Mac/Linux)
    npm start
Open http://localhost:3000 and log in as `admin`.

## Put it online
Use any Node.js host (Render, Railway, Fly.io, VPS). Settings:
- Build: `npm install`   Start: `npm start`
- `NODE_ENV=production`, `ADMIN_PASSWORD=<strong password>`
- `DATA_DIR=/data` pointing to a **persistent disk** (otherwise data is lost on redeploy)

## Login page
The background photo is built into the page itself, so it cannot go missing. A sharper copy is loaded from `public/login-bg.jpg` on top of it. If you replace that file with a larger photo, keep the same name. The login box is placed to match the photo supplied (LOGIN_1.jpg).

## Deal ID
New deals get an ID of the form YY-serial (for example 26-001, 26-002). The serial restarts at 001 each year and continues from older IDs such as 26001. Older deals keep their old IDs.

## Pages
- **Customers**: built from deals (matched by mobile number), search, balance due, click a customer to see all their deals, CSV export.
- **Reports**: this month / last month / financial year (Apr–Mar) / all time / custom dates: sales, collections by method, month-wise sales, finance by bank, trade-in stock, highest balances due, deals CSV.
- **Settings** is still a placeholder.

## Limited staff view (for showroom staff)
Admin: **Users** → add user → tick **Limited staff view** (it is the default for new users). Staff then see only:
- **Deals**: deals done, products, and the accessories in each deal with a **tick box for each accessory provided**.
- **Pending Payments**: only amounts still to come (from customer and from finance). No payment history.
- **Customers**: name, mobile, village and their deals. No billed, received or ledger figures.
The server removes prices, discounts, payments, finance details and notes before sending data to these users, and refuses any change they try to save. Their accessory ticks are saved separately and the admin sees them on the deal page under "Accessories handed over".

## Paperwork, accessories, delivery date
- Invoice, Delivery challan and Insurance policy apply to every deal. Staff tick each when handed over.
- "Other accessories" is an open box in the deal form (separate several with commas). Each one becomes a tick box for staff.
- If no delivery date is entered on the deal, the date of the latest handover is shown as the delivery date.

## Product handover
Staff (and admin) record what has been handed over to the customer, product by product. A product with quantity 1 is a tick box with a date. A product with more than one (for example 12,500 nursery trays) is handed over in lots: staff enter each lot's quantity and date (2,000, then 5,000, then 3,000, then 2,500). The app shows handed over and remaining, blocks entering more than remains, and blocks future dates. Each entry shows who recorded it. Staff can remove only their own entries. Admin can remove any.

## Staff access (custom)
Admin: **Users** → add a user or press **Edit access**. Pick a preset (Salesperson, Accounts, Manager, View only) and adjust the tick boxes.
- Pages: Dashboard, Deals, Trade-in Stock, Payment Ledger, Finance Receivables, Customers, Reports, Settings.
- Actions: add/edit deals · record payments · update trade-in and finance · cancel/delete deals and delete payments.
- Staff with no action ticked are view-only: the server refuses their changes.
- Staff created before this update get: all pages except Settings, everything except cancel/delete.
- Note: hidden pages are hidden in the app. The data is still sent to the browser, so give only trusted people a login.

## How it works
- Admin adds staff under **Users**. All logged-in users can see and enter deals; only admin sees Users and can download a backup.
- Every change is saved automatically to the server. The top bar shows "All changes saved".
- If two people save at the same moment, the app reloads the latest data and shows a message.
- The server keeps the last 300 saved versions in the database (table `state_history`).
- Backup: log in as admin and open `/api/backup`, or copy `DATA_DIR/dealer.db`.
