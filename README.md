# 🔥 GMS FamPay API

**Free FamPay Gateway API** with automatic payment verification for your bots and websites.

![Version](https://img.shields.io/badge/Version-1.0-green)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## ✨ Features

- ✅ **Free Forever** - No payment required
- ✅ One Account = One API Key
- ✅ Dynamic UPI QR Code Generation
- ✅ Payment Verification System
- ✅ Clean & Simple API
- ✅ Easy integration in Telegram bots, Websites & Apps

---

## 🚀 API Endpoints

### 1. Generate QR Code
```http
GET /api/qr?api=YOUR_API_KEY&amount=AMOUNT
Example:
texthttps://yourdomain.com/api/qr?api=GMSABC123XYZ&amount=50
2. Verify Payment
httpGET /api/verify?api_key=YOUR_API_KEY&order_id=ORDER_ID

📸 Screenshots
(You can add screenshots here later)

🛠️ How to Run Locally
Bashgit clone <your-repo-url>
cd gms-fampay-api
npm install
node index.js
Open browser → http://localhost:3000

🌐 Free Deployment

Push code to GitHub
Go to Render.com
New Web Service → Connect GitHub repo
Set:
Build Command: npm install
Start Command: node index.js

Deploy (Free)


📌 Important Note
This is currently using simulated verification.
Real Gmail IMAP scanning will be added soon.

Made with ❤️ by GMS

Need Help? Contact: @yourusername
text**How to use:**
1. Copy the entire code above.
2. Create a new file named `README.md` in your GitHub repo.
3. Paste and commit.

Want me to make it even more advanced (with GIF support, table, etc.)?
