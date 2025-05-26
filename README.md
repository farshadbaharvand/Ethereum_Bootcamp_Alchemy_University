js-bootcamp/
│
├── README.md                   ← معرفی بوت‌کمپ، نحوه استفاده، منابع
├── package.json                ← مدیریت وابستگی‌ها و اسکریپت‌ها
├── .gitignore                  ← فایل‌های نادیده‌گرفته‌شده در گیت
│
├── node_modules/               ← وابستگی‌ها (npm install)
│
├── modules/                    ← پوشه اصلی تمام درس‌ها و پروژه‌ها
│   ├── 01-basics/              ← مفاهیم پایه جاوااسکریپت
│   │   ├── index.js
│   │   └── README.md
│   ├── 02-crypto/              ← رمزنگاری (AES, RSA, ECDSA ...)
│   │   ├── symmetric.js
│   │   ├── asymmetric.js
│   │   ├── privateKey.js
│   │   └── README.md
│   ├── 03-smart-contracts/     ← تعامل با بلاکچین، قرارداد هوشمند
│   │   ├── abi.json
│   │   ├── contract-interact.js
│   │   └── README.md
│   ├── 04-tests/               ← آموزش تست‌نویسی (Jest یا Vitest)
│   │   ├── example.test.js
│   │   └── README.md
│   ├── 05-web-integration/     ← اتصال به فرانت‌اند (HTML/CSS/JS)
│   │   ├── index.html
│   │   ├── app.js
│   │   └── styles.css
│   └── ...
│
├── shared/                     ← کدهای عمومی قابل استفاده بین ماژول‌ها
│   ├── utils.js
│   └── config.js
│
├── scripts/                    ← ابزارها یا اسکریپت‌های کمکی (مثلاً تولید کلید، تست سریع)
│   └── setup.js
│
├── tests/                      ← تست‌های کلی پروژه (یا جدا از هر ماژول)
│   └── bootstrap.test.js
│
└── .eslintrc.json              ← تنظیمات Lint برای حفظ نظم کدنویسی
