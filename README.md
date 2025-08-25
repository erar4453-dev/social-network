# Social Network

Этот проект — минимальная соцсеть на Next.js + Prisma + PostgreSQL.

## 🚀 Запуск

1. Установи зависимости:
   ```bash
   npm install
   ```

2. Настрой `.env` (скопируй из `.env.example` и пропиши доступ к PostgreSQL + NEXTAUTH_SECRET).

3. Прогони миграции:
   ```bash
   npx prisma migrate dev --name init
   ```

4. Запусти сервер:
   ```bash
   npm run dev
   ```

5. Открой [http://localhost:3000](http://localhost:3000).

## 📂 Стек
- Next.js 14 (App Router)
- Prisma ORM
- PostgreSQL
- NextAuth
- Tailwind + shadcn/ui

---

✌️ Проект можно дорабатывать: добавить лайки, комментарии, загрузку фото (S3/R2), профили, подписки и т.д.
