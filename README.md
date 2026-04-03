# Finance Data Processing and Access Control Backend (C++)

A backend system for a finance dashboard with role-based access control, financial records management, and aggregated analytics. Built in **C++17** using Pistache, nlohmann/json, and cpp-jwt.

---

## NOTE 
This is my take on the problem statement and i am totally aware of the fact that it might not be perfect or production grade, and as there were no restrictions for the language and the exact method, that's why i did it in a different way.

## Stack

- **Language**: C++17
- **HTTP Framework**: Pistache (REST)
- **JSON**: nlohmann/json
- **Auth**: JWT via cpp-jwt (HS256), passwords hashed with OpenSSL SHA-256
- **Storage**: In-memory (std::vector + std::mutex), resets on restart

---

## Build & Run

### Dependencies (Ubuntu/Debian)
```bash
apt-get install -y libpistache-dev nlohmann-json3-dev libcpp-jwt-dev libssl-dev g++
```

## Dependencies (Fedora)
```bash
sudo dnf install -y gcc-c++ openssl-devel nlohmann-json-devel cpp-jwt-devel pistache-devel
sudo dnf install -y gcc-c++ cmake openssl-devel nlohmann-json-devel cpp-jwt-devel
git clone https://github.com/pistacheio/pistache.git
cd pistache
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DPISTACHE_BUILD_TESTS=OFF
make -j$(nproc)
sudo make install
sudo ldconfig

### Compile
```bash
g++ -std=c++17 -O2 src/main.cpp -lpistache -lssl -lcrypto -lpthread -o finance_backend
```

### Run
```bash
./finance_backend
# Server starts on port 3000
```

---

## Default Users (seeded on startup)

| Username  | Password     | Role     |
|-----------|--------------|----------|
| admin     | admin123     | admin    |
| analyst1  | analyst123   | analyst  |
| viewer1   | viewer123    | viewer   |

---

## Authentication

All protected routes require a Bearer token:
```
Authorization: Bearer <token>
```

**Login:**
```
POST /auth/login
Body: { "username": "admin", "password": "admin123" }
Returns: { "token": "...", "user": { ... } }
```

---

## Role Permissions

| Action                        | Viewer | Analyst | Admin |
|-------------------------------|--------|---------|-------|
| View records / dashboard      | Y | Y | Y |
| Create / update records       | N | Y | Y |
| Delete records (soft)         | N | N | Y |
| Manage users                  | N | N | Y |
| `/dashboard/stats` full detail| N | Y | Y |

---

## API Endpoints

### Auth / Users

| Method | Path          | Role  | Description              |
|--------|---------------|-------|--------------------------|
| POST   | /auth/login   | -     | Login, returns JWT       |
| GET    | /users/me     | Any   | Get current user         |
| GET    | /users        | admin | List all users           |
| POST   | /users        | admin | Create user              |
| PATCH  | /users/:id    | admin | Update role/status       |
| DELETE | /users/:id    | admin | Delete user              |

### Financial Records

| Method | Path          | Role     | Description               |
|--------|---------------|----------|---------------------------|
| GET    | /records      | Any      | List records (filterable) |
| GET    | /records/:id  | Any      | Get single record         |
| POST   | /records      | analyst+ | Create record             |
| PUT    | /records/:id  | analyst+ | Update record             |
| DELETE | /records/:id  | admin    | Soft-delete record        |

**GET /records query params:** `type`, `category`, `from`, `to`, `page`, `limit`

### Dashboard

| Method | Path                        | Description                 |
|--------|-----------------------------|-----------------------------|
| GET    | /dashboard/summary          | Income, expenses, net       |
| GET    | /dashboard/by-category      | Totals per category         |
| GET    | /dashboard/monthly-trends   | Month-by-month breakdown    |
| GET    | /dashboard/recent           | Recent transactions         |
| GET    | /dashboard/stats            | Aggregated stats            |

---

## Assumptions

1. **In-memory store** — no persistence between restarts; swap in SQLite/PostgreSQL for production.
2. **SHA-256 passwords** — bcrypt isn't readily available as a dev library on this platform; SHA-256 used instead. Swap to bcrypt/Argon2 for production.
3. **Soft deletes** — records get `deleted=true`, never physically removed.
4. **Analyst can create/update but not delete** — destructive ops are admin-only.
5. **Seeded data** — 20 records across 10 months seeded on startup for dashboard endpoints.

---

## Error Responses

```json
{ "error": "description" }
```

HTTP codes used: `200`, `201`, `400`, `401`, `403`, `404`, `409`, `500`# finance_backend
