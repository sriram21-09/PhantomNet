# PhantomNet Docker Guide 🐳

Welcome to the Docker Guide! This document explains how Docker works, how it runs the **PhantomNet** ecosystem, and how to control it step-by-step.

---

## 1. What is Docker & Containerization?

### The "Shipping Container" Analogy
Think of a standard shipping container. It doesn't matter if you're shipping bananas, cars, or electronics; the container has the exact same dimensions, fits on any cargo ship, and isolates its contents from the outside world.

In software, **Docker** does the same:
- It packages an application (like your Python API or React Frontend) along with all its dependencies, system libraries, and configuration files into an **Image**.
- Running this image creates a **Container** — a lightweight, isolated, self-contained box that runs exactly the same on your machine, a production server, or the cloud.

### Why Do We Use It?
1. **Consistency**: No more "works on my machine" issues. If it builds in Docker, it runs the same everywhere.
2. **Isolation**: The honeypots run in their own secure sandboxes. If an attacker "breaks into" the SSH honeypot, they are trapped in that container and cannot touch your host operating system or other services.
3. **Simplicity**: You don't need to install Python, Postgres, Node.js, or Nginx on your own system. Docker handles all of it.

---

## 2. The PhantomNet Docker Architecture

PhantomNet consists of 7 services working together, managed by **Docker Compose** (which acts as the conductor of the orchestra):

```
                       [ Host Port 3000 ]
                               │
                        ┌──────▼──────┐
                        │  Frontend   │ (React Dashboard)
                        └──────┬──────┘
                               │ (API Requests)
                       [ Host Port 8000 ]
                               │
                        ┌──────▼──────┐
                        │  Backend    │ (FastAPI App)
                        └──────┬──────┘
                               │
               ┌───────────────┼───────────────┐
         (app_net Network)     │      (honeypot_net isolated Network)
               │               │               │
        ┌──────▼──────┐        │        ┌──────▼──────┐
        │  Postgres   ◄────────┼────────► SSH Honeypot│ [Port 2222]
        │  Database   │        │        ├─────────────┤
        └─────────────┘        │        │HTTP Honeypot│ [Port 8080]
                               │        ├─────────────┤
                               │        │FTP Honeypot │ [Port 2121]
                               │        ├─────────────┤
                               │        │SMTP Honeypot│ [Port 2525]
                               └────────┴─────────────┘
```

### Networks
- **`app_net`**: A network bridge that connects the Frontend and the Backend API, and lets the API talk to Postgres.
- **`honeypot_net` (Isolated)**: An internal-only network with no external internet access. This ensures that even if a honeypot is compromised, it cannot send outbound traffic, download malicious files, or attack other servers. The database sits in both networks so that honeypots can log events directly to it.

---

## 3. How to Use Docker (Commands Cheatsheet)

You will run all Docker commands from the project root (`c:\Users\srira\Project\PhantomNet`).

### Start the Entire System
To build all images and start the containers in the background:
```powershell
docker compose up --build -d
```
- `--build`: Forces Docker to recompile and rebuild the images (useful when you make changes to your code).
- `-d` (Detached mode): Runs the containers in the background, freeing up your terminal.

### Stop the System
To stop all running containers without deleting database data:
```powershell
docker compose down
```

### Check Container Status
To see which containers are currently running, their status, and port mapping:
```powershell
docker compose ps
```

### View Application Logs
To watch the real-time logs of the entire system:
```powershell
docker compose logs -f
```
To view logs for a specific service (e.g., only the SSH Honeypot):
```powershell
docker compose logs -f ssh_honeypot
```

### Reset & Clean Everything
If you want to clear all data, including the database records, and rebuild from scratch:
```powershell
docker compose down -v
```
- `-v`: Deletes the persistent storage volumes (resets the PostgreSQL database).

---

## 4. Port Mappings (Accessing the Services)

Once the containers are running, you can interact with them using these ports:

| Service | Protocol | Host (External) Port | Internal Port | How to test/access |
|---|---|---|---|---|
| **Frontend** | HTTP | `3000` | `8080` | Open `http://localhost:3000` in browser |
| **Backend API** | HTTP | `8000` | `8000` | Open `http://localhost:8000/docs` (Swagger UI) |
| **SSH Honeypot** | SSH | `2222` | `2222` | Run `ssh admin@localhost -p 2222` |
| **HTTP Honeypot** | HTTP | `8080` | `8080` | Open `http://localhost:8080/admin` in browser |
| **FTP Honeypot** | FTP | `2121` | `2121` | Connect using an FTP client to `localhost:2121` |
| **SMTP Honeypot** | SMTP | `2525` | `2525` | Telnet to `localhost:2525` or send mail test |

---

## 5. Troubleshooting Tips

### 1. Database Connection Retries
On startup, the honeypots and API might print connection retries. This is normal! The postgres container takes a few seconds to start up and run health checks. The application is built to wait and reconnect automatically.

### 2. Frontend Build is Slow
The first time you run `docker compose up --build`, Vite builds the frontend inside the container. This takes 1-2 minutes depending on your CPU. Subsequent starts will be almost instant as long as you do not run `--build`.
