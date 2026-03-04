# Advanced Deception Techniques

PhantomNet employs sophisticated deception techniques to make honeypots indistinguishable from real production systems and to actively frustrate attackers.

## 1. Fake Service Banners

Honeypots are configured to spoof realistic banners and headers.

### SSH
- **Version Spoofing**: Randomly selects between common OpenSSH versions (e.g., `OpenSSH_8.2p1`).
- **Interactive Prompts**: Provides realistic `login as:` and `password:` prompts.
- **Authentication Delays**: Implements timing delays to mimic real authentication processing.

### HTTP
- **Custom Headers**: Spoof `Server` (Apache, nginx, IIS) and `X-Powered-By` (PHP, ASP.NET) headers.
- **Deceptive Routes**:
    - `/admin`, `/wp-admin`, `/phpmyadmin`: Realistic-looking login panels.
    - `/files/`: Simulated directory listing with decoy files (`backup.sql`, `config.php.bak`).

### SMTP & FTP
- **Mail Server Greetings**: Realistic ESMTP Postfix/Exim greetings.
- **FTP Banners**: Spoof `vsFTPd 3.0.3` with interactive login sequence.

## 2. Credential Trap System

Located in `security-dev/deception/credential_traps.py`, this system manages "honeytokens."

- **Honeytoken Generation**: Creates realistic username/password pairs.
- **Seeding**: Automatically seeds "fake" configuration files with honeytokens.
- **Monitoring**: Detects when a honeytoken is used and logs the source of the compromise.
- **Database**: Stores all tokens and usage history in `data/honeytokens.db`.

## 3. Dynamic Response Behaviors

Managed by `security-dev/deception/adaptive_behavior.py`.

### Behavior Profiles
- **Vulnerable**: Low delays, high banner randomization to attract probes.
- **Hardened**: High delays, obfuscated responses to frustrate experienced attackers.
- **Interactive**: Medium delays, provides detailed feedback to keep attackers engaged.

### Tarpitting
Implements exponential backoff for repeated failed attempts. This slows down brute-force attacks significantly without blocking the IP, keeping the attacker "trapped" in the session.

## Configuration

Behavior profiles can be toggled in each honeypot script by initializing the `AdaptiveEngine` with the desired profile name.
