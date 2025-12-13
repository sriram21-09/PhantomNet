# SSH Honeypot

## Location
This honeypot is located in:
phantomnet/backend/honeypots/ssh.py

## How to Run
1. Go to the honeypots folder:
   cd phantomnet/backend/honeypots

2. Run the honeypot:
   python ssh.py

3. Test it:
   nc localhost 2222
   or
   ssh -p 2222 localhost
   or
   telnet localhost 2222

## Log Files
Logs are stored in:
phantomnet/backend/logs/ssh.log
phantomnet/backend/logs/ssh.jsonl
phantomnet/backend/logs/ssh_error.log

## Features
- Accepts connections on port 2222
- Captures username & password
- Allows 3 login attempts
- Fake shell commands: ls, pwd, whoami, cd, exit
- Creates JSON logs for AIML team

## Default Credentials
Username: PhantomNet  
Password: 1234

RUN IN DOCKER :- 
docker build -t phantomnet-ssh .
docker run -it -p 2222:2222 -v "C:\Users\vivekananda reddy\PhantomNet\backend\logs:/logs" phantomnet-ssh

Note :- keep your desktop docker application running and replace this [ "C:\Users\vivekananda reddy\PhantomNet\backend\logs:/logs" phantomnet-ssh ]with your file structure.