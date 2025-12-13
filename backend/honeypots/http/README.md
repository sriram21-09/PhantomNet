# HTTP Honeypot

This honeypot simulates a fake admin login page running on **port 8080**.  
It captures every incoming request (GET / POST) and logs details such as:
- Source IP  
- Request method (GET / POST)  
- URL path  
- Headers  
- Submitted form data  

All logs are written into:
backend/logs/http_logs.jsonl
backend/logs/http_error.log

## 🧱 Build the Docker Image
Run this command inside the backend/honeypots/http directory:
docker build -t phantomnet-http .

## 🚀 Run the Honeypot
docker run -it -p 8080:8080 -v "C:\Users\vivekananda reddy\PhantomNet\backend\logs:/logs" phantomnet-http

This will:
- Run the container interactively (-it)
- Expose port 8080
- Mount your local logs directory so logs are saved in PhantomNet/backend/logs/

## 🔍 Testing the Honeypot
After running the container:
1. Open your browser and go to http://localhost:8080/admin  
2. Try submitting fake credentials  
3. Check your logs inside:
   backend/logs/http_logs.jsonl  
   backend/logs/http_error.log  
4. All requests and any errors will be automatically logged.

## 🧹 Stop the Container
To stop the honeypot:
docker ps
docker stop <container_id>

✅ Done!  
This README fully documents how to build, run, test, and stop your HTTP honeypot container.
