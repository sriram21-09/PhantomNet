# PhantomNet Architecture
+------------------+
|    Attacker      |
+--------+---------+
         |
         v
+------------------------+
|   SSH Honeypot (2222) |
+------------------------+
         |
   writes logs to
   data/logs/ssh/
         |
         v
+------------------------+
|   AI Log Ingestor      |
+------------------------+
         |
 Save parsed events to DB
         |
         v
+------------------------+
|   FastAPI Backend      |
|   (REST API)           |
+------------------------+
         |
         v
+------------------------+
|  PostgreSQL Database   |
+------------------------+
