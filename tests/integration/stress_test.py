import asyncio
import time
import uuid
import random
import logging
import psutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from ml.threat_scoring_service import score_threat_batch
from schemas.threat_schema import ThreatInput
from database.database import SessionLocal, engine
from database.models import PacketLog, Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("stress_test")

class StressTestSimulator:
    def __init__(self, num_attackers=20, target_events=5000, num_honeypots=11):
        self.num_attackers = num_attackers
        self.target_events = target_events
        self.num_honeypots = num_honeypots
        self.db = SessionLocal()
        
    def setup_topology(self):
        """Mocks the topology for tracking the event impacts."""
        logger.info(f"Registering {self.num_honeypots} dummy honeypot nodes...")
        from services.node_manager import NodeManager
        manager = NodeManager(self.db)
        
        for i in range(self.num_honeypots):
            manager.register_node(f"stress-node-{i}", f"10.0.10.{i}", "http_honeypot")

    def _generate_attack_payload(self) -> ThreatInput:
        """Procedurally shapes variable test payloads mapping SSH, HTTP, and ICMP footprints."""
        protocols = ["TCP", "UDP", "ICMP"]
        attack_ips = [f"203.0.113.{random.randint(1, 200)}" for _ in range(self.num_attackers)]
        
        return ThreatInput(
            src_ip=random.choice(attack_ips),
            dst_ip=f"10.0.10.{random.randint(0, self.num_honeypots-1)}",
            dst_port=random.choice([22, 80, 443, 8080, 53]),
            protocol=random.choice(protocols),
            length=random.randint(40, 6500)
        )

    def worker_simulation(self, batch_size=100) -> dict:
        """Simulates one burst of traffic generation routed directly to the ML engine interface."""
        payloads = [self._generate_attack_payload() for _ in range(batch_size)]
        
        start = time.time()
        results = score_threat_batch(payloads)
        end = time.time()
        
        # Write directly to DB to simulate real app DB bound logic
        db_start = time.time()
        try:
            db = SessionLocal()
            logs = [
                PacketLog(
                    src_ip=p.src_ip,
                    dst_ip=p.dst_ip,
                    dst_port=p.dst_port,
                    protocol=p.protocol,
                    length=p.length,
                    threat_score=res.get("threat_score", 0.0),
                    threat_level=res.get("threat_level", "LOW")
                )
                for p, res in zip(payloads, results)
            ]
            db.add_all(logs)
            db.commit()
            db.close()
        except Exception as e:
            logger.error(f"DB Write failed: {e}")
        db_end = time.time()
        
        # Metrics 
        return {
            "ml_latency_ms": (end - start) * 1000,
            "db_latency_ms": (db_end - db_start) * 1000,
            "processed": len(results)
        }

    def run(self):
        """Spins up ThreadPool executing simulated network ingress streams concurrently."""
        Base.metadata.create_all(bind=engine)
        self.setup_topology()
        
        logger.info(f"Starting Stress Test: {self.num_attackers} Workers pumping {self.target_events} vectors.")
        
        batches = self.target_events // 100
        metrics = []
        
        # Profile hardware bounds prior
        cpu_start = psutil.cpu_percent()
        mem_start = psutil.virtual_memory().percent
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.num_attackers) as pool:
            futures = [pool.submit(self.worker_simulation, 100) for _ in range(batches)]
            for f in futures:
                metrics.append(f.result())
                
        total_time = time.time() - start_time
        
        # Profile hardware bounds post
        cpu_end = psutil.cpu_percent()
        mem_end = psutil.virtual_memory().percent
        
        # Aggregate logic
        ml_avg = sum(m["ml_latency_ms"] for m in metrics) / len(metrics)
        db_avg = sum(m["db_latency_ms"] for m in metrics) / len(metrics)
        processed_total = sum(m["processed"] for m in metrics)
        throughput = processed_total / total_time
        
        logger.info("=" * 40)
        logger.info(" STRESS TEST RESULTS ")
        logger.info("=" * 40)
        logger.info(f"Target Events   : {self.target_events}")
        logger.info(f"Total Processed : {processed_total}")
        logger.info(f"Execution Time  : {total_time:.2f} seconds")
        logger.info(f"Overall Rate    : {throughput:.2f} events/sec")
        logger.info(f"Avg ML Latency  : {ml_avg:.2f} ms (per batch of 100)")
        logger.info(f"Avg DB Latency  : {db_avg:.2f} ms (per batch of 100)")
        logger.info(f"CPU Utilization : {cpu_start}% -> {cpu_end}%")
        logger.info(f"RAM Utilization : {mem_start}% -> {mem_end}%")
        logger.info("=" * 40)

if __name__ == "__main__":
    import asyncio
    sim = StressTestSimulator(num_attackers=20, target_events=5000, num_honeypots=11)
    sim.run()
