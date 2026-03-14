from sqlalchemy.orm import Session
from database.models import HoneypotNode
from datetime import datetime
import uuid


class NodeManager:
    def __init__(self, db: Session):
        self.db = db

    def register_node(
        self, hostname: str, ip_address: str, honeypot_type: str
    ) -> HoneypotNode:
        """Registers a new honeypot node or updates an existing one."""
        node_id = str(uuid.uuid4())[:8]

        # Check if node with same hostname/IP exists
        existing_node = (
            self.db.query(HoneypotNode)
            .filter(
                (HoneypotNode.hostname == hostname)
                | (HoneypotNode.ip_address == ip_address)
            )
            .first()
        )

        if existing_node:
            existing_node.last_seen = datetime.utcnow()
            existing_node.status = "active"
            self.db.commit()
            return existing_node

        new_node = HoneypotNode(
            node_id=node_id,
            hostname=hostname,
            ip_address=ip_address,
            honeypot_type=honeypot_type,
            status="active",
        )
        self.db.add(new_node)
        self.db.commit()
        self.db.refresh(new_node)
        return new_node

    def update_heartbeat(self, node_id: str):
        """Updates the last_seen timestamp for a node."""
        node = (
            self.db.query(HoneypotNode).filter(HoneypotNode.node_id == node_id).first()
        )
        if node:
            node.last_seen = datetime.utcnow()
            node.status = "active"
            self.db.commit()
            return True
        return False

    def list_nodes(self):
        """Returns a list of all registered nodes."""
        return self.db.query(HoneypotNode).all()

    def get_node_by_id(self, node_id: str):
        """Retrieves a single node by its node_id."""
        return (
            self.db.query(HoneypotNode).filter(HoneypotNode.node_id == node_id).first()
        )
