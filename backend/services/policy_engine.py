from sqlalchemy.orm import Session
from database.models import Policy, HoneypotNode
import json


class PolicyEngine:
    def __init__(self, db: Session):
        self.db = db

    def create_policy(self, name: str, description: str, config: dict) -> Policy:
        """Creates a new policy."""
        new_policy = Policy(
            name=name, description=description, config=json.dumps(config)
        )
        self.db.add(new_policy)
        self.db.commit()
        self.db.refresh(new_policy)
        return new_policy

    def assign_policy_to_node(self, node_id: str, policy_id: int) -> bool:
        """Assigns a policy to a node."""
        node = (
            self.db.query(HoneypotNode).filter(HoneypotNode.node_id == node_id).first()
        )
        policy = self.db.query(Policy).filter(Policy.id == policy_id).first()

        if node and policy:
            node.policy_id = policy_id
            self.db.commit()
            return True
        return False

    def list_policies(self):
        """Returns a list of all policies."""
        return self.db.query(Policy).all()

    def get_policy_for_node(self, node_id: str):
        """Retrieves the policy configuration for a specific node."""
        node = (
            self.db.query(HoneypotNode).filter(HoneypotNode.node_id == node_id).first()
        )
        if node and node.policy_id:
            policy = self.db.query(Policy).filter(Policy.id == node.policy_id).first()
            if policy:
                return json.loads(policy.config)
        return None
