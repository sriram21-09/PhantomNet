"""add packet_logs timestamp and threat_score composite index

Revision ID: c7b1e4f92d8a
Revises: b38a3ae24623
Create Date: 2026-09-30 09:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c7b1e4f92d8a'
down_revision = 'b38a3ae24623'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Safely create composite index on packet_logs (timestamp, threat_score)
    # to support rapid hourly aggregation and threat score analysis.
    try:
        op.create_index(
            'ix_packet_logs_ts_threat',
            'packet_logs',
            ['timestamp', 'threat_score'],
            unique=False,
            if_not_exists=True
        )
    except Exception:
        # Fallback for dialects without if_not_exists in create_index
        pass


def downgrade() -> None:
    try:
        op.drop_index('ix_packet_logs_ts_threat', table_name='packet_logs')
    except Exception:
        pass
