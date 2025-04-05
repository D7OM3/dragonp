"""Add scan_id and progress tracking fields

Revision ID: d00a507ecbaf
Revises: 2cb87780dfe8
Create Date: 2025-02-07 18:19:12.655172

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd00a507ecbaf'
down_revision = '2cb87780dfe8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('scan_results', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scan_id', sa.String(length=36), nullable=False))
        batch_op.add_column(sa.Column('progress', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('current_tool', sa.String(length=100), nullable=True))
        batch_op.alter_column('status',
               existing_type=sa.VARCHAR(length=50),
               type_=sa.Enum('pending', 'in_progress', 'completed', 'failed', name='scan_status'),
               existing_nullable=True,
               existing_server_default=sa.text("'pending'::character varying"))
        batch_op.create_index('idx_scan_id', ['scan_id'], unique=False)
        batch_op.create_unique_constraint(None, ['scan_id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('scan_results', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')
        batch_op.drop_index('idx_scan_id')
        batch_op.alter_column('status',
               existing_type=sa.Enum('pending', 'in_progress', 'completed', 'failed', name='scan_status'),
               type_=sa.VARCHAR(length=50),
               existing_nullable=True,
               existing_server_default=sa.text("'pending'::character varying"))
        batch_op.drop_column('current_tool')
        batch_op.drop_column('progress')
        batch_op.drop_column('scan_id')

    # ### end Alembic commands ###
