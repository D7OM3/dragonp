"""add_results_column_to_scan_results

Revision ID: 1efe4a0eeacb
Revises: d00a507ecbaf
Create Date: 2025-04-04 20:09:54.359528

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '1efe4a0eeacb'
down_revision = 'd00a507ecbaf'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('scan_results',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.String(length=36), nullable=False),
    sa.Column('target_domain', sa.String(length=255), nullable=False),
    sa.Column('scan_type', sa.String(length=50), nullable=False),
    sa.Column('start_time', sa.DateTime(), nullable=True),
    sa.Column('end_time', sa.DateTime(), nullable=True),
    sa.Column('status', sa.Enum('pending', 'in_progress', 'completed', 'failed', name='scan_status'), nullable=True),
    sa.Column('progress', sa.Integer(), nullable=True),
    sa.Column('current_tool', sa.String(length=100), nullable=True),
    sa.Column('results', postgresql.JSONB(astext_type=Text()), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('scan_id')
    )
    with op.batch_alter_table('scan_results', schema=None) as batch_op:
        batch_op.create_index('idx_scan_id', ['scan_id'], unique=False)
        batch_op.create_index('idx_scan_status', ['status'], unique=False)
        batch_op.create_index('idx_scan_target_domain', ['target_domain'], unique=False)

    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.Enum('admin', 'analyst', 'viewer', name='user_role'), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('last_login', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index('idx_user_email', ['email'], unique=False)
        batch_op.create_index('idx_user_role', ['role'], unique=False)

    op.create_table('scan_details',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('tool_name', sa.String(length=100), nullable=False),
    sa.Column('raw_output', sa.Text(), nullable=True),
    sa.Column('configuration', postgresql.JSONB(astext_type=Text()), nullable=True),
    sa.Column('error_logs', sa.Text(), nullable=True),
    sa.Column('performance_metrics', postgresql.JSONB(astext_type=Text()), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['scan_id'], ['scan_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('scan_details', schema=None) as batch_op:
        batch_op.create_index('idx_detail_scan_id', ['scan_id'], unique=False)
        batch_op.create_index('idx_detail_tool', ['tool_name'], unique=False)

    op.create_table('vulnerabilities',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_type', sa.String(length=100), nullable=False),
    sa.Column('severity', sa.Enum('critical', 'high', 'medium', 'low', 'info', name='severity_level'), nullable=False),
    sa.Column('status', sa.Enum('open', 'in-progress', 'resolved', 'closed', 'reopened', name='vulnerability_status'), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('affected_component', sa.String(length=255), nullable=True),
    sa.Column('remediation_steps', postgresql.JSONB(astext_type=Text()), nullable=True),
    sa.Column('cvss_score', sa.Float(), nullable=True),
    sa.Column('cve_ids', postgresql.JSONB(astext_type=Text()), nullable=True),
    sa.Column('proof_of_concept', sa.Text(), nullable=True),
    sa.Column('technical_details', postgresql.JSONB(astext_type=Text()), nullable=True),
    sa.Column('assigned_to', sa.String(length=100), nullable=True),
    sa.Column('resolution_notes', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['scan_id'], ['scan_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.create_index('idx_vuln_scan_id', ['scan_id'], unique=False)
        batch_op.create_index('idx_vuln_severity', ['severity'], unique=False)
        batch_op.create_index('idx_vuln_status', ['status'], unique=False)

    op.create_table('vulnerability_comments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.Integer(), nullable=False),
    sa.Column('author', sa.String(length=100), nullable=False),
    sa.Column('comment', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('vulnerability_comments', schema=None) as batch_op:
        batch_op.create_index('idx_comment_vuln_id', ['vulnerability_id'], unique=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('vulnerability_comments', schema=None) as batch_op:
        batch_op.drop_index('idx_comment_vuln_id')

    op.drop_table('vulnerability_comments')
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_index('idx_vuln_status')
        batch_op.drop_index('idx_vuln_severity')
        batch_op.drop_index('idx_vuln_scan_id')

    op.drop_table('vulnerabilities')
    with op.batch_alter_table('scan_details', schema=None) as batch_op:
        batch_op.drop_index('idx_detail_tool')
        batch_op.drop_index('idx_detail_scan_id')

    op.drop_table('scan_details')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index('idx_user_role')
        batch_op.drop_index('idx_user_email')

    op.drop_table('users')
    with op.batch_alter_table('scan_results', schema=None) as batch_op:
        batch_op.drop_index('idx_scan_target_domain')
        batch_op.drop_index('idx_scan_status')
        batch_op.drop_index('idx_scan_id')

    op.drop_table('scan_results')
    # ### end Alembic commands ###
