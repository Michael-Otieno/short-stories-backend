"""Initial migration.

Revision ID: 18a0291450ca
Revises: 
Create Date: 2021-09-29 17:02:18.054037

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '18a0291450ca'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('username', sa.VARCHAR(length=50), autoincrement=False, nullable=True),
    sa.Column('email', sa.VARCHAR(length=50), autoincrement=False, nullable=True),
    sa.Column('password', sa.VARCHAR(length=15), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='user_pkey'),
    sa.UniqueConstraint('email', name='user_email_key')
    )
    # ### end Alembic commands ###