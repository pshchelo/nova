# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""change encryption_options to encryption_details

Revision ID: 7a919e29a911
Revises: ab450ba04102
Create Date: 2026-05-14 12:00:00
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7a919e29a911'
down_revision = 'ab450ba04102'
branch_labels = None
depends_on = None


def upgrade():
    for prefix in ('', 'shadow_'):
        table_name = prefix + 'block_device_mapping'
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.alter_column(
                'encryption_options',
                type_=sa.Text(),
                existing_type=sa.String(length=4096),
                new_column_name='encryption_details',
            )
