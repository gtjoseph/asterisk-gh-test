# Asterisk Database Manager

Asterisk includes optional database integration for a variety of features.
The purpose of this effort is to assist in managing the database schema
for Asterisk database integration.

This is implemented as a set of repositories that contain database schema
migrations, using [Alembic](http://alembic.readthedocs.org).  The existing
repositories include:

 * `cdr` - Table used for Asterisk to store CDR records
 * `config` - Tables used for Asterisk realtime configuration
 * `queue_log` - Table used for Asterisk to store Queue Log records
 * `voicemail` - Tables used for `ODBC_STORAGE` of voicemail messages

Alembic uses SQLAlchemy, which has support for
[many databases](http://docs.sqlalchemy.org/en/rel_0_8/dialects/index.html).


## Example Usage

First, create an ini file that contains database connection details.  For help
with connection string details, see the
[SQLAlchemy docs](http://docs.sqlalchemy.org/en/rel_0_8/core/engines.html#database-urls).

    $ cp config.ini.sample config.ini
    ... edit config.ini and change sqlalchemy.url ...

Next, bring the database up to date with the current schema.

    $ alembic -c config.ini upgrade head

In the future, as additional database migrations are added, you can run
alembic again to migrate the existing tables to the latest schema.

    $ alembic -c config.ini upgrade head

The migrations support both upgrading and downgrading.  You could go all the
way back to where you started with no tables by downgrading back to the base
revision.

    $ alembic -c config.ini downgrade base

`base` and `head` are special revisions.  You can refer to specific revisions
to upgrade or downgrade to, as well.

    $ alembic -c config.ini upgrade 4da0c5f79a9c

## Offline Mode

If you would like to just generate the SQL statements that would have been
executed, you can use alembic's offline mode.

    $ alembic -c config.ini upgrade head --sql

## Adding Database Migrations

The best way to learn about how to add additional database migrations is to
refer to the [Alembic documentation](http://alembic.readthedocs.org).

### Notes

* For boolean columns, always use the AST_BOOL_VALUES type.  
  Example:

```
from alembic import op
import sqlalchemy as sa
# This works for MySQL/MariaDB and others as well
from sqlalchemy.dialects.postgresql import ENUM

AST_BOOL_NAME = 'ast_bool_values'
AST_BOOL_VALUES = [ '0', '1',
                    'off', 'on',
                    'false', 'true',
                    'no', 'yes' ]

def upgrade():
    # ast_bool_values have already been created, so use postgres enum object type
    # to get around "already created" issue - works okay with MySQL/MariaDB and others.
    ast_bool_values = ENUM(*AST_BOOL_VALUES, name=AST_BOOL_NAME, create_type=False)
    op.add_column('ps_endpoints', sa.Column('suppress_moh_on_sendonly', ast_bool_values))

def downgrade():
    if op.get_context().bind.dialect.name == 'mssql':
        op.drop_constraint('ck_ps_endpoints_suppress_moh_on_sendonly_ast_bool_values', 'ps_endpoints')
    op.drop_column('ps_endpoints', 'suppress_moh_on_sendonly')
```


Older scripts used YESNO_VALUES but that is no longer supported.

