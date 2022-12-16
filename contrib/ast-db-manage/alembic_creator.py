#!/usr/bin/env python
"""Utilities to create SQL scripts from Asterisk's Alembic scripts

Copyright (C) 2013-2015, Digium, Inc.
Matt Jordan <mjordan@digium.com>
"""

import os
import sys
from alembic.config import Config
from alembic import command
from sqlalchemy.exc import SQLAlchemyError
from argparse import ArgumentParser


def create_db_script(database, script, output_location=None):
    """Create a database script

    Keyword Arguments:
    database A database to create a set of scripts for
    script A script to generate
    output_location Prefix of the directory to create the scripts in
    """
    prefix = output_location or os.curdir
    script_file = os.path.join(prefix, "{0}_{1}.sql".format(database, script))
    print("Creating script for database '%s' and schema '%s' as '%s'" 
                  % (database, script, script_file))
    with open(script_file, "w") as out_file:
        url = '{0}://root:password@localhost/asterisk'.format(database)
        config = Config()
        config.output_buffer = out_file
        config.set_main_option('script_location', script)
        config.set_main_option('sqlalchemy.url', url)
        try:
            command.upgrade(config, 'head', sql=True)
        except SQLAlchemyError as error:
            error.add_note("Unable to generate SQL for db '%s' and schema '%s"
                  % (database, script))
            raise


def main(argv=None):

    parser = ArgumentParser(prog="alembic_creator")

    parser.add_argument('-d', '--db', action='append', required=True,
                      dest='databases', help='Databases to generate')
    parser.add_argument('-s', '--schema', action='append', required=True,
                      dest='schemas', help='Schemas to generate SQL for')
    parser.add_argument('-o', '--output-dir', action='store',
                      dest='outputdir', help='SQL output directory')

    args = parser.parse_args()
    
    if args.outputdir:
        try:
            if not os.path.exists(args.outputdir):
                print("Directory '%s' doesn't exist.  Creating." % args.outputdir)
                os.makedirs(args.outputdir, mode=0o755, exist_ok=True);
                print("Directory '%s' created successfully" % args.outputdir)
        except OSError as error:
            print("Directory '%s' can not be created" % args.outputdir, file=sys.stderr)
            print(error, file=sys.stderr)
            return 1

    for db in args.databases:
        for schema in args.schemas:
            try:
                create_db_script(db, schema, args.outputdir)
            except Exception as error:
                print(str(error))
                return 1

    return 0


if __name__ == "__main__":
    main(sys.argv)
