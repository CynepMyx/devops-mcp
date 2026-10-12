"""db_query talks to the database the way the confirmation promised.

Two defects these pin down, both reproduced against real postgres:16 and mysql:8.0:
- the validator judges a query by its first word, so 'WITH d AS (DELETE ...) SELECT'
  and 'EXPLAIN ANALYZE DELETE' deleted rows without confirmation. An unconfirmed
  query now runs in a read-only transaction and the server refuses the write;
- aiomysql opens connections with autocommit off and nothing committed, so a
  confirmed INSERT reported success and vanished when the connection closed.

The drivers are replaced with recorders, so the tests run without a database.
"""
import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tools.db_query import db_query


@pytest.fixture
def calls(monkeypatch):
    log = []

    class Tx:
        def __init__(self, readonly):
            self.readonly = readonly

        async def __aenter__(self):
            log.append(("begin", "read only" if self.readonly else "read write"))

        async def __aexit__(self, *exc):
            log.append(("end transaction",))

    class PgConn:
        def transaction(self, readonly=False, **_):
            return Tx(readonly)

        async def fetch(self, query):
            log.append(("query", query))
            return []

        async def close(self):
            log.append(("close",))

    async def pg_connect(**_):
        return PgConn()

    class Cursor:
        description = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def execute(self, query):
            log.append(("query", query))

        async def fetchall(self):
            return []

    class MyConn:
        def cursor(self, *_):
            return Cursor()

        async def commit(self):
            log.append(("commit",))

        async def rollback(self):
            log.append(("rollback",))

        def close(self):
            log.append(("close",))

    async def my_connect(**_):
        return MyConn()

    monkeypatch.setitem(sys.modules, "asyncpg", types.SimpleNamespace(connect=pg_connect))
    monkeypatch.setitem(sys.modules, "aiomysql",
                        types.SimpleNamespace(connect=my_connect, DictCursor=object))
    return log


def _run(db_type, query, confirmed):
    args = {"type": db_type, "host": "db", "user": "u", "password": "p", "database": "d",
            "query": query, "confirmed": confirmed}
    return asyncio.run(db_query(args))


def test_postgres_unconfirmed_query_runs_read_only(calls):
    _run("postgres", "WITH d AS (DELETE FROM t RETURNING *) SELECT count(*) FROM d", False)
    assert calls[0] == ("begin", "read only")
    assert calls[1][0] == "query"


def test_postgres_confirmed_query_is_not_forced_read_only(calls):
    _run("postgres", "DELETE FROM t WHERE id = 1", True)
    assert ("begin", "read only") not in calls
    assert ("query", "DELETE FROM t WHERE id = 1") in calls


def test_mysql_confirmed_write_is_committed(calls):
    _run("mysql", "INSERT INTO t VALUES (1)", True)
    query_at = calls.index(("query", "INSERT INTO t VALUES (1)"))
    assert ("commit",) in calls[query_at:]
    assert ("rollback",) not in calls


def test_mysql_unconfirmed_query_runs_read_only_and_never_commits(calls):
    _run("mysql", "SELECT * FROM t", False)
    assert calls[0] == ("query", "START TRANSACTION READ ONLY")
    assert calls[1] == ("query", "SELECT * FROM t")
    assert ("commit",) not in calls
    assert ("rollback",) in calls


# Functions called through SELECT that act rather than read. The read-only
# transaction does not stop them (they are not writes), so they need confirmation.
ACTION_FUNCTIONS = [
    "SELECT pg_terminate_backend(12345)",
    "SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE state = 'active'",
    "select PG_RELOAD_CONF()",
    "SELECT pg_rotate_logfile()",
    "SELECT pg_promote()",
    "WITH s AS (SELECT pid FROM pg_stat_activity) SELECT pg_terminate_backend (pid) FROM s",
    # third pass (12.10.2026): hidden from the comment stripper, or spelled another way
    "SELECT '--', pg_terminate_backend(1)",
    "SELECT 1 # 2, pg_terminate_backend(pid) FROM pg_stat_activity",
    'SELECT "pg_terminate_backend"(1)',
    'SELECT pg_catalog."pg_cancel_backend"(1)',
    "SELECT U&\"\\0070g_terminate_backend\"(1)",
    "SELECT query_to_xml('select pg_termi'||'nate_backend(1)', true, true, '')",
    "SELECT dblink_exec('dbname=x', 'DELETE FROM t')",
    "SELECT pg_switch_wal()",
    "SELECT pg_drop_replication_slot('s')",
    "SELECT pg_stat_statements_reset()",
]


@pytest.mark.parametrize("query", [
    "SELECT '#'; COMMIT; DELETE FROM t; COMMIT",   # deleted every row on mysql:8.0
    "SELECT '--'; COMMIT; DELETE FROM t",
    "SELECT 1 /* ; */; DELETE FROM t",
])
def test_statements_hidden_behind_a_comment_marker_are_refused(query):
    from security import validate_db_query
    with pytest.raises(ValueError, match="Multi-statement"):
        validate_db_query(query, False)


@pytest.mark.parametrize("query", [
    "SELECT '#', 1 INTO OUTFILE '/var/lib/mysql-files/x'",   # wrote the file on mysql:8.0
    "SELECT 1 /*! INTO OUTFILE '/var/lib/mysql-files/x' */",  # MySQL runs /*! */
    "SELECT 1--1 INTO DUMPFILE '/tmp/x'",
    "SELECT 1 INTO/**/OUTFILE '/tmp/x'",
    "SELECT 1 INTO/*! */ /*!OUTFILE*/ '/tmp/x'",
    "SELECT 1 INTO/*!50000 OUTFILE*/ '/tmp/x'",
    "SELECT pg_file_write('/tmp/x', 'y', false)",
])
def test_file_writes_hidden_from_the_stripper_are_refused(query):
    from security import validate_db_query
    with pytest.raises(PermissionError):
        validate_db_query(query, False)


@pytest.mark.parametrize("query", ACTION_FUNCTIONS)
def test_action_functions_need_confirmation(query):
    from security import validate_db_query
    with pytest.raises(ValueError, match="confirmation"):
        validate_db_query(query, False)
    validate_db_query(query, True)


@pytest.mark.parametrize("query", [
    "SELECT pid, state, query FROM pg_stat_activity",
    "SELECT pg_read_binary_file('/etc/hostname')",
    "SELECT 'pg_terminate_backend is mentioned in a string'",
    "SELECT slot_name, active FROM pg_replication_slots",
    "SELECT * FROM pg_stat_activity -- who is connected",
    "SELECT 1;",
])
def test_reads_stay_free(query):
    from security import validate_db_query
    validate_db_query(query, False)
