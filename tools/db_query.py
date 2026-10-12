import asyncio
import time

from security import validate_db_query


def _serialize(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


async def _query_postgres(host, port, user, password, database, query, timeout, read_only):
    import asyncpg
    conn = await asyncio.wait_for(
        asyncpg.connect(host=host, port=port, user=user, password=password, database=database),
        timeout=timeout,
    )
    try:
        if read_only:
            async with conn.transaction(readonly=True):
                records = await asyncio.wait_for(conn.fetch(query), timeout=timeout)
        else:
            records = await asyncio.wait_for(conn.fetch(query), timeout=timeout)
        if records:
            columns = list(records[0].keys())
            rows = [{k: _serialize(v) for k, v in dict(r).items()} for r in records]
        else:
            columns = []
            rows = []
        return {"columns": columns, "rows": rows, "row_count": len(rows)}
    finally:
        await conn.close()


async def _query_mysql(host, port, user, password, database, query, timeout, read_only):
    import aiomysql
    conn = await asyncio.wait_for(
        aiomysql.connect(host=host, port=port, user=user, password=password,
                         db=database, connect_timeout=int(timeout),
                         client_flag=0),
        timeout=timeout,
    )
    try:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            if read_only:
                await cur.execute("START TRANSACTION READ ONLY")
            await asyncio.wait_for(cur.execute(query), timeout=timeout)
            rows = await cur.fetchall()
            columns = [d[0] for d in cur.description] if cur.description else []
            data = [{k: _serialize(v) for k, v in row.items()} for row in (rows or [])]
        # aiomysql opens the connection with autocommit off. Without an explicit
        # commit the server drops a confirmed change on close, after we reported it.
        if read_only:
            await conn.rollback()
        else:
            await conn.commit()
        return {"columns": columns, "rows": data, "row_count": len(data)}
    finally:
        conn.close()


async def db_query(args: dict) -> dict:
    db_type = args.get("type", "postgres").strip().lower()
    host = args.get("host", "").strip()
    user = args.get("user", "").strip()
    password = args.get("password", "").strip()
    database = args.get("database", "").strip()
    query = args.get("query", "").strip()
    confirmed = bool(args.get("confirmed", False))

    default_port = 5432 if db_type == "postgres" else 3306
    port = int(args.get("port", default_port))
    timeout = max(1.0, min(float(args.get("timeout", 30)), 120))

    if db_type not in ("postgres", "mysql"):
        return {"error": "type must be 'postgres' or 'mysql'", "outcome": "refused"}
    if not host:
        return {"error": "Parameter 'host' is required", "outcome": "refused"}
    if not user:
        return {"error": "Parameter 'user' is required", "outcome": "refused"}
    if not database:
        return {"error": "Parameter 'database' is required", "outcome": "refused"}
    if not query:
        return {"error": "Parameter 'query' is required", "outcome": "refused"}

    try:
        validate_db_query(query, confirmed)
    except (ValueError, PermissionError) as e:
        return {"error": str(e), "outcome": "refused"}

    # Without confirmation only queries that start like a read get this far, but the
    # first word is a claim, not a fact: 'WITH d AS (DELETE ...) SELECT' and
    # 'EXPLAIN ANALYZE DELETE' both write. A read-only transaction lets the server
    # itself refuse the write.
    read_only = not confirmed
    start = time.monotonic()
    try:
        if db_type == "postgres":
            result = await _query_postgres(host, port, user, password, database, query,
                                           timeout, read_only)
        else:
            result = await _query_mysql(host, port, user, password, database, query,
                                        timeout, read_only)
        result["duration_ms"] = round((time.monotonic() - start) * 1000)
        return result
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}",
                "duration_ms": round((time.monotonic() - start) * 1000)}
