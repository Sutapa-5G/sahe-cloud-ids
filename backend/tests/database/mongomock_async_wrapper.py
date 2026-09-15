"""
backend/tests/database/mongomock_async_wrapper.py

mongomock (the library used to simulate MongoDB for these tests) is
synchronous, but backend/app/database/repositories.py is written against
motor's async API (since the real production code uses motor). This
module provides a minimal async wrapper around mongomock's sync
collection/cursor objects, so the SAME repository code can be tested
against mongomock here and run against real motor/MongoDB in production
without any repository code changes.

This wrapper is a TEST-ONLY utility. It is not a general-purpose
async-mongomock library, and it doesn't need to be - it implements
exactly the subset of the motor API this project's repositories use.
"""
from __future__ import annotations

import mongomock


class AsyncCursorWrapper:
    def __init__(self, sync_cursor):
        self._cursor = sync_cursor

    def sort(self, *args, **kwargs):
        self._cursor = self._cursor.sort(*args, **kwargs)
        return self

    def limit(self, n):
        self._cursor = self._cursor.limit(n)
        return self

    async def to_list(self, length=None):
        docs = list(self._cursor)
        if length is not None:
            docs = docs[:length]
        return docs


class AsyncCollectionWrapper:
    def __init__(self, sync_collection):
        self._collection = sync_collection

    async def insert_one(self, doc):
        return self._collection.insert_one(doc)

    async def insert_many(self, docs):
        return self._collection.insert_many(docs)

    async def find_one(self, filter=None):
        return self._collection.find_one(filter)

    def find(self, filter=None):
        return AsyncCursorWrapper(self._collection.find(filter))

    def aggregate(self, pipeline):
        return AsyncCursorWrapper(self._collection.aggregate(pipeline))

    async def create_index(self, *args, **kwargs):
        return self._collection.create_index(*args, **kwargs)


class AsyncDatabaseWrapper:
    """Mimics enough of AsyncIOMotorDatabase's __getitem__ interface for
    repositories.py's `db["collection_name"]` usage."""

    def __init__(self, sync_db):
        self._db = sync_db

    def __getitem__(self, name):
        return AsyncCollectionWrapper(self._db[name])


def make_async_mongomock_db(db_name: str = "test_db") -> AsyncDatabaseWrapper:
    client = mongomock.MongoClient()
    return AsyncDatabaseWrapper(client[db_name])
