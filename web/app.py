# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""FastAPI application factory."""

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from settings import require_secret_key
from web.db import init_db, user_count
from web.routes import (
    auth_routes,
    checks,
    critical,
    cves,
    dashboard,
    products,
    settings,
    setup_routes,
    users,
)
from web.scheduler import start_scheduler, stop_scheduler
from web.security import apply_security, csrf_protect

log = logging.getLogger(__name__)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
ROUTERS = [setup_routes, auth_routes, dashboard, critical, products, cves, users, checks, settings]


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    init_db()
    start_scheduler()
    log.info("VulSentinel server started")
    yield
    stop_scheduler()


def create_app(start_background: bool = True) -> FastAPI:
    require_secret_key()  # fail fast, before binding a port, if the key is missing or weak

    app = FastAPI(
        title="VulSentinel", docs_url=None, redoc_url=None, openapi_url=None,
        lifespan=lifespan if start_background else None,
    )

    @app.middleware("http")
    async def guard_and_headers(request: Request, call_next):
        path = request.url.path
        skip = path.startswith(("/static", "/setup", "/api"))
        if not skip and user_count() == 0:
            response = RedirectResponse("/setup", status_code=303)
        else:
            response = await call_next(request)
        return apply_security(request, response)

    @app.exception_handler(RequestValidationError)
    async def bad_request(request: Request, exc: RequestValidationError):
        log.info("Rejected invalid input on %s %s", request.method, request.url.path)
        return PlainTextResponse("Bad request", status_code=400)

    @app.exception_handler(Exception)
    async def server_error(request: Request, exc: Exception):
        log.exception("Unhandled error on %s %s", request.method, request.url.path)
        return PlainTextResponse("Internal server error", status_code=500)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    for module in ROUTERS:
        app.include_router(module.router, dependencies=[Depends(csrf_protect)])

    return app
