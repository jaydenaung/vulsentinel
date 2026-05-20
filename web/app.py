# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""FastAPI application factory."""

import logging

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
import os

from web.db import init_db, user_count
from web.routes import assets, auth_routes, cves, dashboard, scans, settings, setup_routes, users
from web.scheduler import start_scheduler, stop_scheduler

log = logging.getLogger(__name__)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def create_app() -> FastAPI:
    app = FastAPI(title="VulSentinel", docs_url=None, redoc_url=None)

    # Initialise DB on startup
    @app.on_event("startup")
    def startup() -> None:
        init_db()
        start_scheduler()
        log.info("VulSentinel server started")

    @app.on_event("shutdown")
    def shutdown() -> None:
        stop_scheduler()

    # Middleware: redirect to /setup if no users exist (except static assets)
    @app.middleware("http")
    async def setup_guard(request, call_next):
        path = request.url.path
        skip = path.startswith("/static") or path.startswith("/setup") or path.startswith("/api")
        if not skip and user_count() == 0:
            return RedirectResponse("/setup", status_code=303)
        return await call_next(request)

    # Static files
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # Routers
    app.include_router(setup_routes.router)
    app.include_router(auth_routes.router)
    app.include_router(dashboard.router)
    app.include_router(assets.router)
    app.include_router(cves.router)
    app.include_router(users.router)
    app.include_router(scans.router)
    app.include_router(settings.router)

    return app
