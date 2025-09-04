"""
Monitoring middleware for AuthX.
Tracks request metrics, performance, and system health.
"""
import time
import logging
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.services.monitoring_service import monitoring_service
from app.core.config import settings

logger = logging.getLogger(__name__)

class MonitoringMiddleware(BaseHTTPMiddleware):
    """Middleware for monitoring requests and performance metrics."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and collect metrics."""
        start_time = time.time()

        # Extract request info
        method = request.method
        path = request.url.path

        try:
            # Process request
            response = await call_next(request)

            # Calculate processing time
            process_time = time.time() - start_time

            # Record metrics
            if settings.MONITORING_ENABLED:
                await monitoring_service.record_request_metrics(
                    method=method,
                    endpoint=path,
                    status_code=response.status_code,
                    duration=process_time
                )

            # Add performance headers
            response.headers["X-Process-Time"] = str(process_time)

            # Log slow requests
            if process_time > 1.0:  # Log requests taking more than 1 second
                logger.warning(
                    f"Slow request: {method} {path} took {process_time:.2f}s "
                    f"(status: {response.status_code})"
                )

            return response

        except Exception as e:
            # Calculate processing time even for errors
            process_time = time.time() - start_time

            # Record error metrics
            if settings.MONITORING_ENABLED:
                await monitoring_service.record_request_metrics(
                    method=method,
                    endpoint=path,
                    status_code=500,
                    duration=process_time
                )

                # Create alert for server errors
                await monitoring_service.create_alert(
                    alert_type="server_error",
                    message=f"Server error on {method} {path}: {str(e)}",
                    severity="error"
                )

            logger.error(f"Request failed: {method} {path} - {str(e)}")
            raise
