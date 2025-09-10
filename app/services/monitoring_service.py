"""
System Monitoring Service for AuthX.
Provides comprehensive monitoring, metrics collection, and health checks for enterprise deployment.
"""
import asyncio
import logging
import time
import psutil
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.config import settings
from app.db.session import get_async_db

logger = logging.getLogger(__name__)

@dataclass
class SystemMetrics:
    """System metrics data structure."""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    database_connections: int
    redis_connections: int
    response_time_avg: float
    error_rate: float
    active_users: int

@dataclass
class HealthCheck:
    """Health check result structure."""
    service: str
    status: str  # healthy, degraded, unhealthy
    response_time: float
    details: Dict[str, Any]
    timestamp: datetime

class SystemMonitoringService:
    """Comprehensive system monitoring service."""

    def __init__(self):
        self.redis_client = None
        self.metrics_history: List[SystemMetrics] = []
        self.health_checks: Dict[str, HealthCheck] = {}
        self._monitoring_started = False

        # Prometheus metrics
        self.request_count = Counter('authx_requests_total', 'Total requests', ['method', 'endpoint', 'status'])
        self.request_duration = Histogram('authx_request_duration_seconds', 'Request duration', ['method', 'endpoint'])
        self.active_users_gauge = Gauge('authx_active_users', 'Number of active users')
        self.database_connections_gauge = Gauge('authx_database_connections', 'Database connections')
        self.redis_connections_gauge = Gauge('authx_redis_connections', 'Redis connections')
        self.system_cpu_gauge = Gauge('authx_system_cpu_usage', 'System CPU usage percentage')
        self.system_memory_gauge = Gauge('authx_system_memory_usage', 'System memory usage percentage')
        self.system_disk_gauge = Gauge('authx_system_disk_usage', 'System disk usage percentage')
        self.error_rate_gauge = Gauge('authx_error_rate', 'Error rate percentage')

    async def start_monitoring(self):
        """Start monitoring tasks - call this when the application starts."""
        if not self._monitoring_started and settings.MONITORING_ENABLED:
            self._monitoring_started = True
            asyncio.create_task(self._start_monitoring())

    async def _start_monitoring(self):
        """Start background monitoring tasks."""
        try:
            # Initialize Redis connection
            if settings.REDIS_ENABLED:
                self.redis_client = redis.from_url(settings.REDIS_URL)

            # Schedule monitoring tasks
            while True:
                try:
                    await self.collect_metrics()
                    await self.perform_health_checks()
                    await asyncio.sleep(settings.HEALTH_CHECK_INTERVAL)
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {str(e)}")
                    await asyncio.sleep(30)  # Wait before retrying

        except Exception as e:
            logger.error(f"Failed to start monitoring: {str(e)}")

    async def collect_metrics(self) -> SystemMetrics:
        """Collect system metrics."""
        try:
            # System metrics
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            # Database metrics
            db_connections = await self._get_database_connections()

            # Redis metrics
            redis_connections = await self._get_redis_connections()

            # Application metrics
            response_time_avg = await self._get_average_response_time()
            error_rate = await self._get_error_rate()
            active_users = await self._get_active_users_count()

            metrics = SystemMetrics(
                timestamp=datetime.utcnow(),
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                disk_usage=disk.percent,
                database_connections=db_connections,
                redis_connections=redis_connections,
                response_time_avg=response_time_avg,
                error_rate=error_rate,
                active_users=active_users
            )

            # Update Prometheus metrics
            self.system_cpu_gauge.set(cpu_usage)
            self.system_memory_gauge.set(memory.percent)
            self.system_disk_gauge.set(disk.percent)
            self.database_connections_gauge.set(db_connections)
            self.redis_connections_gauge.set(redis_connections)
            self.active_users_gauge.set(active_users)
            self.error_rate_gauge.set(error_rate)

            # Store in history (keep last 24 hours)
            self.metrics_history.append(metrics)
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            self.metrics_history = [m for m in self.metrics_history if m.timestamp > cutoff_time]

            logger.debug(f"Collected metrics: CPU {cpu_usage}%, Memory {memory.percent}%, Disk {disk.percent}%")
            return metrics

        except Exception as e:
            logger.error(f"Error collecting metrics: {str(e)}")
            raise

    async def perform_health_checks(self):
        """Perform health checks on various services."""
        try:
            # Database health check
            await self._check_database_health()

            # Redis health check
            if settings.REDIS_ENABLED:
                await self._check_redis_health()

            # External services health checks
            # if settings.GOOGLE_MAPS_API_KEY:
            #     await self._check_google_maps_health()

            # SMTP health check
            # if settings.SMTP_SERVER:
            #     await self._check_smtp_health()

        except Exception as e:
            logger.error(f"Error performing health checks: {str(e)}")

    async def _check_database_health(self):
        """Check database health."""
        start_time = time.time()
        try:
            async with get_async_db() as db:
                result = await db.execute(text("SELECT 1"))
                await result.fetchone()

            response_time = time.time() - start_time
            self.health_checks['database'] = HealthCheck(
                service='database',
                status='healthy',
                response_time=response_time,
                details={'connection': 'successful'},
                timestamp=datetime.utcnow()
            )

        except Exception as e:
            response_time = time.time() - start_time
            self.health_checks['database'] = HealthCheck(
                service='database',
                status='unhealthy',
                response_time=response_time,
                details={'error': str(e)},
                timestamp=datetime.utcnow()
            )

    async def _check_redis_health(self):
        """Check Redis health."""
        start_time = time.time()
        try:
            if self.redis_client:
                await self.redis_client.ping()
                response_time = time.time() - start_time
                self.health_checks['redis'] = HealthCheck(
                    service='redis',
                    status='healthy',
                    response_time=response_time,
                    details={'connection': 'successful'},
                    timestamp=datetime.utcnow()
                )

        except Exception as e:
            response_time = time.time() - start_time
            self.health_checks['redis'] = HealthCheck(
                service='redis',
                status='unhealthy',
                response_time=response_time,
                details={'error': str(e)},
                timestamp=datetime.utcnow()
            )

    async def _check_google_maps_health(self):
        """Check Google Maps API health."""
        start_time = time.time()
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://maps.googleapis.com/maps/api/geocode/json",
                    params={
                        "address": "1600 Amphitheatre Parkway, Mountain View, CA",
                        "key": settings.GOOGLE_MAPS_API_KEY
                    },
                    timeout=10
                )

            response_time = time.time() - start_time
            if response.status_code == 200:
                self.health_checks['google_maps'] = HealthCheck(
                    service='google_maps',
                    status='healthy',
                    response_time=response_time,
                    details={'api_response': 'successful'},
                    timestamp=datetime.utcnow()
                )
            else:
                self.health_checks['google_maps'] = HealthCheck(
                    service='google_maps',
                    status='degraded',
                    response_time=response_time,
                    details={'status_code': response.status_code},
                    timestamp=datetime.utcnow()
                )

        except Exception as e:
            response_time = time.time() - start_time
            self.health_checks['google_maps'] = HealthCheck(
                service='google_maps',
                status='unhealthy',
                response_time=response_time,
                details={'error': str(e)},
                timestamp=datetime.utcnow()
            )

    async def _check_smtp_health(self):
        """Check SMTP server health."""
        start_time = time.time()
        try:
            import aiosmtplib
            smtp_client = aiosmtplib.SMTP(
                hostname=settings.SMTP_SERVER,
                port=settings.SMTP_PORT,
                use_tls=settings.SMTP_USE_TLS
            )
            await smtp_client.connect()
            await smtp_client.quit()

            response_time = time.time() - start_time
            self.health_checks['smtp'] = HealthCheck(
                service='smtp',
                status='healthy',
                response_time=response_time,
                details={'connection': 'successful'},
                timestamp=datetime.utcnow()
            )

        except Exception as e:
            response_time = time.time() - start_time
            self.health_checks['smtp'] = HealthCheck(
                service='smtp',
                status='unhealthy',
                response_time=response_time,
                details={'error': str(e)},
                timestamp=datetime.utcnow()
            )

    async def _get_database_connections(self) -> int:
        """Get current database connection count."""
        try:
            async with get_async_db() as db:
                result = await db.execute(text("SELECT count(*) FROM pg_stat_activity"))
                count = await result.scalar()
                return count or 0
        except Exception:
            return 0

    async def _get_redis_connections(self) -> int:
        """Get current Redis connection count."""
        try:
            if self.redis_client:
                info = await self.redis_client.info()
                return info.get('connected_clients', 0)
            return 0
        except Exception:
            return 0

    async def _get_average_response_time(self) -> float:
        """Calculate average response time from recent metrics."""
        try:
            if self.redis_client:
                # Get response times from Redis (stored by middleware)
                response_times = await self.redis_client.lrange("response_times", 0, 99)
                if response_times:
                    times = [float(rt) for rt in response_times]
                    return sum(times) / len(times)
            return 0.0
        except Exception:
            return 0.0

    async def _get_error_rate(self) -> float:
        """Calculate error rate from recent metrics."""
        try:
            if self.redis_client:
                # Get error count and total requests from Redis
                errors = await self.redis_client.get("error_count_last_hour") or 0
                total = await self.redis_client.get("request_count_last_hour") or 1
                return (float(errors) / float(total)) * 100
            return 0.0
        except Exception:
            return 0.0

    async def _get_active_users_count(self) -> int:
        """Get count of active users in the last hour."""
        try:
            if self.redis_client:
                # Count active sessions in Redis
                keys = await self.redis_client.keys("session:*")
                return len(keys)
            return 0
        except Exception:
            return 0

    def get_current_metrics(self) -> Optional[SystemMetrics]:
        """Get the most recent metrics."""
        return self.metrics_history[-1] if self.metrics_history else None

    def get_metrics_history(self, hours: int = 24) -> List[SystemMetrics]:
        """Get metrics history for specified hours."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return [m for m in self.metrics_history if m.timestamp > cutoff_time]

    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status."""
        overall_status = "healthy"
        unhealthy_services = []
        degraded_services = []

        for service, health_check in self.health_checks.items():
            if health_check.status == "unhealthy":
                overall_status = "unhealthy"
                unhealthy_services.append(service)
            elif health_check.status == "degraded" and overall_status == "healthy":
                overall_status = "degraded"
                degraded_services.append(service)

        return {
            "status": overall_status,
            "timestamp": datetime.utcnow().isoformat(),
            "services": {service: asdict(check) for service, check in self.health_checks.items()},
            "unhealthy_services": unhealthy_services,
            "degraded_services": degraded_services
        }

    def get_prometheus_metrics(self) -> str:
        """Get Prometheus formatted metrics."""
        return generate_latest()

    async def record_request_metrics(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record request metrics for monitoring."""
        # Update Prometheus metrics
        self.request_count.labels(method=method, endpoint=endpoint, status=str(status_code)).inc()
        self.request_duration.labels(method=method, endpoint=endpoint).observe(duration)

        # Store in Redis for real-time calculations
        if self.redis_client:
            try:
                # Store response time
                await self.redis_client.lpush("response_times", duration)
                await self.redis_client.ltrim("response_times", 0, 999)  # Keep last 1000

                # Update request counters
                await self.redis_client.incr("request_count_last_hour")
                await self.redis_client.expire("request_count_last_hour", 3600)

                if status_code >= 400:
                    await self.redis_client.incr("error_count_last_hour")
                    await self.redis_client.expire("error_count_last_hour", 3600)

            except Exception as e:
                logger.error(f"Error recording request metrics: {str(e)}")

    async def create_alert(self, alert_type: str, message: str, severity: str = "warning"):
        """Create system alert."""
        alert = {
            "type": alert_type,
            "message": message,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "service": "authx"
        }

        try:
            if self.redis_client:
                await self.redis_client.lpush("system_alerts", json.dumps(alert))
                await self.redis_client.ltrim("system_alerts", 0, 99)  # Keep last 100 alerts

            logger.warning(f"System Alert [{severity}]: {message}")

        except Exception as e:
            logger.error(f"Error creating alert: {str(e)}")

    async def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent system alerts."""
        try:
            if self.redis_client:
                alerts_json = await self.redis_client.lrange("system_alerts", 0, limit - 1)
                return [json.loads(alert) for alert in alerts_json]
            return []
        except Exception as e:
            logger.error(f"Error getting alerts: {str(e)}")
            return []

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary for the last 24 hours."""
        recent_metrics = self.get_metrics_history(24)

        if not recent_metrics:
            return {"status": "no_data"}

        # Calculate averages and peaks
        cpu_values = [m.cpu_usage for m in recent_metrics]
        memory_values = [m.memory_usage for m in recent_metrics]
        response_times = [m.response_time_avg for m in recent_metrics]
        error_rates = [m.error_rate for m in recent_metrics]

        return {
            "period": "24_hours",
            "metrics_count": len(recent_metrics),
            "cpu": {
                "average": sum(cpu_values) / len(cpu_values),
                "peak": max(cpu_values),
                "current": cpu_values[-1] if cpu_values else 0
            },
            "memory": {
                "average": sum(memory_values) / len(memory_values),
                "peak": max(memory_values),
                "current": memory_values[-1] if memory_values else 0
            },
            "response_time": {
                "average": sum(response_times) / len(response_times),
                "peak": max(response_times),
                "current": response_times[-1] if response_times else 0
            },
            "error_rate": {
                "average": sum(error_rates) / len(error_rates),
                "peak": max(error_rates),
                "current": error_rates[-1] if error_rates else 0
            }
        }

# Global service instance
monitoring_service = SystemMonitoringService()
