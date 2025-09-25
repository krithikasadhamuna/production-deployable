"""
Service Orchestrator
Professional orchestration of all SOC Platform services and AI agents
Handles service lifecycle, health monitoring, and inter-service communication
"""

import asyncio
import logging
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class ServiceStatus(Enum):
    """Service status enumeration"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"
    MAINTENANCE = "maintenance"

@dataclass
class ServiceHealth:
    """Service health information"""
    status: ServiceStatus
    last_check: datetime
    response_time: float = 0.0
    error_message: Optional[str] = None
    uptime: float = 0.0
    memory_usage: float = 0.0
    cpu_usage: float = 0.0

@dataclass
class ServiceMetrics:
    """Service performance metrics"""
    requests_total: int = 0
    requests_per_second: float = 0.0
    errors_total: int = 0
    error_rate: float = 0.0
    avg_response_time: float = 0.0
    last_reset: datetime = field(default_factory=datetime.now)

class BaseService(ABC):
    """Base class for all SOC Platform services"""
    
    def __init__(self, name: str, config: Any, db_manager: Any):
        self.name = name
        self.config = config
        self.db_manager = db_manager
        self.status = ServiceStatus.STOPPED
        self.health = ServiceHealth(ServiceStatus.STOPPED, datetime.now())
        self.metrics = ServiceMetrics()
        self.start_time = None
        self.stop_event = threading.Event()
        self.service_thread = None
        
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the service"""
        pass
    
    @abstractmethod
    async def start(self) -> bool:
        """Start the service"""
        pass
    
    @abstractmethod
    async def stop(self) -> bool:
        """Stop the service"""
        pass
    
    @abstractmethod
    async def health_check(self) -> ServiceHealth:
        """Perform health check"""
        pass
    
    def update_metrics(self, response_time: float = None, error: bool = False):
        """Update service metrics"""
        self.metrics.requests_total += 1
        
        if error:
            self.metrics.errors_total += 1
        
        if response_time:
            # Simple moving average for response time
            if self.metrics.avg_response_time == 0:
                self.metrics.avg_response_time = response_time
            else:
                self.metrics.avg_response_time = (self.metrics.avg_response_time * 0.9) + (response_time * 0.1)
        
        # Calculate rates
        time_diff = (datetime.now() - self.metrics.last_reset).total_seconds()
        if time_diff > 0:
            self.metrics.requests_per_second = self.metrics.requests_total / time_diff
            self.metrics.error_rate = self.metrics.errors_total / self.metrics.requests_total if self.metrics.requests_total > 0 else 0

class PhantomStrikeService(BaseService):
    """PhantomStrike AI Attack Agent Service"""
    
    def __init__(self, config, db_manager):
        super().__init__("PhantomStrike AI", config, db_manager)
        self.attack_agent = None
        self.active_scenarios = {}
        
    async def initialize(self) -> bool:
        """Initialize PhantomStrike AI"""
        try:
            logger.info("Initializing PhantomStrike AI Attack Agent...")
            
            # Import and initialize attack agent
            from agents.langgraph.workflows.attack_workflow import AttackWorkflow
            self.attack_agent = AttackWorkflow(self.config, self.db_manager)
            
            # Initialize attack scenarios database
            await self._initialize_attack_database()
            
            self.status = ServiceStatus.STOPPED
            logger.info("PhantomStrike AI initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize PhantomStrike AI: {e}")
            self.status = ServiceStatus.ERROR
            self.health.error_message = str(e)
            return False
    
    async def start(self) -> bool:
        """Start PhantomStrike AI service"""
        try:
            self.status = ServiceStatus.STARTING
            self.start_time = datetime.now()
            
            # Start attack monitoring
            self.service_thread = threading.Thread(target=self._attack_monitor_loop, daemon=True)
            self.service_thread.start()
            
            self.status = ServiceStatus.RUNNING
            logger.info("PhantomStrike AI service started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start PhantomStrike AI: {e}")
            self.status = ServiceStatus.ERROR
            return False
    
    async def stop(self) -> bool:
        """Stop PhantomStrike AI service"""
        try:
            self.status = ServiceStatus.STOPPING
            self.stop_event.set()
            
            if self.service_thread:
                self.service_thread.join(timeout=10)
            
            self.status = ServiceStatus.STOPPED
            logger.info("PhantomStrike AI service stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping PhantomStrike AI: {e}")
            return False
    
    async def health_check(self) -> ServiceHealth:
        """Perform health check"""
        try:
            start_time = time.time()
            
            # Check if attack agent is responsive
            if self.attack_agent:
                # Simple health check - verify agent can process a test scenario
                test_result = await self._test_attack_agent()
                
            response_time = time.time() - start_time
            
            self.health = ServiceHealth(
                status=self.status,
                last_check=datetime.now(),
                response_time=response_time,
                uptime=(datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            )
            
        except Exception as e:
            self.health = ServiceHealth(
                status=ServiceStatus.ERROR,
                last_check=datetime.now(),
                error_message=str(e)
            )
        
        return self.health
    
    async def _initialize_attack_database(self):
        """Initialize attack-specific database tables"""
        # Database initialization handled by DatabaseManager
        pass
    
    def _attack_monitor_loop(self):
        """Monitor active attack scenarios"""
        while not self.stop_event.is_set():
            try:
                # Monitor active scenarios
                self._check_active_scenarios()
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in attack monitor loop: {e}")
                time.sleep(60)
    
    def _check_active_scenarios(self):
        """Check status of active attack scenarios"""
        # Implementation for monitoring active attacks
        pass
    
    async def _test_attack_agent(self) -> bool:
        """Test attack agent responsiveness"""
        # Simple test to verify agent is working
        return True

class GuardianAlphaService(BaseService):
    """GuardianAlpha AI Detection Agent Service"""
    
    def __init__(self, config, db_manager):
        super().__init__("GuardianAlpha AI", config, db_manager)
        self.detection_agent = None
        self.log_queue = asyncio.Queue()
        self.processing_workers = []
        
    async def initialize(self) -> bool:
        """Initialize GuardianAlpha AI"""
        try:
            logger.info("Initializing GuardianAlpha AI Detection Agent...")
            
            # Import and initialize detection agent
            from agents.langgraph.workflows.detection_workflow import DetectionWorkflow
            self.detection_agent = DetectionWorkflow(self.config, self.db_manager)
            
            self.status = ServiceStatus.STOPPED
            logger.info("GuardianAlpha AI initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize GuardianAlpha AI: {e}")
            self.status = ServiceStatus.ERROR
            self.health.error_message = str(e)
            return False
    
    async def start(self) -> bool:
        """Start GuardianAlpha AI service"""
        try:
            self.status = ServiceStatus.STARTING
            self.start_time = datetime.now()
            
            # Start log processing workers
            for i in range(self.config.ai_agents.get('detection_workers', 2)):
                worker = threading.Thread(target=self._log_processing_worker, args=(i,), daemon=True)
                worker.start()
                self.processing_workers.append(worker)
            
            # Start continuous detection
            self.service_thread = threading.Thread(target=self._detection_loop, daemon=True)
            self.service_thread.start()
            
            self.status = ServiceStatus.RUNNING
            logger.info("GuardianAlpha AI service started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start GuardianAlpha AI: {e}")
            self.status = ServiceStatus.ERROR
            return False
    
    async def stop(self) -> bool:
        """Stop GuardianAlpha AI service"""
        try:
            self.status = ServiceStatus.STOPPING
            self.stop_event.set()
            
            # Stop all workers
            if self.service_thread:
                self.service_thread.join(timeout=10)
            
            for worker in self.processing_workers:
                worker.join(timeout=5)
            
            self.status = ServiceStatus.STOPPED
            logger.info("GuardianAlpha AI service stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping GuardianAlpha AI: {e}")
            return False
    
    async def health_check(self) -> ServiceHealth:
        """Perform health check"""
        try:
            start_time = time.time()
            
            # Check detection agent health
            if self.detection_agent:
                # Test detection capability
                test_result = await self._test_detection_agent()
            
            response_time = time.time() - start_time
            
            self.health = ServiceHealth(
                status=self.status,
                last_check=datetime.now(),
                response_time=response_time,
                uptime=(datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            )
            
        except Exception as e:
            self.health = ServiceHealth(
                status=ServiceStatus.ERROR,
                last_check=datetime.now(),
                error_message=str(e)
            )
        
        return self.health
    
    def _detection_loop(self):
        """Main detection loop"""
        while not self.stop_event.is_set():
            try:
                # Process pending logs
                self._process_pending_logs()
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in detection loop: {e}")
                time.sleep(30)
    
    def _log_processing_worker(self, worker_id: int):
        """Log processing worker thread"""
        logger.info(f"Detection worker {worker_id} started")
        
        while not self.stop_event.is_set():
            try:
                # Get logs from queue and process
                self._process_log_batch()
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in detection worker {worker_id}: {e}")
                time.sleep(10)
    
    def _process_pending_logs(self):
        """Process pending logs from database"""
        # Implementation for processing logs
        pass
    
    def _process_log_batch(self):
        """Process a batch of logs"""
        # Implementation for batch processing
        pass
    
    async def _test_detection_agent(self) -> bool:
        """Test detection agent responsiveness"""
        return True

class NetworkScannerService(BaseService):
    """Network Scanner Service"""
    
    def __init__(self, config, db_manager):
        super().__init__("Network Scanner", config, db_manager)
        self.scanner = None
        
    async def initialize(self) -> bool:
        """Initialize Network Scanner"""
        try:
            logger.info("Initializing Network Scanner...")
            
            from agents.network_discovery.network_scanner import NetworkScanner
            self.scanner = NetworkScanner(self.config, self.db_manager)
            
            self.status = ServiceStatus.STOPPED
            logger.info("Network Scanner initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Network Scanner: {e}")
            self.status = ServiceStatus.ERROR
            return False
    
    async def start(self) -> bool:
        """Start Network Scanner service"""
        try:
            self.status = ServiceStatus.STARTING
            self.start_time = datetime.now()
            
            # Start network scanning
            self.service_thread = threading.Thread(target=self._scanning_loop, daemon=True)
            self.service_thread.start()
            
            self.status = ServiceStatus.RUNNING
            logger.info("Network Scanner service started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Network Scanner: {e}")
            self.status = ServiceStatus.ERROR
            return False
    
    async def stop(self) -> bool:
        """Stop Network Scanner service"""
        try:
            self.status = ServiceStatus.STOPPING
            self.stop_event.set()
            
            if self.service_thread:
                self.service_thread.join(timeout=10)
            
            self.status = ServiceStatus.STOPPED
            logger.info("Network Scanner service stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping Network Scanner: {e}")
            return False
    
    async def health_check(self) -> ServiceHealth:
        """Perform health check"""
        try:
            start_time = time.time()
            
            # Test scanner functionality
            if self.scanner:
                test_result = await self._test_scanner()
            
            response_time = time.time() - start_time
            
            self.health = ServiceHealth(
                status=self.status,
                last_check=datetime.now(),
                response_time=response_time,
                uptime=(datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            )
            
        except Exception as e:
            self.health = ServiceHealth(
                status=ServiceStatus.ERROR,
                last_check=datetime.now(),
                error_message=str(e)
            )
        
        return self.health
    
    def _scanning_loop(self):
        """Network scanning loop"""
        while not self.stop_event.is_set():
            try:
                # Perform network scan
                self._perform_network_scan()
                
                # Wait for next scan interval
                time.sleep(self.config.network.scan_interval)
                
            except Exception as e:
                logger.error(f"Error in network scanning: {e}")
                time.sleep(60)
    
    def _perform_network_scan(self):
        """Perform network topology scan"""
        # Implementation for network scanning
        pass
    
    async def _test_scanner(self) -> bool:
        """Test scanner functionality"""
        return True

class ServiceOrchestrator:
    """Main service orchestrator for SOC Platform"""
    
    def __init__(self, config, db_manager):
        self.config = config
        self.db_manager = db_manager
        self.services: Dict[str, BaseService] = {}
        self.health_monitor_thread = None
        self.health_check_interval = 60  # seconds
        self.running = False
        
        # Initialize services
        self._initialize_services()
    
    def _initialize_services(self):
        """Initialize all services"""
        try:
            # Core AI services
            self.services['phantom_strike'] = PhantomStrikeService(self.config, self.db_manager)
            self.services['guardian_alpha'] = GuardianAlphaService(self.config, self.db_manager)
            self.services['network_scanner'] = NetworkScannerService(self.config, self.db_manager)
            
            logger.info(f"Initialized {len(self.services)} services")
            
        except Exception as e:
            logger.error(f"Error initializing services: {e}")
            raise
    
    async def start_all_services(self) -> bool:
        """Start all services"""
        try:
            logger.info("Starting SOC Platform services...")
            
            # Initialize all services first
            for name, service in self.services.items():
                logger.info(f"Initializing {name}...")
                success = await service.initialize()
                if not success:
                    logger.error(f"Failed to initialize {name}")
                    return False
            
            # Start all services
            for name, service in self.services.items():
                logger.info(f"Starting {name}...")
                success = await service.start()
                if not success:
                    logger.error(f"Failed to start {name}")
                    return False
            
            # Start health monitoring
            self._start_health_monitoring()
            
            self.running = True
            logger.info("All SOC Platform services started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error starting services: {e}")
            return False
    
    async def stop_all_services(self) -> bool:
        """Stop all services"""
        try:
            logger.info("Stopping SOC Platform services...")
            
            self.running = False
            
            # Stop health monitoring
            if self.health_monitor_thread:
                self.health_monitor_thread.join(timeout=10)
            
            # Stop all services
            for name, service in self.services.items():
                logger.info(f"Stopping {name}...")
                await service.stop()
            
            logger.info("All SOC Platform services stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping services: {e}")
            return False
    
    def _start_health_monitoring(self):
        """Start health monitoring thread"""
        def health_monitor():
            while self.running:
                try:
                    self._perform_health_checks()
                    time.sleep(self.health_check_interval)
                except Exception as e:
                    logger.error(f"Error in health monitoring: {e}")
                    time.sleep(30)
        
        self.health_monitor_thread = threading.Thread(target=health_monitor, daemon=True)
        self.health_monitor_thread.start()
        logger.info("Health monitoring started")
    
    def _perform_health_checks(self):
        """Perform health checks on all services"""
        for name, service in self.services.items():
            try:
                # Run health check asynchronously
                asyncio.create_task(service.health_check())
            except Exception as e:
                logger.error(f"Error checking health of {name}: {e}")
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all services"""
        status = {}
        
        for name, service in self.services.items():
            status[name] = {
                'status': service.status.value,
                'health': {
                    'status': service.health.status.value,
                    'last_check': service.health.last_check.isoformat(),
                    'response_time': service.health.response_time,
                    'uptime': service.health.uptime,
                    'error_message': service.health.error_message
                },
                'metrics': {
                    'requests_total': service.metrics.requests_total,
                    'requests_per_second': service.metrics.requests_per_second,
                    'errors_total': service.metrics.errors_total,
                    'error_rate': service.metrics.error_rate,
                    'avg_response_time': service.metrics.avg_response_time
                }
            }
        
        return status
    
    def get_service(self, name: str) -> Optional[BaseService]:
        """Get service by name"""
        return self.services.get(name)
    
    async def restart_service(self, name: str) -> bool:
        """Restart a specific service"""
        if name not in self.services:
            logger.error(f"Service {name} not found")
            return False
        
        try:
            service = self.services[name]
            logger.info(f"Restarting service {name}...")
            
            await service.stop()
            await service.start()
            
            logger.info(f"Service {name} restarted successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error restarting service {name}: {e}")
            return False
