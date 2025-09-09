#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
개선된 네트워크 설정 자동화 스크립트
VMware VM들의 네트워크 설정을 자동화하는 도구

"""

import json
import subprocess
import re
import paramiko
import sys
import time
import os
import threading
import logging
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

# 인코딩 설정
if sys.platform == 'win32':
    import codecs
    try:
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())
    except AttributeError:
        # detach() 메서드가 없는 경우 (일부 Windows 환경)
        pass

# === Configuration ===
CONFIG_FILE = 'config.json'
VM_CONFIG_FILE = 'vm_config.json'

LOG_FILE = 'logs/network_log.json'

# === Constants ===
MAX_LOG_SIZE = 10  # MB
LOG_BACKUP_COUNT = 5

# Lock for ARP lookups
arp_lock = threading.Lock()

# === Exception Classes ===
class NetworkConfigError(Exception):
    """네트워크 설정 관련 기본 예외"""
    pass

class SSHConnectionError(NetworkConfigError):
    """SSH 연결 실패 예외"""
    pass

class IPDiscoveryError(NetworkConfigError):
    """IP 발견 실패 예외"""
    pass

class ConfigValidationError(NetworkConfigError):
    """설정 검증 실패 예외"""
    pass

# === Data Classes ===
@dataclass
class VMProcessResult:
    """VM 처리 결과를 저장하는 클래스"""
    vm_name: str
    success: bool
    final_ip: Optional[str] = None
    os_type: Optional[str] = None
    failure_reason: Optional[str] = None
    reachable: bool = False
    original_ip: Optional[str] = None
    
@dataclass
class TimeoutConfig:
    """타임아웃 설정을 관리하는 클래스"""
    ssh_connection: int = 1
    network_scan: float = 2
    ping_short: int = 100
    ping_medium: int = 200
    ping_long: int = 500
    
    def load_from_config(self, config: Dict[str, Any]) -> None:
        """설정에서 타임아웃 값 로드"""
        timeouts = config.get('timeouts', {})
        self.ssh_connection = timeouts.get('ssh_connection', self.ssh_connection)
        self.network_scan = timeouts.get('network_scan', self.network_scan)
        self.ping_short = timeouts.get('ping_short', self.ping_short)
        self.ping_medium = timeouts.get('ping_medium', self.ping_medium)
        self.ping_long = timeouts.get('ping_long', self.ping_long)

@dataclass
class PerformanceConfig:
    """성능 설정을 관리하는 클래스"""
    arp_workers: int = 254
    ping_test_workers: int = 100
    network_scan_workers: int = 254
    vm_processing_workers_multiplier: int = 12
    max_vm_processing_workers: int = 48
    
    def load_from_config(self, config: Dict[str, Any]) -> None:
        """설정에서 성능 값 로드"""
        performance = config.get('performance', {})
        self.arp_workers = performance.get('arp_workers', self.arp_workers)
        self.ping_test_workers = performance.get('ping_test_workers', self.ping_test_workers)
        self.network_scan_workers = performance.get('network_scan_workers', self.network_scan_workers)
        self.vm_processing_workers_multiplier = performance.get('vm_processing_workers_multiplier', self.vm_processing_workers_multiplier)
        self.max_vm_processing_workers = performance.get('max_vm_processing_workers', self.max_vm_processing_workers)

@dataclass
class WaitConfig:
    """대기 시간 설정을 관리하는 클래스"""
    arp_refresh: float = 2
    arp_lookup: float = 1.5
    interface_restart: float = 3
    network_stabilization: float = 1.5
    dhcp_assignment: float = 3
    ip_change: float = 0.1
    
    def load_from_config(self, config: Dict[str, Any]) -> None:
        """설정에서 대기 시간 값 로드"""
        waits = config.get('waits', {})
        self.arp_refresh = waits.get('arp_refresh', self.arp_refresh)
        self.arp_lookup = waits.get('arp_lookup', self.arp_lookup)
        self.interface_restart = waits.get('interface_restart', self.interface_restart)
        self.network_stabilization = waits.get('network_stabilization', self.network_stabilization)
        self.dhcp_assignment = waits.get('dhcp_assignment', self.dhcp_assignment)
        self.ip_change = waits.get('ip_change', self.ip_change)

@dataclass
class RetryConfig:
    """재시도 설정을 관리하는 클래스"""
    ssh_attempts: int = 3
    ssh_delay: float = 0.01
    max_retry_attempts: int = 2
    
    def load_from_config(self, config: Dict[str, Any]) -> None:
        """설정에서 재시도 값 로드"""
        retry = config.get('retry', {})
        self.ssh_attempts = retry.get('ssh_attempts', self.ssh_attempts)
        self.ssh_delay = retry.get('ssh_delay', self.ssh_delay)
        self.max_retry_attempts = retry.get('max_retry_attempts', self.max_retry_attempts)

@dataclass
class InterfaceConfig:
    """인터페이스 설정을 관리하는 클래스"""
    linux_default: str = "ens33"
    windows_defaults: List[str] = None
    
    def __post_init__(self):
        if self.windows_defaults is None:
            self.windows_defaults = ["Ethernet0", "Ethernet", "이더넷", "로컬 영역 연결", "Local Area Connection"]
    
    def load_from_config(self, config: Dict[str, Any]) -> None:
        """설정에서 인터페이스 값 로드"""
        interfaces = config.get('interfaces', {})
        self.linux_default = interfaces.get('linux_default', self.linux_default)
        self.windows_defaults = interfaces.get('windows_defaults', self.windows_defaults)


@dataclass
class LoggingConfig:
    """로깅 설정을 관리하는 클래스"""
    max_log_size_mb: int = 10
    backup_count: int = 5
    
    def load_from_config(self, config: Dict[str, Any]) -> None:
        """설정에서 로깅 값 로드"""
        logging_config = config.get('logging', {})
        self.max_log_size_mb = logging_config.get('max_log_size_mb', self.max_log_size_mb)
        self.backup_count = logging_config.get('backup_count', self.backup_count)

@dataclass
class SystemTimeoutConfig:
    """시스템 타임아웃 설정을 관리하는 클래스"""
    ip_cache_timeout: int = 60
    total_execution_timeout: int = 120
    vm_processing_timeout: int = 30
    vm_individual_timeout: int = 3
    powershell_timeout: int = 2
    connectivity_test_min_time: int = 5
    
    def load_from_config(self, config: Dict[str, Any]) -> None:
        """설정에서 시스템 타임아웃 값 로드"""
        system_timeouts = config.get('system_timeouts', {})
        self.ip_cache_timeout = system_timeouts.get('ip_cache_timeout', self.ip_cache_timeout)
        self.total_execution_timeout = system_timeouts.get('total_execution_timeout', self.total_execution_timeout)
        self.vm_processing_timeout = system_timeouts.get('vm_processing_timeout', self.vm_processing_timeout)
        self.vm_individual_timeout = system_timeouts.get('vm_individual_timeout', self.vm_individual_timeout)
        self.powershell_timeout = system_timeouts.get('powershell_timeout', self.powershell_timeout)
        self.connectivity_test_min_time = system_timeouts.get('connectivity_test_min_time', self.connectivity_test_min_time)

@dataclass
class NetworkConfig:
    """네트워크 설정을 관리하는 클래스"""
    base_network: str = "192.168.32"
    gateway: str = "192.168.32.2"
    dns_primary: str = "8.8.8.8"
    dns_secondary: str = "8.8.4.4"
    subnet_mask: str = "255.255.255.0"
    
    def load_from_config(self, config: Dict[str, Any]) -> None:
        """설정에서 네트워크 정보 로드"""
        network_config = config.get('network', {})
        self.base_network = network_config.get('base_network', self.base_network)
        self.gateway = network_config.get('gateway', self.gateway)
        self.dns_primary = network_config.get('dns_primary', self.dns_primary)
        self.dns_secondary = network_config.get('dns_secondary', self.dns_secondary)
        self.subnet_mask = network_config.get('subnet_mask', self.subnet_mask)
    
    def get_network_range(self) -> str:
        """네트워크 범위 반환"""
        return self.base_network

# === Logging Setup ===
def setup_logging() -> logging.Logger:
    """로깅 시스템 설정"""
    logger = logging.getLogger('netconfig_improved')
    logger.setLevel(logging.DEBUG)
    
    # 기존 핸들러 제거
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # 로그 디렉토리 생성
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    
    # File handler with rotation
    fh = RotatingFileHandler(
        'logs/netconfig_improved.log', 
        maxBytes=MAX_LOG_SIZE*1024*1024, 
        backupCount=LOG_BACKUP_COUNT, 
        encoding='utf-8'
    )
    fh.setLevel(logging.DEBUG)
    
    # Formatter
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    ch.setFormatter(fmt)
    fh.setFormatter(fmt)
    logger.addHandler(ch)
    logger.addHandler(fh)
    
    return logger

# === Validation Functions ===
def validate_ip(ip_str: str) -> bool:
    """IP 주소 형식을 검증합니다."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_subnet_mask(mask_str: str) -> bool:
    """서브넷 마스크 형식을 검증합니다."""
    try:
        ipaddress.ip_address(mask_str)
        return True
    except ValueError:
        return False

def validate_mac(mac_str: str) -> bool:
    """MAC 주소 형식을 검증합니다."""
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(mac_pattern.match(mac_str))

def validate_config(cfg: Dict[str, Any]) -> bool:
    """설정 파일의 완전한 검증"""
    required_fields = ['vmx', 'mode', 'user', 'pass']
    
    for vm_name, vm_config in cfg.items():
        # 필수 필드 검증
        for field in required_fields:
            if field not in vm_config:
                raise ConfigValidationError(f"Missing required field '{field}' for VM '{vm_name}'")
        
        # 모드별 검증
        if vm_config['mode'] == 'static':
            static_fields = ['ip', 'gateway', 'subnet_mask']
            for field in static_fields:
                if field not in vm_config:
                    raise ConfigValidationError(f"Static mode requires '{field}' for VM '{vm_name}'")
            
            # IP 주소 유효성 검증
            if not validate_ip(vm_config['ip']):
                raise ConfigValidationError(f"Invalid IP address '{vm_config['ip']}' for VM '{vm_name}'")
            if not validate_ip(vm_config['gateway']):
                raise ConfigValidationError(f"Invalid gateway '{vm_config['gateway']}' for VM '{vm_name}'")
            if not validate_subnet_mask(vm_config['subnet_mask']):
                raise ConfigValidationError(f"Invalid subnet mask '{vm_config['subnet_mask']}' for VM '{vm_name}'")
        
        # DNS 검증
        if 'dns' in vm_config and not validate_ip(vm_config['dns']):
            raise ConfigValidationError(f"Invalid DNS '{vm_config['dns']}' for VM '{vm_name}'")
        if 'secondary_dns' in vm_config and not validate_ip(vm_config['secondary_dns']):
            raise ConfigValidationError(f"Invalid secondary DNS '{vm_config['secondary_dns']}' for VM '{vm_name}'")
    
    return True

# === Configuration Loading ===
def load_system_config(path: str, timeout_config: TimeoutConfig, network_config: NetworkConfig,
                      performance_config: PerformanceConfig, wait_config: WaitConfig,
                      retry_config: RetryConfig, interface_config: InterfaceConfig,
                      logging_config: LoggingConfig, system_timeout_config: SystemTimeoutConfig) -> None:
    """시스템 설정 파일을 로드합니다."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        
        # 모든 설정 로드
        timeout_config.load_from_config(cfg)
        network_config.load_from_config(cfg)
        performance_config.load_from_config(cfg)
        wait_config.load_from_config(cfg)
        retry_config.load_from_config(cfg)
        interface_config.load_from_config(cfg)
        logging_config.load_from_config(cfg)
        system_timeout_config.load_from_config(cfg)
        
    except FileNotFoundError:
        raise ConfigValidationError(f"System config file not found: {path}")
    except json.JSONDecodeError as e:
        raise ConfigValidationError(f"Invalid JSON in system config file: {e}")
    except Exception as e:
        raise ConfigValidationError(f"Error loading system config: {e}")

def load_vm_config(path: str, network_config: NetworkConfig) -> Dict[str, Any]:
    """VM 설정 파일을 로드하고 검증합니다."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        
        # VM 설정 추출
        vm_configs = cfg.get('vms', {})
        
        # 설정 검증
        validate_config(vm_configs)
        
        # 기본값 설정
        for vm, v in vm_configs.items():
            v.setdefault('port', 22)
            v.setdefault('dns', network_config.dns_primary)
            v.setdefault('secondary_dns', network_config.dns_secondary)
            v.setdefault('subnet_mask', network_config.subnet_mask)
        
        return vm_configs
    except FileNotFoundError:
        raise ConfigValidationError(f"VM config file not found: {path}")
    except json.JSONDecodeError as e:
        raise ConfigValidationError(f"Invalid JSON in VM config file: {e}")
    except Exception as e:
        raise ConfigValidationError(f"Error loading VM config: {e}")

# === IP Cache System ===
class IPCache:
    """IP 주소 캐싱 시스템"""
    
    def __init__(self, system_timeout_config: SystemTimeoutConfig):
        self.cache: Dict[str, Tuple[str, float]] = {}
        self.cache_timeout = system_timeout_config.ip_cache_timeout
    
    def get(self, mac: str) -> Optional[str]:
        """캐시에서 IP 주소 가져오기"""
        if mac in self.cache:
            ip, timestamp = self.cache[mac]
            if time.time() - timestamp < self.cache_timeout:
                return ip
            else:
                # 만료된 캐시 삭제
                del self.cache[mac]
        return None
    
    def set(self, mac: str, ip: str) -> None:
        """캐시에 IP 주소 저장"""
        self.cache[mac] = (ip, time.time())
    
    def clear(self) -> None:
        """캐시 전체 삭제"""
        self.cache.clear()

# === SSH Management ===
class SSHManager:
    """SSH 연결 관리 클래스"""
    
    def __init__(self, timeout_config: TimeoutConfig, retry_config: RetryConfig, logger: logging.Logger):
        self.timeout_config = timeout_config
        self.retry_config = retry_config
        self.logger = logger
    
    def run_command(self, ip: str, user: str, password: str, command: str, 
                   port: int = 22, vm_name: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        """SSH를 통해 원격 명령어를 실행합니다."""
        vm_prefix = f"[{vm_name}] " if vm_name else ""
        self.logger.debug(f"{vm_prefix}SSH {ip}:{port} => {command}")
        
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                ip, port=port, username=user, password=password,
                allow_agent=False, look_for_keys=False, timeout=self.timeout_config.ssh_connection
            )
            stdin, stdout, stderr = client.exec_command(
                command, get_pty=True, timeout=self.timeout_config.ssh_connection
            )
            stdin.write(password + '\n')
            stdin.flush()
            out = stdout.read().decode(errors='ignore')
            err = stderr.read().decode(errors='ignore')
            return out.strip(), err.strip()
        except Exception as e:
            # 소켓 예외는 로그에 기록하지 않음 (정상적인 연결 종료)
            if "강제로 끊겼습니다" not in str(e) and "Connection reset" not in str(e):
                self.logger.error(f"{vm_prefix}SSH error on {ip}:{port}: {e}")
            return None, None
        finally:
            # 안전하게 연결 종료
            if client:
                try:
                    client.close()
                except:
                    pass
    
    def run_with_retry(self, ip: str, user: str, password: str, command: str, 
                      port: int = 22, vm_name: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        """SSH 명령어를 재시도와 함께 실행합니다."""
        for attempt in range(self.retry_config.ssh_attempts):
            out, err = self.run_command(ip, user, password, command, port, vm_name)
            if out is not None:
                return out, err
            if attempt < self.retry_config.ssh_attempts - 1:
                self.logger.info(f"[{vm_name}] SSH retry {attempt + 1}/{self.retry_config.ssh_attempts} for {ip}")
                delay = self.retry_config.ssh_delay * (attempt + 1)
                time.sleep(delay)
        return None, None


# === IP Discovery Strategy ===
class IPDiscoveryStrategy:
    """IP 발견 전략 클래스"""
    
    def __init__(self, mac: str, vm_name: str, cfg: Dict[str, Any], 
                 network_config: NetworkConfig, timeout_config: TimeoutConfig, 
                 wait_config: WaitConfig, performance_config: PerformanceConfig,
                 logger: logging.Logger, active_ips: List[str]):
        self.mac = mac
        self.vm_name = vm_name
        self.cfg = cfg
        self.network_config = network_config
        self.timeout_config = timeout_config
        self.wait_config = wait_config
        self.performance_config = performance_config
        self.logger = logger
        self.active_ips = active_ips
    
    def arp_refresh_method(self) -> Optional[str]:
        """ARP 테이블 새로고침 방법"""
        try:
            self.logger.info(f"[{self.vm_name}] Refreshing ARP table...")
            subprocess.run('arp -d', shell=True, capture_output=True)
            time.sleep(self.wait_config.arp_refresh)
            
            # 네트워크 스캔으로 ARP 테이블 갱신
            network_base = self.network_config.get_network_range()
            
            def ping_host(ip: str) -> bool:
                try:
                    result = subprocess.run(
                        ['ping', '-n', '1', '-w', str(self.timeout_config.ping_short), ip], 
                        capture_output=True, timeout=self.timeout_config.network_scan
                    )
                    return result.returncode == 0
                except subprocess.TimeoutExpired:
                    self.logger.debug(f"[{self.vm_name}] Ping timeout for {ip}")
                    return False
                except subprocess.CalledProcessError as e:
                    self.logger.debug(f"[{self.vm_name}] Ping failed for {ip}: {e}")
                    return False
                except Exception as e:
                    self.logger.error(f"[{self.vm_name}] Unexpected error pinging {ip}: {e}")
                    return False
            
            # 병렬로 ping 스캔 실행 (극한 성능 모드)
            arp_workers = min(self.performance_config.arp_workers, 254)  # 설정된 워커 수로 ARP 갱신
            with ThreadPoolExecutor(max_workers=arp_workers) as executor:
                futures = []
                for i in range(1, 255):
                    test_ip = f"{network_base}.{i}"
                    futures.append(executor.submit(ping_host, test_ip))
                
                for future in as_completed(futures):
                    future.result()
            
            time.sleep(self.wait_config.arp_lookup)
            
            # 다시 ARP 조회
            arp = subprocess.check_output('arp -a', shell=True, encoding='cp949', errors='ignore')
            pat = self.mac.replace(':', '-')
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+.*" + pat, arp, re.I)
            if m:
                ip = m.group(1)
                self.logger.info(f"[{self.vm_name}] Found IP after ARP refresh: {ip}")
                return ip
        except Exception as e:
            self.logger.error(f"[{self.vm_name}] ARP refresh failed: {e}")
        return None
    
    def network_scan_method(self) -> Optional[str]:
        """글로벌 네트워크 스캔 결과를 사용하여 MAC 매칭"""
        self.logger.info(f"[{self.vm_name}] Using global network scan results with {len(self.active_ips)} active IPs: {self.active_ips}")
        try:
            # 활성 IP들 중에서 MAC 주소가 일치하는 것 찾기
            if self.active_ips:
                arp_result = subprocess.check_output('arp -a', shell=True, encoding='cp949', errors='ignore')
                mac_patterns = [
                    self.mac.replace(':', '-'),
                    self.mac.replace(':', ''),
                    self.mac.upper(),
                    self.mac.lower()
                ]
                
                for active_ip in self.active_ips:
                    for pattern in mac_patterns:
                        if pattern in arp_result:
                            self.logger.info(f"[{self.vm_name}] Found matching MAC {pattern} for active IP {active_ip}")
                            return active_ip
                
                # MAC 주소가 일치하지 않으면 실패
                self.logger.error(f"[{self.vm_name}] No matching MAC address found among {len(self.active_ips)} active IPs")
                return None
            else:
                self.logger.error(f"[{self.vm_name}] No active IPs found in global network scan")
                return None
                
        except Exception as e:
            self.logger.error(f"[{self.vm_name}] Network scan MAC matching failed: {e}")
            return None
    
    def common_ip_method(self) -> Optional[str]:
        """일반적인 VM IP 범위 방법"""
        self.logger.info(f"[{self.vm_name}] Trying common VM IP ranges...")
        network_base = self.network_config.get_network_range()
        common_ips = [
            f"{network_base}.128", f"{network_base}.129", f"{network_base}.130", 
            f"{network_base}.131", f"{network_base}.132", f"{network_base}.133",
            f"{network_base}.134", f"{network_base}.135", f"{network_base}.136"
        ]
        
        def ping_and_check_mac(test_ip: str) -> Optional[str]:
            try:
                result = subprocess.run(
                        ['ping', '-n', '1', '-w', str(self.timeout_config.ping_medium), test_ip], 
                        capture_output=True, timeout=self.timeout_config.network_scan
                )
                if result.returncode == 0:
                    try:
                        arp_result = subprocess.check_output('arp -a', shell=True, encoding='cp949', errors='ignore')
                        mac_patterns = [
                            self.mac.replace(':', '-'),
                            self.mac.replace(':', ''),
                            self.mac.upper(),
                            self.mac.lower()
                        ]
                        
                        for pattern in mac_patterns:
                            if pattern in arp_result:
                                self.logger.info(f"[{self.vm_name}] Found matching MAC {pattern} for IP {test_ip}")
                                return test_ip
                    except subprocess.CalledProcessError as e:
                        self.logger.debug(f"[{self.vm_name}] ARP command failed for {test_ip}: {e}")
                    except UnicodeDecodeError as e:
                        self.logger.debug(f"[{self.vm_name}] ARP output decode error for {test_ip}: {e}")
                    except Exception as e:
                        self.logger.error(f"[{self.vm_name}] Unexpected error checking ARP for {test_ip}: {e}")
                    # MAC 매칭 실패 시 None 반환
                    self.logger.debug(f"[{self.vm_name}] Ping successful but no MAC match for {test_ip}")
                    return None
            except subprocess.TimeoutExpired:
                self.logger.debug(f"[{self.vm_name}] Ping timeout for {test_ip}")
            except subprocess.CalledProcessError as e:
                self.logger.debug(f"[{self.vm_name}] Ping failed for {test_ip}: {e}")
            except Exception as e:
                self.logger.error(f"[{self.vm_name}] Unexpected error pinging {test_ip}: {e}")
            return None
        
        # ThreadPoolExecutor를 사용하여 병렬로 ping 테스트 (극한 성능)
        with ThreadPoolExecutor(max_workers=self.performance_config.ping_test_workers) as executor:
            futures = [executor.submit(ping_and_check_mac, ip) for ip in common_ips]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.logger.info(f"[{self.vm_name}] Found potential VM IP: {result}")
                    return result
        
        return None
    
    def discover(self) -> Optional[str]:
        """모든 방법을 순차적으로 시도"""
        methods = [self.arp_refresh_method, self.network_scan_method, self.common_ip_method]
        for method in methods:
            result = method()
            if result:
                return result
        
        self.logger.error(f"[{self.vm_name}] No IP found with any method")
        return None

# === Global Network Scan ===
def perform_global_network_scan(network_config: NetworkConfig, timeout_config: TimeoutConfig, 
                                performance_config: PerformanceConfig, logger: logging.Logger) -> List[str]:
    """전체 네트워크를 한 번만 스캔하여 활성 IP 목록을 반환합니다."""
    try:
        network_base = network_config.get_network_range()
        active_ips = []
        
        def scan_host(ip: str) -> Optional[str]:
            try:
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', str(timeout_config.ping_short), ip], 
                    capture_output=True, timeout=timeout_config.network_scan
                )
                return ip if result.returncode == 0 else None
            except subprocess.TimeoutExpired:
                logger.debug(f"Ping timeout for {ip}")
                return None
            except subprocess.CalledProcessError as e:
                logger.debug(f"Ping failed for {ip}: {e}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error pinging {ip}: {e}")
                return None
        
        # 병렬로 네트워크 스캔 (극한 성능 모드)
        scan_workers = min(performance_config.network_scan_workers, 254)  # 설정된 워커 수로 네트워크 스캔
        with ThreadPoolExecutor(max_workers=scan_workers) as executor:
            futures = []
            for i in range(1, 255):
                test_ip = f"{network_base}.{i}"
                futures.append(executor.submit(scan_host, test_ip))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    active_ips.append(result)
        
        return sorted(active_ips, key=lambda x: int(x.split('.')[-1]))
    except Exception as e:
        logger.error(f"Global network scan failed: {e}")
        return []

# === Main Execution ===
def main():
    """메인 실행 함수"""
    # 로깅 설정
    logger = setup_logging()
    
    # 설정 객체 초기화
    timeout_config = TimeoutConfig()
    network_config = NetworkConfig()
    performance_config = PerformanceConfig()
    wait_config = WaitConfig()
    retry_config = RetryConfig()
    interface_config = InterfaceConfig()
    logging_config = LoggingConfig()
    system_timeout_config = SystemTimeoutConfig()
    
    # 전체 실행 시간 측정 시작
    start_time = datetime.now()
    logger.info(f"=== Network Configuration Started at {start_time.strftime('%Y-%m-%d %H:%M:%S')} ===")
    
    try:
        # 시스템 설정 로드
        load_system_config(CONFIG_FILE, timeout_config, network_config, performance_config, 
                          wait_config, retry_config, interface_config, logging_config, system_timeout_config)
        
        # VM 설정 로드
        configs = load_vm_config(VM_CONFIG_FILE, network_config)
        logger.info(f"Loaded configuration for {len(configs)} VMs")
        
        # IP 캐시 초기화
        ip_cache = IPCache(system_timeout_config)
        
        # SSH 매니저 초기화
        ssh_manager = SSHManager(timeout_config, retry_config, logger)
        
        # 네트워크 유틸리티 초기화
        from utils.network_utils import NetworkUtils, LinuxNetworkManager, WindowsNetworkManager
        network_utils = NetworkUtils(logger)
        linux_manager = LinuxNetworkManager(logger)
        windows_manager = WindowsNetworkManager(logger)
        
        # 전체 네트워크 스캔 (한 번만 실행)
        logger.info("=== Starting global network scan ===")
        active_ips = perform_global_network_scan(network_config, timeout_config, performance_config, logger)
        logger.info(f"Global network scan completed. Found {len(active_ips)} active IPs: {active_ips}")
        
        # VM 처리 결과 저장
        vm_results: List[VMProcessResult] = []
        
        # 병렬로 VM 처리 (60초 타임아웃 적용) - 극한 성능 워커 수
        optimized_workers = min(len(configs) * performance_config.vm_processing_workers_multiplier, 
                               performance_config.max_vm_processing_workers)
        logger.info(f"Using {optimized_workers} workers for {len(configs)} VMs (extreme performance mode)")
        with ThreadPoolExecutor(max_workers=optimized_workers) as executor:
            futures = {executor.submit(process_vm, vm_name, cfg, timeout_config, network_config, 
                                     wait_config, performance_config, retry_config,
                                     ssh_manager, network_utils, linux_manager, windows_manager, 
                                     ip_cache, system_timeout_config, logger, active_ips): vm_name 
                      for vm_name, cfg in configs.items()}
            
            # 설정된 타임아웃으로 futures 처리
            try:
                for future in as_completed(futures, timeout=system_timeout_config.vm_processing_timeout):
                    vm_name = futures[future]
                    try:
                        result = future.result(timeout=system_timeout_config.vm_individual_timeout)
                        vm_results.append(result)
                    except Exception as e:
                        logger.error(f"[{vm_name}] Exception: {e}")
                        # 예외 발생 시에도 실패 결과 추가
                        vm_results.append(VMProcessResult(vm_name=vm_name, success=False, failure_reason=f"처리 타임아웃 또는 예외: {str(e)}"))
            except Exception as e:
                logger.warning(f"VM processing timed out after {system_timeout_config.vm_processing_timeout} seconds: {e}")
                # 아직 완료되지 않은 futures들에 대해 타임아웃 결과 추가
                for future, vm_name in futures.items():
                    if not future.done():
                        future.cancel()
                        vm_results.append(VMProcessResult(vm_name=vm_name, success=False, failure_reason=f"처리 타임아웃 ({system_timeout_config.vm_processing_timeout}초 초과)"))
        
        # 모든 VM 설정 완료 후 연결성 테스트 (15초 제한)
        successful_vms = [result for result in vm_results if result.success]
        connectivity_matrix = {}
        if successful_vms:
            remaining_time = system_timeout_config.total_execution_timeout - (datetime.now() - start_time).total_seconds()
            if remaining_time > system_timeout_config.connectivity_test_min_time:
                logger.info(f"Starting connectivity test with {remaining_time:.1f} seconds remaining")
                # 연결성 테스트용 딕셔너리 생성
                connectivity_configs = {}
                connectivity_vm_results = {}
                for result in successful_vms:
                    connectivity_configs[result.vm_name] = configs[result.vm_name]
                    connectivity_vm_results[result.vm_name] = {
                        'final_ip': result.final_ip,
                        'os_type': result.os_type,
                        'reachable': result.reachable
                    }
                connectivity_matrix = test_all_vm_connectivity(connectivity_configs, connectivity_vm_results, ssh_manager, logger)
            else:
                logger.warning(f"Skipping connectivity test - only {remaining_time:.1f} seconds remaining")
        else:
            logger.warning("No VMs were successfully configured, skipping connectivity test")
        
    except Exception as e:
        logger.error(f"Configuration failed: {e}")
        return 1
    
    # 전체 실행 시간 측정
    end_time = datetime.now()
    total_duration = end_time - start_time
    
    # 로그 요약 먼저 출력 (VM 이름 순으로 정렬)
    logger.info(f"=== FINAL SUMMARY: {len([r for r in vm_results if r.success])}/{len(vm_results)} VMs configured successfully ===")
    # VM 이름 순으로 정렬
    sorted_vm_results = sorted(vm_results, key=lambda x: x.vm_name)
    for result in sorted_vm_results:
        if result.success:
            logger.info(f"SUCCESS: {result.vm_name} -> {result.final_ip} ({result.os_type})")
        else:
            logger.info(f"FAILED: {result.vm_name} -> {result.failure_reason}")
    
    # 완료 시간과 소요 시간 출력
    logger.info(f"=== Network Configuration Completed at {end_time.strftime('%Y-%m-%d %H:%M:%S')} ===")
    logger.info(f"=== Total Execution Time: {total_duration} ===")
    
    # 전체 결과 요약 출력 (맨 마지막, 소요 시간 포함)
    print_final_summary(vm_results, total_duration, connectivity_matrix, logger)
    
    # 프로그램 종료 전 대기
    print("\n프로그램이 완료되었습니다.")
    input("아무 키나 누르면 종료됩니다...")
    
    return 0

def process_vm(vm_name: str, cfg: Dict[str, Any], timeout_config: TimeoutConfig, 
               network_config: NetworkConfig, wait_config: WaitConfig,
               performance_config: PerformanceConfig, retry_config: RetryConfig,
               ssh_manager: SSHManager, network_utils, linux_manager, windows_manager, 
               ip_cache: IPCache, system_timeout_config: SystemTimeoutConfig, logger: logging.Logger, active_ips: List[str]) -> VMProcessResult:
    """개별 VM 처리 함수"""
    logger.info(f"[{vm_name}] START")
    
    try:
        # 1) MAC 주소와 현재 IP 가져오기
        mac = network_utils.get_mac_from_vmx(cfg['vmx'], vm_name)
        if not mac:
            logger.warning(f"[{vm_name}] Skipped: no MAC")
            return VMProcessResult(vm_name=vm_name, success=False, failure_reason="MAC 주소를 VMX 파일에서 찾을 수 없음")
        
        # 캐시에서 IP 확인
        current_ip = ip_cache.get(mac)
        if not current_ip:
            current_ip = network_utils.get_ip_from_mac(mac, vm_name)
            if current_ip:
                ip_cache.set(mac, current_ip)
        
        if not current_ip:
            # ARP에서 IP를 찾지 못한 경우, 대안 방법 시도
            discovery_strategy = IPDiscoveryStrategy(mac, vm_name, cfg, network_config, timeout_config, 
                                                   wait_config, performance_config, logger, active_ips)
            current_ip = discovery_strategy.discover()
            if current_ip:
                ip_cache.set(mac, current_ip)
            else:
                logger.error(f"[{vm_name}] No IP found with any method, skipping")
                return VMProcessResult(vm_name=vm_name, success=False, failure_reason="ARP 테이블과 네트워크 스캔에서 해당 MAC 주소의 IP를 찾을 수 없음")
        
        logger.info(f"[{vm_name}] Current IP: {current_ip}")
        
        # 2) 현재 IP로 SSH 연결성 확인
        out, _ = ssh_manager.run_command(current_ip, cfg['user'], cfg['pass'], 'echo ok', cfg['port'], vm_name)
        if out is None:
            logger.error(f"[{vm_name}] SSH connection failed on {current_ip}")
            return VMProcessResult(vm_name=vm_name, success=False, failure_reason=f"SSH 연결 실패 ({current_ip}:22)")
        
        # 3) OS 감지 및 네트워크 설정
        os_type = network_utils.detect_os(current_ip, vm_name, cfg['user'], cfg['pass'], cfg['port'], ssh_manager)
        
        if os_type == 'linux':
            new_ip = configure_linux_network(current_ip, vm_name, cfg, ssh_manager, linux_manager, wait_config, logger, network_utils)
        else:
            # Windows VM도 SSH 사용
            new_ip = configure_windows_network(current_ip, vm_name, cfg, ssh_manager, windows_manager, wait_config, logger, network_utils)
        
        # 4) IP 변경 후 재연결
        final_ip = wait_for_ip_change_and_reconnect(current_ip, new_ip, vm_name, 
                                                   cfg['user'], cfg['pass'], cfg['port'], ssh_manager, wait_config, retry_config, logger)
        
        # 5) 네트워크 설정 검증
        verification_result = verify_network_configuration(final_ip, vm_name, cfg, os_type, ssh_manager, logger)
        
        if not verification_result['success']:
            logger.error(f"[{vm_name}] Network configuration verification failed: {verification_result['reason']}")
            return VMProcessResult(vm_name=vm_name, success=False, failure_reason=f"네트워크 설정 검증 실패: {verification_result['reason']}")
        
        # 6) 새로운 IP로 방화벽 설정
        set_firewall(final_ip, vm_name, cfg['user'], cfg['pass'], cfg['port'], os_type, ssh_manager, system_timeout_config, logger)
        
        # 7) 최종 연결성 테스트 및 로깅
        if os_type == 'linux':
            cmd = 'hostname -I'
        else:
            cmd = 'ipconfig'
        final_ip_output, _ = ssh_manager.run_command(final_ip, cfg['user'], cfg['pass'], cmd, cfg['port'], vm_name)
        
        reachable = network_utils.test_connectivity(final_ip, vm_name)
        
        status = {'current_ip': final_ip_output, 'reachable': reachable, 'os_type': os_type, 'final_ip': final_ip}
        log_status(vm_name, status, logger)
        
        logger.info(f"[{vm_name}] END")
        
        # 결과 반환
        return VMProcessResult(
            vm_name=vm_name,
            success=True,
            final_ip=final_ip,
            os_type=os_type,
            reachable=reachable,
            original_ip=current_ip
        )
        
    except Exception as e:
        logger.error(f"[{vm_name}] Error during processing: {e}")
        return VMProcessResult(vm_name=vm_name, success=False, failure_reason=f"처리 중 예외 발생: {str(e)}")

def configure_linux_network(ip: str, vm_name: str, cfg: Dict[str, Any], 
                           ssh_manager: SSHManager, linux_manager, wait_config: WaitConfig,
                           logger: logging.Logger, network_utils) -> str:
    """Linux VM 네트워크 설정"""
    # 1) 인터페이스와 연결 프로필 감지
    iface = linux_manager.detect_interface(ip, vm_name, cfg['user'], cfg['pass'], cfg['port'], ssh_manager)
    conn = linux_manager.detect_connection_name(ip, vm_name, cfg['user'], cfg['pass'], cfg['port'], iface, ssh_manager)
    
    # 2) NetworkManager 관리 및 자동 연결 설정
    ssh_manager.run_command(ip, cfg['user'], cfg['pass'],
                           f"sudo nmcli device set {iface} managed yes", cfg['port'], vm_name)
    ssh_manager.run_command(ip, cfg['user'], cfg['pass'],
                           f"sudo nmcli connection modify '{conn}' connection.autoconnect yes", cfg['port'], vm_name)
    
    # 3) DHCP 또는 정적 설정 적용
    if cfg['mode'] == 'dhcp':
        # DHCP 설정 시 기존 정적 IP 완전 제거
        ssh_manager.run_command(ip, cfg['user'], cfg['pass'],
                               f"sudo nmcli connection modify '{conn}' ipv4.method auto " +
                               f"ipv4.addresses '' ipv4.gateway '' ipv4.dns ''", cfg['port'], vm_name)
    else:
        # 서브넷 마스크를 CIDR로 변환
        subnet_cidr = sum(bin(int(x)).count('1') for x in cfg['subnet_mask'].split('.'))
        ssh_manager.run_command(ip, cfg['user'], cfg['pass'],
                               f"sudo nmcli connection modify '{conn}' ipv4.method manual " +
                               f"ipv4.addresses {cfg['ip']}/{subnet_cidr} " +
                               f"ipv4.gateway {cfg['gateway']} " +
                               f"ipv4.dns {cfg['dns']},{cfg['secondary_dns']}", cfg['port'], vm_name)
    
    ssh_manager.run_command(ip, cfg['user'], cfg['pass'],
                           f"sudo nmcli connection up '{conn}'", cfg['port'], vm_name)
    logger.info(f"[{vm_name}] Ran NM configuration on {conn}")
    
    # DHCP 모드인 경우 부드러운 DHCP 갱신만 수행
    if cfg['mode'] == 'dhcp':
        logger.info(f"[{vm_name}] Requesting DHCP renewal without interface restart...")
        # 인터페이스 재시작 없이 DHCP 갱신만 수행
        ssh_manager.run_command(ip, cfg['user'], cfg['pass'],
                               f"sudo dhclient -r {iface}", cfg['port'], vm_name)
        time.sleep(1)  # DHCP 해제 대기
        ssh_manager.run_command(ip, cfg['user'], cfg['pass'],
                               f"sudo dhclient {iface}", cfg['port'], vm_name)
        time.sleep(2)  # DHCP 갱신 대기
    
    # 4) 새로운 IP 결정
    if cfg['mode'] == 'static':
        new_ip = cfg['ip']
    else:
        # DHCP 모드인 경우, 기존 IP로 SSH 연결이 끊어질 수 있으므로
        # ARP 테이블에서 MAC 주소로 새로운 IP를 찾습니다
        logger.info(f"[{vm_name}] DHCP mode: searching for new IP via ARP table...")
        # MAC 주소를 가져와서 ARP 테이블에서 정확한 IP를 찾습니다
        mac = network_utils.get_mac_from_vmx(cfg['vmx'], vm_name)
        new_ip = linux_manager.fetch_dhcp_ip_via_arp(iface, vm_name, logger, mac, ip)
        if not new_ip:
            # ARP에서 찾지 못한 경우 기존 방법 시도 (실패할 가능성 높음)
            logger.warning(f"[{vm_name}] ARP search failed, trying SSH method...")
            new_ip = linux_manager.fetch_dhcp_ip(ip, vm_name, cfg['user'], cfg['pass'], cfg['port'], iface, ssh_manager)
    
    return new_ip


def configure_windows_network(ip: str, vm_name: str, cfg: Dict[str, Any], 
                             ssh_manager: SSHManager, windows_manager, wait_config: WaitConfig,
                             logger: logging.Logger, network_utils) -> str:
    """Windows VM 네트워크 설정"""
    iface_list = windows_manager.detect_interfaces(ip, cfg['user'], cfg['pass'], cfg['port'], vm_name, ssh_manager)
    success = False
    new_ip = ip  # 기본값은 기존 IP
    
    for iface in iface_list:
        logger.info(f"[{vm_name}] Trying to configure interface: {iface}")
        
        # IP/DNS 설정 시도
        if cfg['mode'] == 'dhcp':
            success = windows_manager.configure_dhcp(ip, vm_name, cfg['user'], cfg['pass'], cfg['port'], iface, ssh_manager)
            
            # DHCP 설정 후 SSH 연결을 즉시 끊고 새로운 IP로 접속 시도
            logger.info(f"[{vm_name}] DHCP configuration completed, attempting immediate connection to new IP")
            
            # DHCP 설정 후 잠시 대기하고 원래 IP로 재연결 시도
            logger.info(f"[{vm_name}] DHCP configuration completed, waiting for IP assignment...")
            time.sleep(wait_config.dhcp_assignment)  # DHCP 할당 대기
            
            # DHCP 모드인 경우, ARP 테이블에서 MAC 주소로 새로운 IP를 찾습니다
            logger.info(f"[{vm_name}] DHCP mode: searching for new IP via ARP table...")
            # MAC 주소를 가져와서 ARP 테이블에서 정확한 IP를 찾습니다
            mac = network_utils.get_mac_from_vmx(cfg['vmx'], vm_name)
            new_ip = windows_manager.fetch_dhcp_ip_via_arp(iface, vm_name, logger, mac, ip)
            if not new_ip:
                # ARP에서 찾지 못한 경우 원래 IP로 재연결 시도
                logger.warning(f"[{vm_name}] ARP search failed, trying original IP...")
                test_out, _ = ssh_manager.run_command(ip, cfg['user'], cfg['pass'], 'ipconfig', cfg['port'], vm_name)
                if test_out is not None:
                    logger.info(f"[{vm_name}] [SUCCESS] SSH connection to original IP {ip} successful after DHCP")
                    return ip
                else:
                    logger.warning(f"[{vm_name}] [FAILED] SSH connection to original IP {ip} failed after DHCP")
                    return ip  # 실패해도 원래 IP 반환
            else:
                logger.info(f"[{vm_name}] Found new DHCP IP: {new_ip}")
                return new_ip
        else:
            # 정적 IP 설정
            success = windows_manager.configure_static(ip, vm_name, cfg['user'], cfg['pass'], cfg['port'], iface, cfg, ssh_manager)
            
            # 네트워크 설정 완료
            logger.info(f"[{vm_name}] Network configuration completed, waiting for IP change...")
            
            # 정적 IP 설정의 경우 설정된 IP로 접속 시도
            if cfg['mode'] == 'static':
                new_test_ip = cfg['ip']
                logger.info(f"[{vm_name}] Attempting connection to new static IP: {new_test_ip}")
                
                # 네트워크 설정 안정화 대기
                time.sleep(wait_config.network_stabilization)  # 네트워크 설정 안정화 대기
                
                # 새로운 IP로 SSH 연결 시도
                if windows_manager.verify_connection(new_test_ip, vm_name, cfg['user'], cfg['pass'], cfg['port'], ssh_manager):
                    return new_test_ip
                else:
                    logger.warning(f"[{vm_name}] [FAILED] SSH connection to new static IP {new_test_ip}, will retry with wait")
                    # SSH 실패 시 잠시 대기 후 재시도
                    time.sleep(wait_config.ip_change)
                    if windows_manager.verify_connection(new_test_ip, vm_name, cfg['user'], cfg['pass'], cfg['port'], ssh_manager):
                        return new_test_ip
                    else:
                        logger.warning(f"[{vm_name}] [FAILED] SSH connection to new static IP {new_test_ip} after retry")
                        return ip  # 실패 시 기존 IP 반환
        
        if success:
            break
    
    if not success:
        logger.error(f"[{vm_name}] All interface IP set attempts failed!")
        return ip  # 실패시 기존 IP 반환
    
    return new_ip

def wait_for_ip_change_and_reconnect(old_ip: str, new_ip: str, vm_name: str, 
                                   user: str, password: str, port: int, 
                                   ssh_manager: SSHManager, wait_config: WaitConfig, retry_config: RetryConfig,
                                   logger: logging.Logger) -> str:
    """IP 변경 후 새로운 IP로 재연결을 시도합니다."""
    if old_ip == new_ip:
        logger.info(f"[{vm_name}] IP unchanged ({old_ip}), skipping wait")
        return new_ip
    
    logger.info(f"[{vm_name}] IP changed from {old_ip} to {new_ip}, waiting for network stabilization...")
    
    # 네트워크 안정화 대기
    time.sleep(wait_config.network_stabilization)
    
    # 새로운 IP로 SSH 연결 시도
    logger.info(f"[{vm_name}] Attempting SSH connection to new IP {new_ip}")
    for attempt in range(retry_config.ssh_attempts):  # 설정된 횟수만큼 시도
        out, err = ssh_manager.run_command(new_ip, user, password, 'echo "IP change test"', port, vm_name)
        if out is not None:
            logger.info(f"[{vm_name}] [SUCCESS] SSH connection to new IP {new_ip} successful (attempt {attempt + 1})")
            return new_ip
        else:
            logger.warning(f"[{vm_name}] [FAILED] SSH connection to new IP {new_ip} failed (attempt {attempt + 1})")
            if attempt < retry_config.max_retry_attempts:
                time.sleep(retry_config.ssh_delay)  # 대기 시간 증가
    
    # 새로운 IP 연결 실패 시 기존 IP로 폴백
    logger.warning(f"[{vm_name}] All SSH attempts to new IP failed, falling back to original IP {old_ip}")
    return old_ip

def verify_network_configuration(ip: str, vm_name: str, cfg: Dict[str, Any], 
                               os_type: str, ssh_manager: SSHManager, logger: logging.Logger) -> Dict[str, Any]:
    """네트워크 설정이 올바르게 적용되었는지 검증합니다."""
    logger.info(f"[{vm_name}] Verifying network configuration...")
    
    try:
        if cfg['mode'] == 'static':
            # 정적 IP 모드인 경우 설정값 검증
            expected_ip = cfg['ip']
            expected_gateway = cfg['gateway']
            expected_dns = cfg['dns']
            
            if os_type == 'linux':
                # Linux에서 네트워크 설정 검증
                
                # 1. IP 주소 확인
                ip_cmd = f"ip -4 addr show | grep 'inet.*{expected_ip}'"
                ip_out, _ = ssh_manager.run_command(ip, cfg['user'], cfg['pass'], ip_cmd, cfg['port'], vm_name)
                if not ip_out or expected_ip not in ip_out:
                    return {'success': False, 'reason': f'IP 주소가 {expected_ip}로 설정되지 않음'}
                
                # 2. 게이트웨이 확인
                gw_cmd = "ip route show default"
                gw_out, _ = ssh_manager.run_command(ip, cfg['user'], cfg['pass'], gw_cmd, cfg['port'], vm_name)
                if not gw_out or expected_gateway not in gw_out:
                    return {'success': False, 'reason': f'게이트웨이가 {expected_gateway}로 설정되지 않음'}
                
                # 3. DNS 확인 (여러 방법 시도)
                dns_verified = False
                
                # 방법 1: systemd-resolve --status (최신 Ubuntu)
                dns_cmd1 = "systemd-resolve --status | grep 'DNS Servers'"
                dns_out1, _ = ssh_manager.run_command(ip, cfg['user'], cfg['pass'], dns_cmd1, cfg['port'], vm_name)
                if dns_out1 and expected_dns in dns_out1:
                    dns_verified = True
                
                # 방법 2: resolvectl status (Ubuntu 20.04+)
                if not dns_verified:
                    dns_cmd2 = "resolvectl status | grep 'DNS Servers'"
                    dns_out2, _ = ssh_manager.run_command(ip, cfg['user'], cfg['pass'], dns_cmd2, cfg['port'], vm_name)
                    if dns_out2 and expected_dns in dns_out2:
                        dns_verified = True
                
                # 방법 3: /etc/resolv.conf (기존 방법)
                if not dns_verified:
                    dns_cmd3 = "cat /etc/resolv.conf | grep nameserver"
                    dns_out3, _ = ssh_manager.run_command(ip, cfg['user'], cfg['pass'], dns_cmd3, cfg['port'], vm_name)
                    if dns_out3 and expected_dns in dns_out3:
                        dns_verified = True
                
                # 방법 4: NetworkManager 설정 확인
                if not dns_verified:
                    dns_cmd4 = f"nmcli connection show | grep -E '(netplan|Wired|ethernet)' | head -1 | awk '{{print $1}}'"
                    conn_out, _ = ssh_manager.run_command(ip, cfg['user'], cfg['pass'], dns_cmd4, cfg['port'], vm_name)
                    if conn_out:
                        conn_name = conn_out.strip().split('\n')[0]
                        dns_cmd5 = f"nmcli connection show '{conn_name}' | grep ipv4.dns"
                        dns_out5, _ = ssh_manager.run_command(ip, cfg['user'], cfg['pass'], dns_cmd5, cfg['port'], vm_name)
                        if dns_out5 and expected_dns in dns_out5:
                            dns_verified = True
                
                if not dns_verified:
                    return {'success': False, 'reason': f'DNS가 {expected_dns}로 설정되지 않음 (모든 검증 방법 실패)'}
                
            else:
                # Windows에서 네트워크 설정 검증
                
                # 1. IP 주소 확인
                ip_cmd = "ipconfig"
                ip_out, _ = ssh_manager.run_command(ip, cfg['user'], cfg['pass'], ip_cmd, cfg['port'], vm_name)
                if not ip_out or expected_ip not in ip_out:
                    return {'success': False, 'reason': f'IP 주소가 {expected_ip}로 설정되지 않음'}
                
                # 2. 게이트웨이 확인
                gw_cmd = "ipconfig /all"
                gw_out, _ = ssh_manager.run_command(ip, cfg['user'], cfg['pass'], gw_cmd, cfg['port'], vm_name)
                if not gw_out or expected_gateway not in gw_out:
                    return {'success': False, 'reason': f'게이트웨이가 {expected_gateway}로 설정되지 않음'}
        
        # 4. 게이트웨이 연결성 테스트 (정적 IP 모드에서만)
        if cfg['mode'] == 'static':
            gateway_ip = cfg.get('gateway', '192.168.32.2')  # 기본 게이트웨이
            ping_cmd = f"ping -c 1 {gateway_ip}" if os_type == 'linux' else f"ping -n 1 {gateway_ip}"
            ping_out, _ = ssh_manager.run_command(ip, cfg['user'], cfg['pass'], ping_cmd, cfg['port'], vm_name)
            
            if not ping_out or ("TTL=" not in ping_out and "ttl=" not in ping_out):
                return {'success': False, 'reason': f'게이트웨이 {gateway_ip}에 ping 실패 (네트워크 연결 불가)'}
        else:
            # DHCP 모드에서는 게이트웨이 연결성 검증을 건너뛰고 기본 연결성만 확인
            logger.info(f"[{vm_name}] DHCP mode: skipping gateway connectivity test")
        
        logger.info(f"[{vm_name}] Network configuration verification successful")
        return {'success': True, 'reason': 'Network configuration verified successfully'}
        
    except Exception as e:
        logger.error(f"[{vm_name}] Network verification error: {e}")
        return {'success': False, 'reason': f'검증 중 오류 발생: {str(e)}'}


def set_firewall(ip: str, vm_name: str, user: str, password: str, port: int, 
                os_type: str, ssh_manager: SSHManager, system_timeout_config: SystemTimeoutConfig, logger: logging.Logger) -> None:
    """방화벽을 설정합니다."""
    if os_type == 'linux':
        ssh_manager.run_command(ip, user, password, 'sudo ufw allow proto icmp', port, vm_name)
    else:
        cmd = 'netsh advfirewall firewall add rule name="Allow ICMP" protocol=icmpv4 dir=in action=allow'
        # SSH가 안 되면 PowerShell Remoting 사용
        test_out, _ = ssh_manager.run_command(ip, user, password, 'echo test', port, vm_name)
        if test_out is None:
            # PowerShell Remoting 사용
            ps_command = f"Invoke-Command -ComputerName {ip} -Credential (New-Object System.Management.Automation.PSCredential('{user}', (ConvertTo-SecureString '{password}' -AsPlainText -Force))) -ScriptBlock {{{cmd}}}"
            try:
                result = subprocess.run(['powershell', '-Command', ps_command], 
                                      capture_output=True, text=True, timeout=system_timeout_config.powershell_timeout)
                logger.info(f"[{vm_name}] PowerShell firewall configuration completed")
            except Exception as e:
                logger.error(f"[{vm_name}] PowerShell firewall configuration failed: {e}")
        else:
            ssh_manager.run_command(ip, user, password, cmd, port, vm_name)
    
    logger.info(f"[{vm_name}] Firewall configured for ICMP")


def log_status(vm_name: str, status: Dict[str, Any], logger: logging.Logger) -> None:
    """VM 상태를 로깅합니다."""
    try:
        logs = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        logs.append({'vm': vm_name, **status, 'time': time.strftime('%Y-%m-%d %H:%M:%S')})
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
        logger.debug(f"[{vm_name}] Status logged")
    except Exception as e:
        logger.error(f"[{vm_name}] Logging failed: {e}")

def test_vm_connectivity(vm_name: str, ip: str, target_vms: Dict[str, Any], 
                        user: str, password: str, port: int, os_type: str,
                        ssh_manager: SSHManager, logger: logging.Logger) -> Dict[str, bool]:
    """특정 VM에서 다른 VM들로의 연결성을 테스트합니다."""
    logger.info(f"[{vm_name}] Testing connectivity to other VMs from {ip}")
    
    results = {}
    for target_vm, target_info in target_vms.items():
        if target_vm == vm_name:
            continue
            
        target_ip = target_info.get('ip')
        if not target_ip:
            logger.warning(f"[{vm_name}] No IP found for {target_vm}")
            results[target_vm] = False
            continue
        
        # OS별 ping 명령어 결정
        if os_type == 'linux':
            ping_cmd = f"ping -c 1 {target_ip}"
        else:
            ping_cmd = f"ping -n 1 {target_ip}"
        
        # SSH를 통해 ping 실행
        out, err = ssh_manager.run_command(ip, user, password, ping_cmd, port, vm_name)
        
        if out and ("TTL=" in out or "ttl=" in out):
            logger.info(f"[{vm_name}] [SUCCESS] Successfully pinged {target_vm} ({target_ip})")
            results[target_vm] = True
        else:
            logger.warning(f"[{vm_name}] [FAILED] Failed to ping {target_vm} ({target_ip})")
            # 실패 시 한 번 더 재시도
            logger.info(f"[{vm_name}] Retrying ping to {target_vm} ({target_ip})...")
            retry_out, retry_err = ssh_manager.run_command(ip, user, password, ping_cmd, port, vm_name)
            if retry_out and ("TTL=" in retry_out or "ttl=" in retry_out):
                logger.info(f"[{vm_name}] [SUCCESS] Successfully pinged {target_vm} ({target_ip}) on retry")
                results[target_vm] = True
            else:
                logger.warning(f"[{vm_name}] [FAILED] Failed to ping {target_vm} ({target_ip}) after retry")
                results[target_vm] = False
    
    return results

def test_all_vm_connectivity(configs: Dict[str, Any], vm_results: Dict[str, Any], 
                            ssh_manager: SSHManager, logger: logging.Logger) -> Dict[str, Dict[str, bool]]:
    """모든 VM들 간의 연결성을 종합적으로 테스트합니다."""
    logger.info("=== VM Connectivity Test ===")
    
    # 각 VM의 최종 IP 수집
    vm_ips = {}
    for vm_name, result in vm_results.items():
        if result and 'final_ip' in result:
            vm_ips[vm_name] = {
                'ip': result['final_ip'],
                'user': configs[vm_name]['user'],
                'pass': configs[vm_name]['pass'],
                'port': configs[vm_name]['port'],
                'os_type': result.get('os_type', 'linux')
            }
    
    # 각 VM에서 다른 VM들로의 연결성 테스트
    connectivity_matrix = {}
    for vm_name, vm_info in vm_ips.items():
        results = test_vm_connectivity(
            vm_name, 
            vm_info['ip'], 
            vm_ips, 
            vm_info['user'], 
            vm_info['pass'], 
            vm_info['port'],
            vm_info['os_type'],
            ssh_manager,
            logger
        )
        connectivity_matrix[vm_name] = results
    
    # 결과 요약 (VM 이름 순으로 정렬)
    logger.info("=== Connectivity Test Summary ===")
    # VM 이름 순으로 정렬
    sorted_connectivity_items = sorted(connectivity_matrix.items())
    for vm_name, connections in sorted_connectivity_items:
        successful = sum(1 for connected in connections.values() if connected)
        total = len(connections)
        logger.info(f"[{vm_name}] Connected to {successful}/{total} VMs")
        
        # 대상 VM들도 정렬
        sorted_connections = sorted(connections.items())
        for target_vm, connected in sorted_connections:
            status = "[SUCCESS]" if connected else "[FAILED]"
            logger.info(f"  {status} {vm_name} -> {target_vm}")
    
    return connectivity_matrix

def print_final_summary(vm_results: List[VMProcessResult], total_duration, connectivity_matrix: Dict[str, Dict[str, bool]], logger: logging.Logger) -> None:
    """전체 VM 처리 결과 요약을 출력합니다."""
    
    print("\n" + "="*80)
    print("                           전체 처리 결과 요약")
    print("="*80)
    
    successful_vms = [result for result in vm_results if result.success]
    failed_vms = [result for result in vm_results if not result.success]
    
    # 통계 출력
    total_vms = len(vm_results)
    success_count = len(successful_vms)
    failure_count = len(failed_vms)
    
    print(f"\n전체 통계:")
    print(f"   - 총 VM 수: {total_vms}")
    print(f"   - 성공: {success_count} ({success_count/total_vms*100:.1f}%)")
    print(f"   - 실패: {failure_count} ({failure_count/total_vms*100:.1f}%)")
    print(f"   - 총 소요 시간: {total_duration}")
    
    # 성공한 VM들 (VM 이름 순으로 정렬)
    if successful_vms:
        print(f"\n성공한 VM들 ({success_count}개):")
        # VM 이름 순으로 정렬
        sorted_successful_vms = sorted(successful_vms, key=lambda x: x.vm_name)
        for result in sorted_successful_vms:
            connectivity_text = "연결됨" if result.reachable else "연결 확인 필요"
            original_info = f" (원래: {result.original_ip})" if result.original_ip and result.original_ip != result.final_ip else ""
            
            print(f"   + {result.vm_name:<15} | IP: {result.final_ip:<15} | OS: {result.os_type:<8} | {connectivity_text}{original_info}")
    
    # VM 간 연결성 매트릭스
    if connectivity_matrix and len(connectivity_matrix) > 1:
        print(f"\nVM 간 연결성 매트릭스:")
        # VM 이름 순으로 정렬
        vm_names = sorted(connectivity_matrix.keys())
        
        # 헤더 출력
        print(f"   {'From/To':<12}", end="")
        for target_vm in vm_names:
            print(f" {target_vm[:8]:<8}", end="")
        print()
        
        # 구분선 출력
        print("   " + "-" * (12 + len(vm_names) * 9))
        
        # 연결성 매트릭스 출력
        for source_vm in vm_names:
            print(f"   {source_vm[:12]:<12}", end="")
            for target_vm in vm_names:
                if source_vm == target_vm:
                    symbol = "   -   "
                else:
                    is_connected = connectivity_matrix.get(source_vm, {}).get(target_vm, False)
                    symbol = "   O   " if is_connected else "   X   "
                print(f" {symbol:<8}", end="")
            print()
        
        print("\n   범례: O = 연결됨, X = 연결 실패, - = 자기 자신")
        
        # 연결성 요약
        total_connections = 0
        successful_connections = 0
        for source_vm, targets in connectivity_matrix.items():
            for target_vm, connected in targets.items():
                total_connections += 1
                if connected:
                    successful_connections += 1
        
        if total_connections > 0:
            connection_rate = (successful_connections / total_connections) * 100
            print(f"   연결 성공률: {successful_connections}/{total_connections} ({connection_rate:.1f}%)")
    
    # 네트워크 토폴로지 시각화
    if successful_vms and connectivity_matrix:
        print(f"\n네트워크 토폴로지:")
        connected_groups = find_connected_groups(connectivity_matrix)
        
        if len(connected_groups) == 1:
            print("   모든 VM이 하나의 네트워크 그룹에 연결되어 있습니다.")
            group = connected_groups[0]
            # VM 이름 순으로 정렬
            sorted_group = sorted(group)
            print(f"   연결된 VM들: {' <-> '.join(sorted_group)}")
        else:
            print(f"   {len(connected_groups)}개의 분리된 네트워크 그룹이 발견되었습니다:")
            for i, group in enumerate(connected_groups):
                # VM 이름 순으로 정렬
                sorted_group = sorted(group)
                print(f"   그룹 {i+1}: {' <-> '.join(sorted_group)}")
    
    # 실패한 VM들
    if failed_vms:
        print(f"\n실패한 VM들 ({failure_count}개):")
        
        # 실패 원인별 분류
        failure_categories = {}
        for result in failed_vms:
            reason = result.failure_reason or "알 수 없는 원인"
            if reason not in failure_categories:
                failure_categories[reason] = []
            failure_categories[reason].append(result.vm_name)
        
        for reason, vm_names in failure_categories.items():
            print(f"\n   실패 원인: {reason}")
            # VM 이름 순으로 정렬
            sorted_vm_names = sorted(vm_names)
            for vm_name in sorted_vm_names:
                print(f"      - {vm_name}")
    
    # 권장사항
    if failed_vms:
        print(f"\n권장사항:")
        has_mac_issues = any("MAC" in (result.failure_reason or "") for result in failed_vms)
        has_ip_issues = any("IP" in (result.failure_reason or "") or "ARP" in (result.failure_reason or "") for result in failed_vms)
        
        if has_mac_issues:
            print("   - VMX 파일의 MAC 주소 설정을 확인하세요")
        if has_ip_issues:
            print("   - VM들이 올바른 네트워크에 연결되어 있는지 확인하세요")
            print("   - VM들이 부팅되어 있고 네트워크가 활성화되어 있는지 확인하세요")
        
        print("   - VMware VM 상태와 네트워크 설정을 점검하세요")
    
    print("\n" + "="*80)

def find_connected_groups(connectivity_matrix: Dict[str, Dict[str, bool]]) -> List[List[str]]:
    """연결된 VM 그룹들을 찾습니다."""
    if not connectivity_matrix:
        return []
    
    vm_names = list(connectivity_matrix.keys())
    visited = set()
    groups = []
    
    def dfs(vm: str, current_group: List[str]):
        if vm in visited:
            return
        visited.add(vm)
        current_group.append(vm)
        
        # 이 VM과 연결된 다른 VM들을 찾습니다
        for target_vm in vm_names:
            if target_vm != vm and target_vm not in visited:
                # 양방향 연결 확인
                is_connected = (connectivity_matrix.get(vm, {}).get(target_vm, False) or 
                               connectivity_matrix.get(target_vm, {}).get(vm, False))
                if is_connected:
                    dfs(target_vm, current_group)
    
    for vm in vm_names:
        if vm not in visited:
            current_group = []
            dfs(vm, current_group)
            if current_group:
                groups.append(current_group)
    
    return groups

if __name__ == '__main__':
    sys.exit(main()) 