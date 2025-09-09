#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
네트워크 유틸리티 함수들
VM 네트워크 설정에 필요한 공통 함수들을 제공합니다.
"""

import subprocess
import re
import time
import logging
import threading
import sys
from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass

# 인코딩 설정
if sys.platform == 'win32':
    import codecs
    try:
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())
    except AttributeError:
        # detach() 메서드가 없는 경우 (일부 Windows 환경)
        pass

# Lock for ARP lookups
arp_lock = threading.Lock()

@dataclass
class NetworkInterface:
    """네트워크 인터페이스 정보"""
    name: str
    mac_address: str
    ip_address: str
    status: str
    connection_profile: Optional[str] = None

class NetworkUtils:
    """네트워크 유틸리티 클래스"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def get_mac_from_vmx(self, vmx_path: str, vm_name: str) -> Optional[str]:
        """VMX 파일에서 MAC 주소를 추출합니다."""
        # 여러 인코딩을 시도
        encodings = ['utf-8', 'cp949', 'euc-kr', 'latin-1', 'ascii']
        
        for encoding in encodings:
            try:
                with open(vmx_path, 'r', encoding=encoding) as f:
                    for line in f:
                        if 'ethernet0.generatedAddress' in line:
                            mac = line.split('=')[1].strip().strip('"')
                            if self._validate_mac(mac):
                                self.logger.info(f"[{vm_name}] MAC: {mac} (encoding: {encoding})")
                                return mac
                            else:
                                self.logger.error(f"[{vm_name}] Invalid MAC format: {mac}")
                
                # 파일을 성공적으로 읽었지만 MAC을 찾지 못한 경우
                self.logger.warning(f"[{vm_name}] VMX file read successfully with {encoding} but MAC not found")
                break
                
            except UnicodeDecodeError:
                self.logger.debug(f"[{vm_name}] Failed to read VMX with {encoding}, trying next encoding...")
                continue
            except Exception as e:
                self.logger.error(f"[{vm_name}] Failed to read VMX with {encoding}: {e}")
                continue
        
        self.logger.error(f"[{vm_name}] MAC not found, skipping")
        return None
    
    def get_ip_from_mac(self, mac: str, vm_name: str) -> Optional[str]:
        """ARP 테이블에서 MAC 주소로 IP를 찾습니다."""
        with arp_lock:
            self.logger.info(f"[{vm_name}] ARP lookup for MAC {mac}")
            try:
                arp = subprocess.check_output('arp -a', shell=True, encoding='cp949', errors='ignore')
                
                # 여러 MAC 주소 형식으로 시도
                mac_patterns = [
                    mac.replace(':', '-'),  # 00:0c:29:xx:xx:xx -> 00-0c-29-xx-xx-xx
                    mac.replace(':', ''),   # 00:0c:29:xx:xx:xx -> 000c29xxxxxx
                    mac.upper(),            # 대문자로 변환
                    mac.lower()             # 소문자로 변환
                ]
                
                for pattern in mac_patterns:
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+.*" + pattern, arp, re.I)
                    if m:
                        ip = m.group(1)
                        if self._validate_ip(ip):
                            self.logger.info(f"[{vm_name}] Found IP: {ip} with pattern {pattern}")
                            return ip
                
                # ARP 테이블에서 MAC 주소가 없는 경우 로그
                self.logger.debug(f"[{vm_name}] ARP table content: {arp}")
                self.logger.error(f"[{vm_name}] MAC {mac} not found in ARP table")
                
            except Exception as e:
                self.logger.error(f"[{vm_name}] ARP lookup failed: {e}")
            return None
    
    def detect_os(self, ip: str, vm_name: str, user: str, password: str, port: int, 
                  ssh_manager) -> str:
        """원격 시스템의 OS를 감지합니다."""
        # 먼저 Linux 명령어로 시도
        out, _ = ssh_manager.run_command(ip, user, password, 'cat /etc/os-release', port, vm_name)
        if out:
            if any(x in out for x in ('Ubuntu', 'CentOS', 'Kali', 'Debian')):
                self.logger.info(f"[{vm_name}] Detected OS: linux")
                return 'linux'
        
        # Linux 명령어가 실패하면 Windows 명령어 시도
        out, _ = ssh_manager.run_command(ip, user, password, 'ver', port, vm_name)
        if out:
            if any(x in out for x in ('Microsoft', 'Windows')):
                self.logger.info(f"[{vm_name}] Detected OS: windows")
                return 'windows'
        
        # VM 이름으로 OS 추정 (fallback)
        vm_name_lower = vm_name.lower()
        if 'windows' in vm_name_lower:
            self.logger.info(f"[{vm_name}] Detected OS: windows (from VM name)")
            return 'windows'
        elif any(x in vm_name_lower for x in ['ubuntu', 'kali', 'linux']):
            self.logger.info(f"[{vm_name}] Detected OS: linux (from VM name)")
            return 'linux'
        
        self.logger.info(f"[{vm_name}] Defaulting OS to linux")
        return 'linux'
    
    def test_connectivity(self, ip: str, vm_name: str, ping_count: int = 1) -> bool:
        """IP 연결성을 테스트합니다."""
        try:
            import os
            reachable = subprocess.call(
                ['ping', '-n', str(ping_count), ip] if os.name == 'nt' else ['ping', '-c', str(ping_count), ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return reachable == 0
        except Exception as e:
            self.logger.error(f"[{vm_name}] Connectivity test failed: {e}")
            return False
    
    def _validate_ip(self, ip_str: str) -> bool:
        """IP 주소 형식을 검증합니다."""
        try:
            import ipaddress
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def _validate_mac(self, mac_str: str) -> bool:
        """MAC 주소 형식을 검증합니다."""
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_pattern.match(mac_str))

class LinuxNetworkManager:
    """Linux 네트워크 관리 클래스"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def detect_interface(self, ip: str, vm_name: str, user: str, password: str, port: int, 
                        ssh_manager) -> str:
        """Linux VM의 기본 네트워크 인터페이스를 감지합니다."""
        cmd = "ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}'"
        out, _ = ssh_manager.run_command(ip, user, password, cmd, port, vm_name)
        if out:
            lines = [line.strip() for line in out.splitlines() if line.strip()]
            iface = lines[-1]
        else:
            iface = 'ens33'
        self.logger.info(f"[{vm_name}] Detected Linux interface: {iface}")
        return iface
    
    def detect_connection_name(self, ip: str, vm_name: str, user: str, password: str, port: int, 
                              iface: str, ssh_manager) -> str:
        """NetworkManager 연결 프로필 이름을 감지합니다."""
        cmd = f"nmcli -t -f NAME,DEVICE connection show | grep ':{iface}$'"
        out, _ = ssh_manager.run_command(ip, user, password, cmd, port, vm_name)
        if out:
            lines = [line.strip() for line in out.splitlines() if line.strip()]
            profiles = [line.split(':', 1)[0] for line in lines]
            connection_name = profiles[-1]
        else:
            connection_name = iface
        self.logger.info(f"[{vm_name}] Connection profile: {connection_name}")
        return connection_name
    
    def fetch_dhcp_ip(self, ip: str, vm_name: str, user: str, password: str, port: int, 
                      iface: str, ssh_manager) -> str:
        """DHCP로 할당된 IP를 가져옵니다."""
        cmd = f"ip -o -4 addr show {iface} | awk '{{print $4}}'"
        out, _ = ssh_manager.run_command(ip, user, password, cmd, port, vm_name)
        if out:
            # 출력에서 비밀번호나 불필요한 문자 제거
            lines = out.strip().splitlines()
            dhcp_ips = []
            
            for line in lines:
                line = line.strip()
                # IP 주소 패턴만 찾기
                if '/' in line and '192.168.32.' in line:
                    cidr = line.split()[0] if line.split() else line
                    dhcp_ip = cidr.split('/')[0]
                    if self._validate_ip(dhcp_ip):
                        dhcp_ips.append(dhcp_ip)
                        self.logger.debug(f"[{vm_name}] Found IP: {dhcp_ip}")
            
            # 중복 IP가 있는 경우 처리
            if len(dhcp_ips) > 1:
                self.logger.warning(f"[{vm_name}] Multiple IPs found: {dhcp_ips}")
                
                # 가장 최근에 할당된 IP 선택 (일반적으로 마지막 IP)
                # 또는 기존 IP와 다른 IP 선택
                for dhcp_ip in dhcp_ips:
                    if dhcp_ip != ip:
                        self.logger.info(f"[{vm_name}] Selected new DHCP IP: {dhcp_ip}")
                        return dhcp_ip
                
                # 모든 IP가 기존 IP와 같다면 첫 번째 IP 사용
                self.logger.info(f"[{vm_name}] Using first DHCP IP: {dhcp_ips[0]}")
                return dhcp_ips[0]
            elif len(dhcp_ips) == 1:
                self.logger.info(f"[{vm_name}] DHCP assigned IP: {dhcp_ips[0]}")
                return dhcp_ips[0]
            else:
                self.logger.warning(f"[{vm_name}] No valid DHCP IPs found")
        
        self.logger.warning(f"[{vm_name}] No new IP found, using original IP: {ip}")
        return ip
    
    def _validate_ip(self, ip_str: str) -> bool:
        """IP 주소 형식을 검증합니다."""
        try:
            import ipaddress
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

class WindowsNetworkManager:
    """Windows 네트워크 관리 클래스"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def detect_interfaces(self, ip: str, user: str, password: str, port: int, 
                         vm_name: Optional[str] = None, ssh_manager=None) -> List[str]:
        """Windows에서 연결된 네트워크 인터페이스 이름들을 반환합니다."""
        cmd = 'netsh interface show interface'
        out, _ = ssh_manager.run_command(ip, user, password, cmd, port, vm_name)
        if out:
            lines = out.splitlines()
            candidates = []
            self.logger.debug(f"[Windows] Interface detection output:\n{out}")
            
            for line in lines:
                # ANSI 이스케이프 코드 제거
                clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line)
                clean_line = re.sub(r'\x1b\[[0-9]*[a-zA-Z]', '', clean_line)
                clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', clean_line)
                # 추가로 특수 문자 제거
                clean_line = clean_line.replace('\x1b[?25h', '').replace('\x1b[6;1H', '')
                
                # 영문/한글 모두 대응
                if (('Connected' in clean_line or '연결됨' in clean_line) and 
                    ('Dedicated' in clean_line or '전용' in clean_line)):
                    parts = clean_line.split()
                    if parts:
                        interface_name = parts[-1]
                        # 따옴표 제거
                        interface_name = interface_name.strip('"')
                        candidates.append(interface_name)
                        self.logger.debug(f"[Windows] Found interface: {interface_name}")
            
            if candidates:
                self.logger.info(f"[Windows] Detected interfaces: {candidates}")
                return candidates
        
        # 기본값들
        default_interfaces = ['Ethernet0', 'Ethernet', '이더넷', '로컬 영역 연결', 'Local Area Connection']
        self.logger.info(f"[Windows] Using default interfaces: {default_interfaces}")
        return default_interfaces
    
    def configure_dhcp(self, ip: str, vm_name: str, user: str, password: str, port: int, 
                       iface: str, ssh_manager) -> bool:
        """DHCP 설정"""
        try:
            out1, err1 = ssh_manager.run_command(ip, user, password, 
                                                f'netsh interface ip set address "{iface}" dhcp', port, vm_name, extended_timeout=True)
            out2, err2 = ssh_manager.run_command(ip, user, password, 
                                                f'netsh interface ip set dns "{iface}" dhcp', port, vm_name, extended_timeout=True)
            
            self.logger.info(f"[{vm_name}] DHCP configuration completed for {iface}")
            return True
        except Exception as e:
            self.logger.error(f"[{vm_name}] DHCP configuration failed for {iface}: {e}")
            return False
    
    def configure_static(self, ip: str, vm_name: str, user: str, password: str, port: int, 
                        iface: str, cfg: Dict[str, Any], ssh_manager) -> bool:
        """정적 IP 설정"""
        try:
            # 네트워크 설정 명령어들을 한 번에 실행
            network_commands = [
                f'netsh interface ip set address "{iface}" static {cfg["ip"]} {cfg["subnet_mask"]} {cfg["gateway"]}',
                f'netsh interface ip set dns "{iface}" static {cfg["dns"]}',
                f'netsh interface ip add dns "{iface}" {cfg["secondary_dns"]} index=2'
            ]
            
            # 모든 네트워크 설정 명령어 실행
            self.logger.info(f"[{vm_name}] Executing network configuration commands for {iface}...")
            for i, cmd in enumerate(network_commands):
                out, err = ssh_manager.run_command(ip, user, password, cmd, port, vm_name)
                if out is not None:
                    self.logger.debug(f"[{vm_name}] Command {i+1} successful")
                else:
                    self.logger.warning(f"[{vm_name}] Command {i+1} failed, but continuing...")
            
            self.logger.info(f"[{vm_name}] Static IP configuration completed for {iface}")
            return True
        except Exception as e:
            self.logger.error(f"[{vm_name}] Static IP configuration failed for {iface}: {e}")
            return False
    
    def verify_connection(self, new_ip: str, vm_name: str, user: str, password: str, port: int, 
                         ssh_manager) -> bool:
        """연결 확인"""
        try:
            test_out, _ = ssh_manager.run_command(new_ip, user, password, 'ipconfig', port, vm_name)
            if test_out is not None:
                self.logger.info(f"[{vm_name}] [SUCCESS] SSH connection to new IP {new_ip} successful")
                return True
            else:
                self.logger.warning(f"[{vm_name}] [FAILED] SSH connection to new IP {new_ip} failed")
                return False
        except Exception as e:
            self.logger.error(f"[{vm_name}] Connection verification failed: {e}")
            return False
    
    # PowerShell Remoting용 메서드들
    def detect_interfaces_powershell(self, ip: str, user: str, password: str, 
                                   vm_name: Optional[str] = None, powershell_manager=None) -> List[str]:
        """PowerShell을 사용하여 Windows에서 연결된 네트워크 인터페이스 이름들을 반환합니다."""
        cmd = 'netsh interface show interface'
        out, _ = powershell_manager.run_command(ip, user, password, cmd, vm_name)
        if out:
            lines = out.splitlines()
            candidates = []
            self.logger.debug(f"[Windows] Interface detection output:\n{out}")
            
            for line in lines:
                # ANSI 이스케이프 코드 제거
                clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line)
                clean_line = re.sub(r'\x1b\[[0-9]*[a-zA-Z]', '', clean_line)
                clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', clean_line)
                # 추가로 특수 문자 제거
                clean_line = clean_line.replace('\x1b[?25h', '').replace('\x1b[6;1H', '')
                
                # 영문/한글 모두 대응
                if (('Connected' in clean_line or '연결됨' in clean_line) and 
                    ('Dedicated' in clean_line or '전용' in clean_line)):
                    parts = clean_line.split()
                    if parts:
                        interface_name = parts[-1]
                        # 따옴표 제거
                        interface_name = interface_name.strip('"')
                        candidates.append(interface_name)
                        self.logger.debug(f"[Windows] Found interface: {interface_name}")
            
            if candidates:
                self.logger.info(f"[Windows] Detected interfaces: {candidates}")
                return candidates
        
        # 기본값들
        default_interfaces = ["Ethernet0", "Ethernet", "이더넷", "로컬 영역 연결", "Local Area Connection"]
        self.logger.warning(f"[Windows] No interfaces detected, using defaults: {default_interfaces}")
        return default_interfaces
    
    def configure_dhcp_powershell(self, ip: str, vm_name: str, user: str, password: str, 
                                 iface: str, powershell_manager) -> bool:
        """PowerShell을 사용한 DHCP 설정"""
        try:
            out1, err1 = powershell_manager.run_command(ip, user, password, 
                                                      f'netsh interface ip set address "{iface}" dhcp', vm_name)
            out2, err2 = powershell_manager.run_command(ip, user, password, 
                                                      f'netsh interface ip set dns "{iface}" dhcp', vm_name)
            
            self.logger.info(f"[{vm_name}] DHCP configuration completed for {iface}")
            return True
        except Exception as e:
            self.logger.error(f"[{vm_name}] DHCP configuration failed for {iface}: {e}")
            return False
    
    def configure_static_powershell(self, ip: str, vm_name: str, user: str, password: str, 
                                   iface: str, cfg: Dict[str, Any], powershell_manager) -> bool:
        """PowerShell을 사용한 정적 IP 설정"""
        try:
            # 네트워크 설정 명령어들을 한 번에 실행
            network_commands = [
                f'netsh interface ip set address "{iface}" static {cfg["ip"]} {cfg["subnet_mask"]} {cfg["gateway"]}',
                f'netsh interface ip set dns "{iface}" static {cfg["dns"]}',
                f'netsh interface ip add dns "{iface}" {cfg["secondary_dns"]} index=2'
            ]
            
            # 모든 네트워크 설정 명령어 실행
            self.logger.info(f"[{vm_name}] Executing network configuration commands for {iface}...")
            for i, cmd in enumerate(network_commands):
                out, err = powershell_manager.run_command(ip, user, password, cmd, vm_name)
                if out is not None:
                    self.logger.debug(f"[{vm_name}] Command {i+1} successful")
                else:
                    self.logger.warning(f"[{vm_name}] Command {i+1} failed, but continuing...")
            
            self.logger.info(f"[{vm_name}] Static IP configuration completed for {iface}")
            return True
        except Exception as e:
            self.logger.error(f"[{vm_name}] Static IP configuration failed for {iface}: {e}")
            return False
    
    def verify_connection_powershell(self, new_ip: str, vm_name: str, user: str, password: str, 
                                   powershell_manager) -> bool:
        """PowerShell을 사용한 연결 확인"""
        try:
            test_out, _ = powershell_manager.run_command(new_ip, user, password, 'ipconfig', vm_name)
            if test_out is not None:
                self.logger.info(f"[{vm_name}] [SUCCESS] PowerShell connection to new IP {new_ip} successful")
                return True
            else:
                self.logger.warning(f"[{vm_name}] [FAILED] PowerShell connection to new IP {new_ip} failed")
                return False
        except Exception as e:
            self.logger.error(f"[{vm_name}] PowerShell connection verification error: {e}")
            return False 