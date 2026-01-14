# VM 네트워크 자동화 프로그램

VMware VM들의 네트워크 설정을 자동화하는 도구입니다. SSH를 통해 원격으로 VM의 네트워크 인터페이스를 구성하고 연결성을 테스트합니다.

## 🚀 주요 기능

- **VM 네트워크 자동 설정**: Linux/Windows VM의 네트워크 인터페이스를 SSH로 원격 구성
- **VMX 파일 연동**: VMware VMX 파일에서 MAC 주소를 자동 추출
- **병렬 처리**: 여러 VM을 동시에 처리하여 성능 최적화
- **연결성 테스트**: VM 간 네트워크 연결성 자동 검증
- **ARP 테이블 활용**: MAC 주소를 통한 IP 주소 자동 매핑
- **로깅 시스템**: 상세한 실행 로그 및 네트워크 설정 로그 저장

## 📁 프로젝트 구조

```
vm-network-automation/
├── main.py                 # 메인 실행 파일
├── config.json            # 시스템 설정
├── vm_config.json         # VM별 설정
├── utils/                 # 유틸리티 모듈
│   └── network_utils.py   # 네트워크 유틸리티 함수
├── templates/             # 설정 템플릿 파일
│   ├── config_template.json
│   └── vm_config_template.json
├── logs/                  # 로그 파일
│   ├── netconfig_improved.log
│   └── network_log.json
├── __pycache__/          # Python 캐시 파일
├── LICENSE               # 라이선스 파일
└── README.md
```

## 🛠️ 설치 및 설정

### 1. 의존성 설치
```bash
# Python 3.7+ 필요
pip install paramiko

# 또는 requirements.txt가 있다면
pip install -r requirements.txt
```

**필요한 Python 패키지:**
- `paramiko`: SSH 연결 및 원격 명령 실행
- `concurrent.futures`: 병렬 처리 (Python 3.2+ 내장)
- `ipaddress`: IP 주소 처리 (Python 3.3+ 내장)
- `dataclasses`: 데이터 클래스 (Python 3.7+ 내장)

### 2. 설정 파일 구성
- `config.json`: 시스템 전반 설정 (타임아웃, 성능, 대기시간 등)
- `vm_config.json`: VM별 설정 (IP, 사용자 정보 등)
- `templates/`: 설정 파일 템플릿
  - `config_template.json`: 시스템 설정 템플릿
  - `vm_config_template.json`: VM 설정 템플릿

### 3. VM 설정
각 VM에 SSH 접속이 가능하도록 설정:

**Linux VM:**
```bash
# SSH 서비스 설치 및 활성화
sudo apt update
sudo apt install openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh

# 방화벽 설정 (ICMP 허용)
sudo ufw allow ssh
sudo ufw allow icmp
```

**Windows VM:**
- OpenSSH 서버 설치 및 활성화
- Windows 방화벽에서 SSH 포트(22) 허용
- ICMP 프로토콜 허용

**VMware 설정:**
- VMX 파일 경로를 `vm_config.json`에 정확히 설정
- VM이 실행 중이어야 함

## 🎯 사용법

### 기본 실행
```bash
python main.py
```

### 로그 확인
```bash
# 상세 로그 확인 (Windows)
type logs\netconfig_improved.log

# 네트워크 로그 확인 (Windows)
type logs\network_log.json

# Linux/Mac의 경우
cat logs/netconfig_improved.log
cat logs/network_log.json
```

## ⚙️ 설정 최적화

### config.json 설정 예제
```json
{
  "network": {
    "base_network": "192.168.32",
    "gateway": "192.168.32.2",
    "dns_primary": "8.8.8.8",
    "dns_secondary": "8.8.4.4",
    "subnet_mask": "255.255.255.0"
  },
  "timeouts": {
    "ssh_connection": 2,
    "network_scan": 0.5,
    "ping_short": 30,
    "ping_medium": 50,
    "ping_long": 100
  },
  "performance": {
    "arp_workers": 200,
    "ping_test_workers": 80,
    "network_scan_workers": 200,
    "vm_processing_workers_multiplier": 10,
    "max_vm_processing_workers": 40
  }
}
```

### vm_config.json 설정 예제
```json
{
  "vms": {
    "Ubuntu1": {
      "vmx": "C:\\Users\\username\\AppData\\Roaming\\Virtual Machines\\Ubuntu1\\Ubuntu1.vmx",
      "mode": "static",
      "ip": "192.168.32.111",
      "gateway": "192.168.32.2",
      "subnet_mask": "255.255.255.0",
      "dns": "8.8.8.8",
      "secondary_dns": "8.8.4.4",
      "user": "ubuntu",
      "pass": "password"
    }
  }
}
```

## 📊 네트워크 자동화 시스템

### 주요 기능
- **VM 네트워크 설정**: Linux/Windows VM의 네트워크 인터페이스 자동 구성
- **병렬 처리**: 여러 VM을 동시에 처리하여 성능 최적화
- **연결성 검증**: VM 간 네트워크 연결성 자동 테스트
- **로그 관리**: 상세한 실행 로그 및 네트워크 설정 로그 저장

### 로그 파일
- `logs/netconfig_improved.log`: 상세 실행 로그
- `logs/network_log.json`: 네트워크 설정 및 테스트 결과

## 🔧 고급 사용법

### 네트워크 유틸리티 직접 사용
```python
import logging
from utils.network_utils import NetworkUtils, NetworkInterface

# 로거 설정
logger = logging.getLogger(__name__)

# 네트워크 유틸리티 인스턴스 생성
network_utils = NetworkUtils(logger)

# VMX 파일에서 MAC 주소 추출
mac_address = network_utils.get_mac_from_vmx("path/to/vm.vmx", "vm_name")

# ARP 테이블에서 IP 주소 조회
ip_address = network_utils.get_ip_from_arp(mac_address)

# 네트워크 인터페이스 정보 생성
interface = NetworkInterface(
    name="eth0",
    mac_address=mac_address,
    ip_address=ip_address,
    status="up"
)
```

## 📈 성능 최적화

### 권장 설정값
- **워커 수**: CPU 코어 수의 2-4배
- **타임아웃**: 네트워크 환경에 따라 조정
- **대기 시간**: 안정성과 속도의 균형점

### 성능 모니터링
- 실행 시간 추적
- 성공률 모니터링
- 리소스 사용량 확인

## 🐛 문제 해결

### 일반적인 문제
1. **SSH 연결 실패**: VM 설정 및 네트워크 연결 확인
2. **타임아웃 오류**: 타임아웃 설정 증가
3. **권한 오류**: VM 사용자 권한 확인

### 로그 확인
- `logs/netconfig_improved.log`: 상세 실행 로그
- `logs/network_log.json`: 네트워크 설정 로그

## 📝 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

**주의**: 이 도구는 테스트 환경에서만 사용하세요. 프로덕션 환경에서 사용하기 전에 충분한 테스트를 수행하세요.
