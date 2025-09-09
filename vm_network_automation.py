#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VM 네트워크 자동화 도구 - 메인 실행 파일
설정 파일이 없으면 템플릿을 복사하고 안내 메시지를 출력합니다.
"""

import os
import sys
import shutil
import json
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

# 설정 파일 경로
CONFIG_FILE = 'config.json'
VM_CONFIG_FILE = 'vm_config.json'
TEMPLATE_DIR = 'templates'
CONFIG_TEMPLATE = os.path.join(TEMPLATE_DIR, 'config_template.json')
VM_CONFIG_TEMPLATE = os.path.join(TEMPLATE_DIR, 'vm_config_template.json')

def print_banner():
    """프로그램 배너 출력"""
    print("=" * 80)
    print("                    VM 네트워크 자동화 도구")
    print("=" * 80)
    print()

def check_config_files():
    """설정 파일 존재 여부 확인"""
    config_exists = os.path.exists(CONFIG_FILE)
    vm_config_exists = os.path.exists(VM_CONFIG_FILE)
    
    return config_exists, vm_config_exists

def copy_template_files():
    """템플릿 파일들을 복사"""
    try:
        # config.json 복사
        if not os.path.exists(CONFIG_FILE):
            if os.path.exists(CONFIG_TEMPLATE):
                shutil.copy2(CONFIG_TEMPLATE, CONFIG_FILE)
                print(f"✓ {CONFIG_FILE} 템플릿을 복사했습니다.")
            else:
                print(f"✗ {CONFIG_TEMPLATE} 템플릿 파일을 찾을 수 없습니다.")
                return False
        
        # vm_config.json 복사
        if not os.path.exists(VM_CONFIG_FILE):
            if os.path.exists(VM_CONFIG_TEMPLATE):
                shutil.copy2(VM_CONFIG_TEMPLATE, VM_CONFIG_FILE)
                print(f"✓ {VM_CONFIG_FILE} 템플릿을 복사했습니다.")
            else:
                print(f"✗ {VM_CONFIG_TEMPLATE} 템플릿 파일을 찾을 수 없습니다.")
                return False
        
        return True
    except Exception as e:
        print(f"✗ 템플릿 파일 복사 중 오류 발생: {e}")
        return False

def validate_config_files():
    """설정 파일 유효성 검사"""
    try:
        # config.json 검증
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        
        # vm_config.json 검증
        with open(VM_CONFIG_FILE, 'r', encoding='utf-8') as f:
            vm_config_data = json.load(f)
        
        # 기본적인 구조 검증
        if 'vms' not in vm_config_data:
            print("✗ vm_config.json에 'vms' 섹션이 없습니다.")
            return False
        
        # VM 설정 검증
        vms = vm_config_data['vms']
        if not vms:
            print("✗ vm_config.json에 VM 설정이 없습니다.")
            return False
        
        # 각 VM의 필수 필드 검증
        for vm_name, vm_config in vms.items():
            required_fields = ['vmx', 'user', 'pass']
            for field in required_fields:
                if field not in vm_config:
                    print(f"✗ {vm_name}에 필수 필드 '{field}'가 없습니다.")
                    return False
            
            # VMX 파일 경로 검증
            vmx_path = vm_config['vmx']
            if 'VM의_VMX_파일_경로를_여기에_입력하세요' in vmx_path:
                print(f"✗ {vm_name}의 VMX 파일 경로가 템플릿 상태입니다.")
                return False
            
            # 사용자명/비밀번호 검증
            if vm_config['user'] == 'VM_사용자명' or vm_config['pass'] == 'VM_비밀번호':
                print(f"✗ {vm_name}의 사용자명 또는 비밀번호가 템플릿 상태입니다.")
                return False
        
        return True
    except json.JSONDecodeError as e:
        print(f"✗ JSON 파일 형식 오류: {e}")
        return False
    except Exception as e:
        print(f"✗ 설정 파일 검증 중 오류 발생: {e}")
        return False

def show_setup_instructions():
    """설정 안내 메시지 출력"""
    print("\n" + "=" * 80)
    print("                           설정 안내")
    print("=" * 80)
    print()
    print("설정 파일이 생성되었습니다. 다음 단계를 따라 설정을 완료하세요:")
    print()
    print("1. config.json 파일 수정:")
    print("   - 네트워크 설정 (base_network, gateway, dns 등)")
    print("   - 타임아웃 및 성능 설정")
    print("   - 필요에 따라 기본값을 수정하세요")
    print()
    print("2. vm_config.json 파일 수정:")
    print("   - 각 VM의 VMX 파일 경로를 실제 경로로 변경")
    print("   - VM 사용자명과 비밀번호 설정")
    print("   - IP 주소 및 네트워크 설정 (static 모드인 경우)")
    print("   - 불필요한 VM 설정은 삭제하세요")
    print()
    print("3. 설정 완료 후 프로그램을 다시 실행하세요.")
    print()
    print("=" * 80)
    print("중요 사항:")
    print("- VM들이 실행 중이어야 합니다")
    print("- SSH 서비스가 활성화되어 있어야 합니다")
    print("- VMX 파일 경로는 정확해야 합니다")
    print("- 네트워크 설정은 실제 환경에 맞게 조정하세요")
    print("=" * 80)

def run_main_program():
    """메인 프로그램 실행"""
    try:
        # main.py 모듈을 동적으로 import
        import main
        print("VM 네트워크 자동화를 시작합니다...")
        print()
        
        # main.py의 main 함수 실행
        return main.main()
    except ImportError as e:
        print(f"✗ main.py 모듈을 불러올 수 없습니다: {e}")
        return 1
    except Exception as e:
        print(f"✗ 프로그램 실행 중 오류 발생: {e}")
        return 1

def main():
    """메인 함수"""
    print_banner()
    
    # 설정 파일 존재 여부 확인
    config_exists, vm_config_exists = check_config_files()
    
    if not config_exists or not vm_config_exists:
        print("설정 파일이 없습니다. 템플릿을 복사합니다...")
        print()
        
        if not copy_template_files():
            print("템플릿 파일 복사에 실패했습니다.")
            return 1
        
        show_setup_instructions()
        print("\n프로그램을 종료합니다. 설정을 완료한 후 다시 실행하세요.")
        input("아무 키나 누르면 종료됩니다...")
        return 0
    
    # 설정 파일 유효성 검사
    print("설정 파일을 검증합니다...")
    if not validate_config_files():
        print("\n설정 파일에 오류가 있습니다. 위의 오류를 수정한 후 다시 실행하세요.")
        input("아무 키나 누르면 종료됩니다...")
        return 1
    
    print("✓ 설정 파일이 올바르게 구성되었습니다.")
    print()
    
    # 메인 프로그램 실행
    result = run_main_program()
    
    return result

if __name__ == '__main__':
    sys.exit(main())
