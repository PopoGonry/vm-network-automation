#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
.exe 빌드 스크립트
"""

import os
import sys
import subprocess
import shutil

def main():
    print("=" * 60)
    print("           VM 네트워크 자동화 도구 - 빌드")
    print("=" * 60)
    print()
    
    # 인코딩 설정
    if sys.platform == 'win32':
        try:
            os.system('chcp 65001 >nul')
        except:
            pass
        
        # Python 출력 스트림 인코딩 설정
        try:
            import codecs
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
            sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())
        except AttributeError:
            # detach() 메서드가 없는 경우 (일부 Windows 환경)
            pass
    
    # 현재 디렉토리 확인
    print(f"현재 디렉토리: {os.getcwd()}")
    
    # 필요한 파일들 확인
    required_files = [
        'vm_network_automation.py',
        'main.py',
        'utils/network_utils.py',
        'templates/config_template.json',
        'templates/vm_config_template.json',
        'requirements.txt'
    ]
    
    print("필요한 파일들을 확인합니다...")
    missing_files = []
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✓ {file_path}")
        else:
            print(f"✗ {file_path} (누락)")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n누락된 파일이 {len(missing_files)}개 있습니다.")
        print("프로젝트 루트 디렉토리에서 실행하세요.")
        return 1
    
    # 패키지 설치
    print("\n필요한 패키지를 설치합니다...")
    try:
        result = subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                              capture_output=True, text=True, encoding='utf-8', errors='ignore')
        if result.returncode == 0:
            print("✓ 패키지 설치 완료")
        else:
            print("✗ 패키지 설치 실패")
            print(result.stderr)
            return 1
    except Exception as e:
        print(f"✗ 패키지 설치 중 오류: {e}")
        return 1
    
    # 기존 빌드 파일들 정리
    print("\n기존 빌드 파일들을 정리합니다...")
    for dir_name in ['build', 'dist']:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"✓ {dir_name} 디렉토리 삭제됨")
    
    # .exe 파일 빌드
    print("\n.exe 파일을 빌드합니다...")
    try:
        cmd = [
            sys.executable, '-m', 'PyInstaller',
            '--onefile',
            '--console',
            '--name', 'VM_Network_Automation',
            '--add-data', 'templates;templates',
            '--add-data', 'utils;utils',
            '--hidden-import', 'paramiko',
            'vm_network_automation.py'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        if result.returncode == 0:
            print("✓ .exe 파일 빌드 완료!")
        else:
            print("✗ 빌드 실패:")
            print(result.stderr)
            return 1
    except Exception as e:
        print(f"✗ 빌드 중 오류: {e}")
        return 1
    
    # 배포용 패키지 생성
    print("\n배포용 패키지를 생성합니다...")
    dist_dir = 'VM_Network_Automation_Distribution'
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
    os.makedirs(dist_dir)
    
    exe_path = os.path.join('dist', 'VM_Network_Automation.exe')
    if os.path.exists(exe_path):
        shutil.copy2(exe_path, dist_dir)
        file_size = os.path.getsize(exe_path) / (1024 * 1024)
        print(f"✓ 실행 파일 생성됨: {file_size:.1f} MB")
    else:
        print("✗ 실행 파일을 찾을 수 없습니다.")
        return 1
    
    # templates 디렉토리 복사
    if os.path.exists('templates'):
        templates_dest = os.path.join(dist_dir, 'templates')
        shutil.copytree('templates', templates_dest)
        print("✓ templates 디렉토리 복사됨")
    
    # README 파일 생성
    readme_content = """# VM 네트워크 자동화 도구

## 사용 방법

1. VM_Network_Automation.exe를 실행합니다.
2. 처음 실행 시 설정 파일이 자동으로 생성됩니다.
3. 생성된 config.json과 vm_config.json 파일을 수정합니다.
4. 설정 완료 후 프로그램을 다시 실행합니다.

## 설정 파일

- config.json: 시스템 설정 (네트워크, 타임아웃, 성능 등)
- vm_config.json: VM별 설정 (VMX 경로, 사용자 정보, IP 설정 등)

## 템플릿 파일

- templates/config_template.json: 시스템 설정 템플릿
- templates/vm_config_template.json: VM 설정 템플릿

## 주의사항

- VM들이 실행 중이어야 합니다
- SSH 서비스가 활성화되어 있어야 합니다
- VMX 파일 경로는 정확해야 합니다
- 네트워크 설정은 실제 환경에 맞게 조정하세요

## 문제 해결

설정 파일에 오류가 있으면 프로그램이 안내 메시지를 표시합니다.
오류를 수정한 후 다시 실행하세요.

## 템플릿 파일 사용법

설정 파일을 처음부터 만들고 싶다면:
1. templates 폴더의 템플릿 파일들을 참고하세요
2. 템플릿 파일을 복사하여 config.json, vm_config.json으로 이름을 변경하세요
3. 내용을 실제 환경에 맞게 수정하세요
"""
    
    with open(os.path.join(dist_dir, 'README.txt'), 'w', encoding='utf-8') as f:
        f.write(readme_content)
    print("✓ README.txt 생성됨")
    
    # 빌드 과정에서 생성된 불필요한 파일들 정리
    print("\n빌드 과정에서 생성된 불필요한 파일들을 정리합니다...")
    cleanup_build_files()
    
    print("\n" + "=" * 60)
    print("                    빌드 완료!")
    print("=" * 60)
    print("VM_Network_Automation_Distribution 폴더를 확인하세요.")
    print("=" * 60)
    
    return 0

def cleanup_build_files():
    """빌드 과정에서 생성된 불필요한 파일들을 정리"""
    import glob
    
    # 정리할 디렉토리와 파일들
    cleanup_items = [
        # PyInstaller 빌드 디렉토리
        'build',
        'dist',
        
        # PyInstaller spec 파일
        '*.spec',
        
        # Python 캐시 파일들
        '__pycache__',
        '**/__pycache__',
        '**/*.pyc',
        '**/*.pyo',
        
        # 임시 파일들
        '*.tmp',
        '*.temp',
        '*.log',
        
        # PyInstaller 관련 임시 파일들
        '*.toc',
        '*.pkg',
        '*.pyz',
        'warn-*.txt',
        'xref-*.html',
        'Analysis-*.toc',
        'EXE-*.toc',
        'PKG-*.toc',
        'PYZ-*.toc',
        'localpycs',
    ]
    
    cleaned_count = 0
    
    for item in cleanup_items:
        try:
            if '*' in item:
                # 와일드카드 패턴 처리
                files = glob.glob(item, recursive=True)
                for file_path in files:
                    if os.path.exists(file_path):
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                            print(f"✓ 파일 삭제: {file_path}")
                            cleaned_count += 1
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                            print(f"✓ 디렉토리 삭제: {file_path}")
                            cleaned_count += 1
            else:
                # 단일 파일/디렉토리 처리
                if os.path.exists(item):
                    if os.path.isfile(item):
                        os.remove(item)
                        print(f"✓ 파일 삭제: {item}")
                        cleaned_count += 1
                    elif os.path.isdir(item):
                        shutil.rmtree(item)
                        print(f"✓ 디렉토리 삭제: {item}")
                        cleaned_count += 1
        except Exception as e:
            print(f"⚠ 정리 실패: {item} - {e}")
    
    if cleaned_count > 0:
        print(f"✓ 총 {cleaned_count}개의 파일/디렉토리를 정리했습니다.")
    else:
        print("✓ 정리할 파일이 없습니다.")

if __name__ == '__main__':
    sys.exit(main())
