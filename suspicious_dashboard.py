import os
import time
from datetime import datetime
import hashlib
from Crypto.Cipher import AES
import sys
from collections import deque

class MalwareAnalysisDashboard:
    def __init__(self):
        self.DISPLAY_LINES = 10
        self.hex_buffer = deque(maxlen=self.DISPLAY_LINES)
        self.suspicious_patterns = {
            # 한글 패턴
            "이거어때".encode('utf-8'): 'Korean text found',
            "보이니".encode('utf-8'): 'Korean text found',
            "안녕하세요".encode('utf-8'): 'Korean text found',
            
            # 악성 행위 관련
            b'KILL': 'Possible malicious identifier',
            b'exec': 'Execution attempt',
            b'system': 'System access attempt',
            b'root': 'Root privilege attempt',
            b'su ': 'Superuser command',
            b'chmod': 'Permission modification',
            b'rm -rf': 'File deletion attempt',
            
            # 네트워크 관련
            b'http://': 'HTTP connection',
            b'https://': 'HTTPS connection',
            b'firebase': 'Firebase connection',
            b'tcp': 'TCP connection',
            b'udp': 'UDP connection',
            b'socket': 'Socket operation',
            b'connect': 'Network connection attempt',
            
            # API 및 서비스
            b'api.': 'API endpoint',
            b'.com': 'Domain access',
            b'.kr': 'Korean domain access',
            b'gmail': 'Gmail related',
            b'cloud': 'Cloud service access',
            
            # 파일 시스템 접근
            b'/data': 'Data directory access',
            b'/system': 'System directory access',
            b'/sdcard': 'External storage access',
            b'.dex': 'DEX file operation',
            b'.apk': 'APK file operation',
            
            # 권한 관련
            b'permission': 'Permission related',
            b'WRITE_EXTERNAL': 'Storage write permission',
            b'READ_EXTERNAL': 'Storage read permission',
            b'INTERNET': 'Internet permission',
            
            # 디바이스 정보
            b'getDeviceId': 'Device ID access',
            b'getImei': 'IMEI access',
            b'getSubscriberId': 'IMSI access',
            b'getSimSerialNumber': 'SIM serial access',
            
            # 암호화 관련
            b'AES': 'AES encryption',
            b'DES': 'DES encryption',
            b'RSA': 'RSA encryption',
            b'MD5': 'MD5 hash',
            b'SHA': 'SHA hash',
            
            # 앱 관련
            b'ActivityManager': 'Activity management',
            b'PackageManager': 'Package management',
            b'getPackageName': 'Package name access',
            b'getApplicationInfo': 'App info access',
            
            # 추가 의심 문자열
            b'shell': 'Shell command',
            b'download': 'Download operation',
            b'upload': 'Upload operation',
            b'delete': 'Delete operation',
            b'base64': 'Base64 encoding/decoding',
            b'eval': 'Code evaluation',
            b'reflect': 'Reflection usage',
            b'native': 'Native code usage'
        }
        self.found_suspicious = set()

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def format_hex_line(self, offset: int, data: bytes, reason: str = None) -> str:
        """의심스러운 영역 하이라이트와 함께 헥스 라인 포맷팅"""
        hex_part = ' '.join(f'{b:02x}' for b in data)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
        line = f"{offset:08x}  {hex_part:<48}  |{ascii_part}|"
        if reason:
            line = f"{line} <- {reason}"
        return line

    def check_suspicious(self, offset: int, data: bytes):
        """의심스러운 패턴 확인 및 한글 문자열 검사"""
        # 기�� 패턴 체크
        for pattern, reason in self.suspicious_patterns.items():
            if pattern in data:
                hex_line = self.format_hex_line(offset, data, reason)
                self.hex_buffer.append(hex_line)
                self.found_suspicious.add((pattern, reason))
                return True
        
        # 추가: 일반 텍스트 문자열 검사 (4자 이상)
        try:
            text = data.decode('utf-8', errors='ignore')
            if len(text.strip()) >= 4 and text.isprintable():
                hex_line = self.format_hex_line(offset, data, f"Readable text: {text.strip()}")
                self.hex_buffer.append(hex_line)
                return True
        except:
            pass
        
        return False

    def display_dashboard(self):
        """분석 대시보드 표시"""
        self.clear_screen()
        print("="*100)
        print("MALWARE ANALYSIS DASHBOARD - SUSPICIOUS AREAS AND STRINGS")
        print("="*100)
        print("OFFSET    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |ASCII|   REASON")
        print("-"*100)
        
        for line in self.hex_buffer:
            print(line)
            
        remaining_lines = self.DISPLAY_LINES - len(self.hex_buffer)
        for _ in range(remaining_lines):
            print()
            
        print("-"*100)
        if self.found_suspicious:
            print("Found Suspicious Patterns:")
            for pattern, reason in sorted(self.found_suspicious):
                try:
                    pattern_str = pattern.decode('utf-8', errors='replace')
                except:
                    pattern_str = str(pattern)
                print(f"- {pattern_str}: {reason}")
        sys.stdout.flush()

class DexDecryptor:
    def __init__(self):
        self.key = b'dbcdcfghijklmaop'
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.dashboard = MalwareAnalysisDashboard()

    def analyze_block(self, offset: int, block: bytes, is_encrypted: bool = True):
        """블록 분석 및 의심 영역 확인"""
        if is_encrypted:
            try:
                decrypted_block = self.cipher.decrypt(block)
            except:
                decrypted_block = block
        else:
            decrypted_block = block
            
        if self.dashboard.check_suspicious(offset, decrypted_block):
            self.dashboard.display_dashboard()
            time.sleep(0.2)  # 의심 영역 발견 시 잠시 멈춤

    def process_file(self, file_path: str):
        """파일 분석 수행"""
        print(f"\nAnalyzing: {file_path}")
        
        try:
            with open(file_path, 'rb') as f:
                offset = 0
                while True:
                    block = f.read(16)
                    if not block:
                        break
                    if len(block) < 16:
                        block = block.ljust(16, b'\0')
                    self.analyze_block(offset, block)
                    offset += 16
        except Exception as e:
            print(f"Error processing file: {str(e)}")

def main():
    # 파일 경로 설정
    target_file = "/Users/yesunglim/sandbox/sample/kill-classes.dex"
    
    if not os.path.exists(target_file):
        print(f"Error: File not found - {target_file}")
        return

    try:
        decryptor = DexDecryptor()
        decryptor.process_file(target_file)
        
        print("\nAnalysis complete!")
        input("\nPress Enter to exit...")
    except Exception as e:
        print(f"Critical error: {str(e)}")

if __name__ == "__main__":
    main()