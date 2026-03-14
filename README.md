# URL 보안 스캐너 CLI

Cloudflare + VirusTotal + 다중 API 보안 분석 도구

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> 교육 및 보안 연구 목적의 URL 보안 분석 도구

## 주요 기능

### 1. URL 구조 분석
- HTTPS 사용 여부 확인
- 의심스러운 문자 탐지
- 직접 IP 주소 사용 확인
- 의심스러운 TLD 탐지 (.tk, .ml, .ga 등)
- URL 길이 및 서브도메인 개수 분석

### 2. DNS 레코드 검사
- A 레코드 조회
- MX 레코드 확인
- DNS 레코드 존재 여부 검증

### 3. SSL/TLS 인증서 검사
- 인증서 유효성 확인
- 발급자 정보 조회
- 만료일 확인
- 인증서 버전 검사

### 4. 악성 패턴 탐지
- 피싱 키워드 탐지 (login, verify, banking 등)
- 도박/불법 사이트 키워드 탐지 (한글 + 영문)
- 성인 콘텐츠 키워드 탐지
- 의심스러운 패턴 검사

### 5. Cloudflare DNS 필터링
- Cloudflare 1.1.1.2 (악성코드 차단 DNS) 사용
- 차단된 사이트 자동 감지
- 실시간 필터링 확인

### 6. VirusTotal 검사
- 70개 이상의 보안 엔진으로 URL 검사
- 악성/의심 사이트 탐지율 확인
- 자동 URL 제출 기능

## 설치

### 자동 설치
```bash
install.bat
```

### 수동 설치
```bash
pip install -r requirements.txt
```

## 사용법

### 기본 사용
```bash
python scanner_cli.py https://example.com
```

### 배치 파일 사용
```bash
run.bat https://example.com
```

### 프로토콜 없이 사용
```bash
python scanner_cli.py example.com
```

### VirusTotal API 키와 함께 사용
```bash
python scanner_cli.py https://example.com --vt-key your_api_key_here
```

### 상세 모드
```bash
python scanner_cli.py https://example.com -v
```

## VirusTotal API 설정

### API 키 발급받기

1. [VirusTotal](https://www.virustotal.com) 방문
2. 무료 계정 가입
3. 프로필 설정으로 이동
4. API Key 섹션에서 API 키 복사

### API 키 설정 방법

**방법 1: 환경변수 (권장)**
```bash
# Windows
set VT_API_KEY=your_api_key_here

# Linux/Mac
export VT_API_KEY=your_api_key_here
```

**방법 2: 명령줄 옵션**
```bash
python scanner_cli.py https://example.com --vt-key your_api_key_here
```
