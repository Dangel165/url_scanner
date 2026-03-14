#!/usr/bin/env python3
import sys
import socket
import ssl
import dns.resolver
import requests
from urllib.parse import urlparse
from datetime import datetime
import re
from colorama import init, Fore, Back, Style
import argparse
import os

# Colorama 초기화
init(autoreset=True)

class URLSecurityScanner:
    def __init__(self, virustotal_api_key=None):
        self.results = {}
        self.vt_api_key = virustotal_api_key or os.environ.get('VT_API_KEY')
    
    def print_banner(self):
        """배너 출력"""
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           {Fore.YELLOW}URL 스캐너 v2.0{Fore.CYAN}                       ║
║          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def print_section(self, title):
        """섹션 제목 출력"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] {title}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    def print_result(self, key, value, status="info"):
        """결과 출력"""
        colors = {
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "info": Fore.WHITE
        }
        color = colors.get(status, Fore.WHITE)
        print(f"{color}  {key}: {value}{Style.RESET_ALL}")
    
    def scan_url(self, url):
        """URL 종합 보안 분석"""
        self.print_banner()
        print(f"{Fore.WHITE}검사 대상 URL: {Fore.CYAN}{url}{Style.RESET_ALL}\n")
        
        self.results = {
            'url': url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'risk_score': 0,
            'risk_level': 'SAFE',
            'checks': {}
        }
        
        # 각 검사 수행
        self.check_url_structure(url)
        self.check_dns(url)
        self.check_ssl(url)
        self.check_malicious_patterns(url)
        self.check_cloudflare_dns(url)
        self.check_virustotal(url)  # VirusTotal 검사 추가
        
        # 위험도 계산
        self.calculate_risk_score()
        
        # 최종 결과 출력
        self.print_final_results()
        
        return self.results
    
    def check_url_structure(self, url):
        """URL 구조 분석"""
        self.print_section("URL 구조 분석")
        
        try:
            parsed = urlparse(url)
            
            has_https = parsed.scheme == 'https'
            is_ip = self.is_ip_address(parsed.netloc)
            suspicious_tld = self.check_suspicious_tld(parsed.netloc)
            url_length = len(url)
            subdomain_count = parsed.netloc.count('.')
            
            # 결과 출력
            self.print_result("프로토콜", parsed.scheme.upper(), "success" if has_https else "warning")
            self.print_result("도메인", parsed.netloc, "info")
            self.print_result("경로", parsed.path if parsed.path else "/", "info")
            self.print_result("URL 길이", url_length, "warning" if url_length > 100 else "info")
            self.print_result("서브도메인 개수", subdomain_count, "warning" if subdomain_count > 3 else "info")
            
            if is_ip:
                self.print_result("IP 주소", "직접 IP 사용 감지됨", "warning")
            
            if suspicious_tld:
                self.print_result("TLD", "의심스러운 TLD 감지됨", "warning")
            
            # 위험도 계산
            risk = 0
            if not has_https:
                risk += 30
            if is_ip:
                risk += 25
            if suspicious_tld:
                risk += 20
            if url_length > 100:
                risk += 15
            if subdomain_count > 3:
                risk += 10
            
            self.results['checks']['url_structure'] = {
                'status': 'completed',
                'risk': min(risk, 100)
            }
            
            print(f"\n{Fore.YELLOW}  Risk Score: {risk}/100{Style.RESET_ALL}")
            
        except Exception as e:
            self.print_result("Error", str(e), "error")
            self.results['checks']['url_structure'] = {
                'status': 'error',
                'risk': 50
            }
    
    def check_dns(self, url):
        """DNS 레코드 검사"""
        self.print_section("DNS 레코드 검사")
        
        try:
            domain = urlparse(url).netloc.split(':')[0]  # 포트 제거
            
            # A 레코드
            try:
                answers = dns.resolver.resolve(domain, 'A')
                a_records = [str(rdata) for rdata in answers]
                self.print_result("A 레코드", ", ".join(a_records), "success")
            except Exception as e:
                self.print_result("A 레코드", f"찾을 수 없음 ({str(e)})", "warning")
                a_records = []
            
            # MX 레코드
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                mx_records = [str(rdata) for rdata in answers]
                self.print_result("MX 레코드", f"{len(mx_records)}개 발견", "info")
            except:
                self.print_result("MX 레코드", "찾을 수 없음", "info")
            
            risk = 0 if len(a_records) > 0 else 30
            
            self.results['checks']['dns'] = {
                'status': 'completed',
                'risk': risk
            }
            
            print(f"\n{Fore.YELLOW}  위험도 점수: {risk}/100{Style.RESET_ALL}")
            
        except Exception as e:
            self.print_result("오류", str(e), "error")
            self.results['checks']['dns'] = {
                'status': 'error',
                'risk': 20
            }
    
    def check_ssl(self, url):
        """SSL/TLS 인증서 검사"""
        self.print_section("SSL/TLS 인증서 검사")
        
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                self.print_result("상태", "HTTPS 아님 - SSL 검사 건너뜀", "warning")
                self.results['checks']['ssl'] = {
                    'status': 'no_https',
                    'risk': 40
                }
                print(f"\n{Fore.YELLOW}  위험도 점수: 40/100{Style.RESET_ALL}")
                return
            
            domain = parsed.netloc.split(':')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # 인증서 정보
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    self.print_result("발급자", issuer.get('organizationName', '알 수 없음'), "info")
                    self.print_result("주체", subject.get('commonName', '알 수 없음'), "info")
                    self.print_result("만료일", cert['notAfter'], "info")
                    self.print_result("만료까지 남은 일수", days_until_expiry, 
                                    "success" if days_until_expiry > 30 else "warning")
                    
                    risk = 0 if days_until_expiry > 30 else 20
                    
                    self.results['checks']['ssl'] = {
                        'status': 'completed',
                        'risk': risk
                    }
                    
                    print(f"\n{Fore.YELLOW}  위험도 점수: {risk}/100{Style.RESET_ALL}")
                    
        except Exception as e:
            self.print_result("오류", str(e), "error")
            self.results['checks']['ssl'] = {
                'status': 'error',
                'risk': 35
            }
            print(f"\n{Fore.YELLOW}  위험도 점수: 35/100{Style.RESET_ALL}")
    
    def check_malicious_patterns(self, url):
        """악성 패턴 검사"""
        self.print_section("악성 패턴 탐지")
        
        # 피싱 관련 키워드
        phishing_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'banking', 'paypal', 'amazon', 'microsoft', 'apple',
            'password', 'credential', 'confirm', 'suspended'
        ]
        
        # 도박/불법 사이트 키워드 (한글 + 영문)
        gambling_keywords = [
            'casino', 'bet', 'betting', 'poker', 'slot', 'jackpot',
            'gamble', 'gambling', 'baccarat', 'roulette', 'blackjack',
            '카지노', '바카라', '슬롯', '토토', '배팅', '베팅',
            '먹튀', '사설', '도박', '포커', '홀덤', '룰렛',
            'toto', 'sports-bet', 'sportsbet', 'livecasino', 'live-casino'
        ]
        
        # 성인/불법 콘텐츠 키워드
        adult_keywords = [
            'porn', 'xxx', 'adult', 'sex', '야동', '성인', '19금',
            'escort', 'webcam', 'live-cam'
        ]
        
        url_lower = url.lower()
        domain = urlparse(url).netloc.lower()
        
        # 각 카테고리별 검사
        found_phishing = [kw for kw in phishing_keywords if kw in url_lower]
        found_gambling = [kw for kw in gambling_keywords if kw in url_lower or kw in domain]
        found_adult = [kw for kw in adult_keywords if kw in url_lower or kw in domain]
        
        risk = 0
        
        if found_phishing:
            self.print_result("피싱 의심 키워드", ", ".join(found_phishing), "warning")
            risk += len(found_phishing) * 10
        
        if found_gambling:
            self.print_result("도박 사이트 키워드", ", ".join(found_gambling), "error")
            risk += 60  # 도박 사이트는 높은 위험도
            
        if found_adult:
            self.print_result("성인 콘텐츠 키워드", ", ".join(found_adult), "error")
            risk += 50
        
        if not found_phishing and not found_gambling and not found_adult:
            self.print_result("의심 키워드", "감지되지 않음", "success")
        
        # IP 주소 패턴
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            self.print_result("IP 패턴", "직접 IP 주소 감지됨", "warning")
            risk += 15
        
        risk = min(risk, 100)
        
        self.results['checks']['malicious_patterns'] = {
            'status': 'completed',
            'risk': risk,
            'gambling_detected': len(found_gambling) > 0,
            'adult_detected': len(found_adult) > 0
        }
        
        print(f"\n{Fore.YELLOW}  위험도 점수: {risk}/100{Style.RESET_ALL}")
    
    def check_cloudflare_dns(self, url):
        """Cloudflare DNS 필터링 체크"""
        self.print_section("Cloudflare DNS 필터링 검사")
        
        try:
            domain = urlparse(url).netloc.split(':')[0]
            
            # Cloudflare Malware Blocking DNS
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['1.1.1.2', '1.0.0.2']
            
            try:
                answers = resolver.resolve(domain, 'A')
                blocked = False
                
                for rdata in answers:
                    if str(rdata) in ['0.0.0.0', '127.0.0.1']:
                        blocked = True
                        break
                
                if blocked:
                    self.print_result("Cloudflare 상태", "차단됨 - 악성 사이트 감지!", "error")
                    risk = 80
                else:
                    self.print_result("Cloudflare 상태", "통과 - 차단되지 않음", "success")
                    risk = 0
                
                self.results['checks']['cloudflare_dns'] = {
                    'status': 'completed',
                    'risk': risk
                }
                
                print(f"\n{Fore.YELLOW}  위험도 점수: {risk}/100{Style.RESET_ALL}")
                
            except dns.resolver.NXDOMAIN:
                self.print_result("Cloudflare 상태", "도메인이 존재하지 않거나 차단됨", "error")
                self.results['checks']['cloudflare_dns'] = {
                    'status': 'completed',
                    'risk': 70
                }
                print(f"\n{Fore.YELLOW}  위험도 점수: 70/100{Style.RESET_ALL}")
                
        except Exception as e:
            self.print_result("오류", str(e), "error")
            self.results['checks']['cloudflare_dns'] = {
                'status': 'error',
                'risk': 10
            }
            print(f"\n{Fore.YELLOW}  위험도 점수: 10/100{Style.RESET_ALL}")
    
    def check_virustotal(self, url):
        """VirusTotal API를 사용한 URL 검사"""
        self.print_section("VirusTotal 검사")
        
        if not self.vt_api_key:
            self.print_result("상태", "API 키 없음 - 검사 건너뜀", "warning")
            self.print_result("안내", "VT_API_KEY 환경변수 설정 또는 --vt-key 옵션 사용", "info")
            self.results['checks']['virustotal'] = {
                'status': 'skipped',
                'risk': 0
            }
            return
        
        try:
            import base64
            
            # URL을 base64로 인코딩 (VirusTotal API 요구사항)
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {
                "x-apikey": self.vt_api_key
            }
            
            # VirusTotal API v3 엔드포인트
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            response = requests.get(vt_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                self.print_result("검사 엔진 수", f"{total}개", "info")
                self.print_result("악성 탐지", f"{malicious}개", "error" if malicious > 0 else "success")
                self.print_result("의심 탐지", f"{suspicious}개", "warning" if suspicious > 0 else "success")
                self.print_result("안전 판정", f"{harmless}개", "success")
                
                # 위험도 계산
                if total > 0:
                    detection_rate = ((malicious + suspicious) / total) * 100
                    risk = min(int(detection_rate), 100)
                else:
                    risk = 0
                
                self.results['checks']['virustotal'] = {
                    'status': 'completed',
                    'risk': risk,
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'total': total
                }
                
                print(f"\n{Fore.YELLOW}  위험도 점수: {risk}/100{Style.RESET_ALL}")
                
            elif response.status_code == 404:
                # URL이 VirusTotal 데이터베이스에 없음 - URL 제출
                self.print_result("상태", "데이터베이스에 없음 - URL 제출 중...", "warning")
                
                submit_url = "https://www.virustotal.com/api/v3/urls"
                submit_data = {"url": url}
                submit_response = requests.post(submit_url, headers=headers, data=submit_data, timeout=10)
                
                if submit_response.status_code == 200:
                    self.print_result("제출 완료", "분석 대기 중 (나중에 다시 확인하세요)", "info")
                
                self.results['checks']['virustotal'] = {
                    'status': 'submitted',
                    'risk': 0
                }
                
            else:
                self.print_result("오류", f"API 응답 코드: {response.status_code}", "error")
                self.results['checks']['virustotal'] = {
                    'status': 'error',
                    'risk': 0
                }
                
        except Exception as e:
            self.print_result("오류", str(e), "error")
            self.results['checks']['virustotal'] = {
                'status': 'error',
                'risk': 0
            }
    
    def is_ip_address(self, domain):
        """IP 주소 여부 확인"""
        try:
            socket.inet_aton(domain.split(':')[0])
            return True
        except:
            return False
    
    def check_suspicious_tld(self, domain):
        """의심스러운 TLD 확인"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        return any(domain.endswith(tld) for tld in suspicious_tlds)
    
    def calculate_risk_score(self):
        """전체 위험도 점수 계산"""
        total_risk = 0
        count = 0
        
        for check_name, check_data in self.results['checks'].items():
            if 'risk' in check_data:
                total_risk += check_data['risk']
                count += 1
        
        if count > 0:
            self.results['risk_score'] = int(total_risk / count)
        
        # 위험 레벨 결정
        score = self.results['risk_score']
        if score < 20:
            self.results['risk_level'] = '안전'
            self.results['risk_color'] = 'green'
        elif score < 40:
            self.results['risk_level'] = '낮음'
            self.results['risk_color'] = 'cyan'
        elif score < 60:
            self.results['risk_level'] = '보통'
            self.results['risk_color'] = 'yellow'
        else:
            self.results['risk_level'] = '높음'
            self.results['risk_color'] = 'red'
    
    def print_final_results(self):
        """최종 결과 출력"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] 최종 분석 결과")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        # 위험도 표시
        score = self.results['risk_score']
        level = self.results['risk_level']
        
        if score < 20:
            color = Fore.GREEN
        elif score < 40:
            color = Fore.CYAN
        elif score < 60:
            color = Fore.YELLOW
        else:
            color = Fore.RED
        
        print(f"{color}{'█' * (score // 2)}{Fore.WHITE}{'░' * (50 - score // 2)}{Style.RESET_ALL}")
        print(f"\n{color}  위험 수준: {level}")
        print(f"  위험도 점수: {score}/100{Style.RESET_ALL}\n")
        
        # VirusTotal 특수 경고
        vt_check = self.results['checks'].get('virustotal', {})
        if vt_check.get('status') == 'completed' and vt_check.get('malicious', 0) > 0:
            print(f"{Fore.RED}{'='*60}")
            print(f"{Fore.RED}  ⚠️  VirusTotal 경고!")
            print(f"{Fore.RED}  {vt_check['malicious']}개의 보안 엔진이 악성으로 탐지했습니다.")
            print(f"{Fore.RED}  (총 {vt_check['total']}개 엔진 중)")
            print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n")
        
        # 특수 경고 메시지
        malicious_check = self.results['checks'].get('malicious_patterns', {})
        if malicious_check.get('gambling_detected'):
            print(f"{Fore.RED}{'='*60}")
            print(f"{Fore.RED}  ⚠️  도박 사이트 감지됨!")
            print(f"{Fore.RED}  이 사이트는 도박 관련 콘텐츠를 포함하고 있습니다.")
            print(f"{Fore.RED}  불법 도박은 법적 처벌 대상입니다.")
            print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n")
        
        if malicious_check.get('adult_detected'):
            print(f"{Fore.RED}{'='*60}")
            print(f"{Fore.RED}  ⚠️  성인 콘텐츠 감지됨!")
            print(f"{Fore.RED}  이 사이트는 성인 콘텐츠를 포함할 수 있습니다.")
            print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n")
        
        # 권장사항
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] 권장사항")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if vt_check.get('malicious', 0) > 5:
            print(f"{Fore.RED}  ⚠️  여러 보안 엔진이 악성으로 탐지했습니다!")
            print(f"{Fore.RED}  이 사이트는 매우 위험합니다. 절대 접속하지 마세요.{Style.RESET_ALL}")
        elif malicious_check.get('gambling_detected') or malicious_check.get('adult_detected'):
            print(f"{Fore.RED}  ⚠️  이 사이트는 불법/유해 콘텐츠를 포함하고 있습니다.")
            print(f"{Fore.RED}  접속을 강력히 권장하지 않습니다.{Style.RESET_ALL}")
        elif score >= 60:
            print(f"{Fore.RED}  ⚠️  이 사이트는 잠재적으로 위험합니다. 접속을 피하세요.{Style.RESET_ALL}")
        elif score >= 40:
            print(f"{Fore.YELLOW}  ⚠️  이 사이트 접속 시 주의하세요.{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}  ✓ 이 사이트는 안전한 것으로 보입니다.{Style.RESET_ALL}")
        
        print(f"\n{Fore.WHITE}스캔 완료 시간: {self.results['timestamp']}{Style.RESET_ALL}\n")

def main():
    parser = argparse.ArgumentParser(
        description='URL 보안 스캐너 - Cloudflare + VirusTotal + 다중 API 분석',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python scanner_cli.py https://google.com
  python scanner_cli.py http://suspicious-site.tk
  python scanner_cli.py https://example.com --vt-key YOUR_API_KEY
  
VirusTotal API 키 설정:
  1. 환경변수: set VT_API_KEY=your_api_key_here
  2. 옵션: --vt-key your_api_key_here
  
API 키 없이도 기본 검사는 가능합니다.
        """
    )
    
    parser.add_argument('url', help='검사할 URL')
    parser.add_argument('-v', '--verbose', action='store_true', help='상세 출력')
    parser.add_argument('--vt-key', help='VirusTotal API 키', default=None)
    
    args = parser.parse_args()
    
    # URL 형식 검증
    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # 스캔 실행
    scanner = URLSecurityScanner(virustotal_api_key=args.vt_key)
    try:
        scanner.scan_url(url)
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] 사용자에 의해 스캔이 중단되었습니다{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] 오류: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()
