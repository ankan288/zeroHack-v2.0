#!/usr/bin/env python3
"""
zeroHack Notification System
Real-time notifications when vulnerabilities are discovered
No AI required - uses built-in system features
"""

import os
import sys
import time
import threading
from colorama import Fore, Style
try:
    import winsound  # Windows sound support
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False

try:
    from plyer import notification  # Cross-platform desktop notifications
    DESKTOP_NOTIFICATIONS = True
except ImportError:
    DESKTOP_NOTIFICATIONS = False

try:
    import smtplib
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
    EMAIL_AVAILABLE = True
except ImportError:
    EMAIL_AVAILABLE = False

class NotificationManager:
    def __init__(self, enable_desktop=True, enable_audio=True, enable_email=False):
        self.enable_desktop = enable_desktop and DESKTOP_NOTIFICATIONS
        self.enable_audio = enable_audio and AUDIO_AVAILABLE
        self.enable_email = enable_email
        self.vulnerability_count = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        self.email_config = None
        self.last_notification_time = 0
        self.notification_cooldown = 2  # Seconds between notifications to avoid spam
        
        # Sound frequencies for different severity levels (Hz)
        self.sound_frequencies = {
            'Critical': 1000,  # High pitch for critical
            'High': 800,       # Medium-high pitch
            'Medium': 600,     # Medium pitch
            'Low': 400         # Lower pitch
        }
        
        print(f"{Fore.CYAN}[+] Notification system initialized:")
        print(f"    Desktop notifications: {'✓' if self.enable_desktop else '✗'}")
        print(f"    Audio alerts: {'✓' if self.enable_audio else '✗'}")
        print(f"    Email notifications: {'✓' if self.enable_email else '✗'}{Style.RESET_ALL}")
    
    def setup_email_notifications(self, smtp_server, smtp_port, username, password, recipient):
        """Setup email notification configuration"""
        self.email_config = {
            'smtp_server': smtp_server,
            'smtp_port': smtp_port,
            'username': username,
            'password': password,
            'recipient': recipient
        }
        self.enable_email = True
        print(f"{Fore.GREEN}[+] Email notifications configured for {recipient}{Style.RESET_ALL}")
    
    def play_alert_sound(self, severity='Medium'):
        """Play system sound alert based on severity"""
        if not self.enable_audio:
            return
            
        try:
            if sys.platform == 'win32' and AUDIO_AVAILABLE:
                # Windows beep with different frequencies
                frequency = self.sound_frequencies.get(severity, 600)
                duration = 500 if severity == 'Critical' else 200  # ms
                
                # Play sound in separate thread to avoid blocking
                def play_sound():
                    try:
                        winsound.Beep(frequency, duration)
                        if severity == 'Critical':
                            time.sleep(0.1)
                            winsound.Beep(frequency, duration)  # Double beep for critical
                    except:
                        pass
                
                sound_thread = threading.Thread(target=play_sound, daemon=True)
                sound_thread.start()
            
            elif sys.platform in ['linux', 'darwin']:
                # Unix-like systems - use system bell
                os.system('echo -e "\\a"')
                
        except Exception as e:
            pass  # Fail silently if sound not available
    
    def show_desktop_notification(self, title, message, severity='Medium'):
        """Show desktop notification"""
        if not self.enable_desktop:
            return
            
        try:
            # Set icon and urgency based on severity
            if severity == 'Critical':
                icon_path = 'critical'
                timeout = 15
            elif severity == 'High':
                icon_path = 'important'
                timeout = 10
            else:
                icon_path = 'info'
                timeout = 5
            
            # Show notification in separate thread
            def show_notification():
                try:
                    notification.notify(
                        title=f"🔒 zeroHack - {severity} Vulnerability",
                        message=message,
                        timeout=timeout,
                        app_name="zeroHack Security Scanner",
                        app_icon=None  # Use default icon
                    )
                except Exception:
                    pass
            
            notification_thread = threading.Thread(target=show_notification, daemon=True)
            notification_thread.start()
            
        except Exception:
            pass  # Fail silently if notifications not available
    
    def send_email_alert(self, vulnerability_details):
        """Send email notification for critical vulnerabilities"""
        if not self.enable_email or not self.email_config or not EMAIL_AVAILABLE:
            return
            
        try:
            # Only send email for Critical and High severity
            if vulnerability_details.get('severity') not in ['Critical', 'High']:
                return
            
            def send_email():
                try:
                    msg = MimeMultipart()
                    msg['From'] = self.email_config['username']
                    msg['To'] = self.email_config['recipient']
                    msg['Subject'] = f"🚨 zeroHack Alert: {vulnerability_details.get('severity')} Vulnerability Found"
                    
                    body = f"""
                    zeroHack Security Scanner has discovered a {vulnerability_details.get('severity')} vulnerability:
                    
                    Type: {vulnerability_details.get('type', 'Unknown')}
                    URL: {vulnerability_details.get('url', 'Unknown')}
                    Parameter: {vulnerability_details.get('parameter', 'N/A')}
                    Evidence: {vulnerability_details.get('evidence', 'N/A')}
                    
                    Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
                    
                    Please investigate immediately.
                    
                    -- zeroHack Security Scanner
                    """
                    
                    msg.attach(MimeText(body, 'plain'))
                    
                    server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
                    server.starttls()
                    server.login(self.email_config['username'], self.email_config['password'])
                    text = msg.as_string()
                    server.sendmail(self.email_config['username'], self.email_config['recipient'], text)
                    server.quit()
                    
                    print(f"{Fore.GREEN}[+] Email alert sent for {vulnerability_details.get('severity')} vulnerability{Style.RESET_ALL}")
                    
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Email notification failed: {str(e)}{Style.RESET_ALL}")
            
            email_thread = threading.Thread(target=send_email, daemon=True)
            email_thread.start()
            
        except Exception:
            pass
    
    def notify_vulnerability_found(self, vulnerability_details):
        """Main notification function - called when vulnerability is discovered"""
        current_time = time.time()
        
        # Prevent notification spam
        if current_time - self.last_notification_time < self.notification_cooldown:
            return
        
        severity = vulnerability_details.get('severity', 'Medium')
        vuln_type = vulnerability_details.get('type', 'Unknown Vulnerability')
        url = vulnerability_details.get('url', 'Unknown URL')
        
        # Update counter
        if severity in self.vulnerability_count:
            self.vulnerability_count[severity] += 1
        
        # Create notification message
        message = f"{vuln_type} found on {url[:50]}{'...' if len(url) > 50 else ''}"
        
        # Enhanced terminal notification with progress
        severity_colors = {
            'Critical': Fore.RED,
            'High': Fore.MAGENTA,
            'Medium': Fore.YELLOW,
            'Low': Fore.CYAN
        }
        
        color = severity_colors.get(severity, Fore.WHITE)
        total_vulns = sum(self.vulnerability_count.values())
        
        print(f"\n{color}{'='*80}")
        print(f"🚨 VULNERABILITY DETECTED #{total_vulns} 🚨")
        print(f"Severity: {severity}")
        print(f"Type: {vuln_type}")
        print(f"Target: {url}")
        if vulnerability_details.get('parameter'):
            print(f"Parameter: {vulnerability_details['parameter']}")
        print(f"{'='*80}{Style.RESET_ALL}\n")
        
        # Show vulnerability counter
        self.show_vulnerability_counter()
        
        # Desktop notification
        self.show_desktop_notification(
            f"{severity} Vulnerability Found",
            message,
            severity
        )
        
        # Audio alert
        self.play_alert_sound(severity)
        
        # Email alert for critical/high vulnerabilities
        self.send_email_alert(vulnerability_details)
        
        self.last_notification_time = current_time
    
    def show_vulnerability_counter(self):
        """Display real-time vulnerability counter"""
        total = sum(self.vulnerability_count.values())
        if total == 0:
            return
            
        counter_display = f"{Fore.CYAN}[Vulnerabilities Found] "
        
        if self.vulnerability_count['Critical'] > 0:
            counter_display += f"{Fore.RED}Critical: {self.vulnerability_count['Critical']} "
        if self.vulnerability_count['High'] > 0:
            counter_display += f"{Fore.MAGENTA}High: {self.vulnerability_count['High']} "
        if self.vulnerability_count['Medium'] > 0:
            counter_display += f"{Fore.YELLOW}Medium: {self.vulnerability_count['Medium']} "
        if self.vulnerability_count['Low'] > 0:
            counter_display += f"{Fore.CYAN}Low: {self.vulnerability_count['Low']} "
            
        counter_display += f"{Fore.GREEN}Total: {total}{Style.RESET_ALL}"
        print(counter_display)
    
    def show_final_summary(self):
        """Show final vulnerability summary with notifications"""
        total = sum(self.vulnerability_count.values())
        
        if total > 0:
            print(f"\n{Fore.YELLOW}{'='*60}")
            print(f"🎯 SCAN COMPLETE - VULNERABILITIES FOUND: {total}")
            print(f"{'='*60}{Style.RESET_ALL}")
            
            # Final summary notification
            if total >= 5:
                severity = 'Critical'
                message = f"Scan complete! Found {total} vulnerabilities (High risk target)"
            elif total >= 2:
                severity = 'High' 
                message = f"Scan complete! Found {total} vulnerabilities"
            else:
                severity = 'Medium'
                message = f"Scan complete! Found {total} vulnerability(s)"
            
            self.show_desktop_notification(
                "zeroHack Scan Complete",
                message,
                severity
            )
            
            self.play_alert_sound(severity)
        else:
            print(f"\n{Fore.GREEN}✅ Scan complete - No vulnerabilities found{Style.RESET_ALL}")

# Global notification manager instance
notification_manager = None

def initialize_notifications(enable_desktop=True, enable_audio=True, enable_email=False):
    """Initialize the global notification manager"""
    global notification_manager
    notification_manager = NotificationManager(enable_desktop, enable_audio, enable_email)
    return notification_manager

def notify_vulnerability(vulnerability_details):
    """Quick function to send vulnerability notification"""
    global notification_manager
    if notification_manager:
        notification_manager.notify_vulnerability_found(vulnerability_details)

def get_notification_manager():
    """Get the global notification manager"""
    global notification_manager
    return notification_manager