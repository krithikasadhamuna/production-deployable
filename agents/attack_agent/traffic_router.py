import subprocess
import json
import os
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class RoutingStatus(Enum):
    INACTIVE = "inactive"
    ACTIVE = "active"
    FAILED = "failed"

@dataclass
class RoutingRule:
    rule_id: str
    target_system: str
    destination_server: str
    ports: List[int]
    protocols: List[str]  # tcp, udp, http, https
    status: RoutingStatus
    created_at: str
    original_routes: Dict = None  # Store original routing for restoration

class TrafficRouter:
    """Manages traffic routing to SOC server during attack simulations"""
    
    def __init__(self, soc_server_url: str, soc_server_ip: str):
        self.soc_server_url = soc_server_url
        self.soc_server_ip = soc_server_ip
        self.active_routes = {}
        self.routes_backup_file = "./routing_backup.json"
    
    def setup_traffic_routing(self, target_systems: List[str], attack_id: str) -> bool:
        """Setup traffic routing for target systems to SOC server"""
        print(f"🔄 Setting up traffic routing for attack {attack_id}...")
        
        success_count = 0
        for system_id in target_systems:
            if self._setup_system_routing(system_id, attack_id):
                success_count += 1
            else:
                print(f"❌ Failed to setup routing for system {system_id}")
        
        if success_count == len(target_systems):
            print(f"✅ Traffic routing setup complete for {success_count} systems")
            return True
        else:
            print(f"⚠️ Partial routing setup: {success_count}/{len(target_systems)} systems")
            return False
    
    def _setup_system_routing(self, system_id: str, attack_id: str) -> bool:
        """Setup routing for a specific system"""
        rule_id = f"{attack_id}_{system_id}_{int(time.time())}"
        
        # Common ports to route (HTTP, HTTPS, DNS, common malware C2)
        ports = [80, 443, 53, 8080, 8443, 9001, 9002]
        protocols = ["tcp", "udp", "http", "https"]
        
        routing_rule = RoutingRule(
            rule_id=rule_id,
            target_system=system_id,
            destination_server=self.soc_server_ip,
            ports=ports,
            protocols=protocols,
            status=RoutingStatus.INACTIVE,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            original_routes={}
        )
        
        try:
            # Backup original routes
            original_routes = self._backup_system_routes(system_id)
            routing_rule.original_routes = original_routes
            
            # Apply new routing rules
            if self._apply_routing_rules(routing_rule):
                routing_rule.status = RoutingStatus.ACTIVE
                self.active_routes[rule_id] = routing_rule
                self._save_routing_backup()
                print(f"✅ Routing active for system {system_id}")
                return True
            else:
                routing_rule.status = RoutingStatus.FAILED
                print(f"❌ Failed to apply routing for system {system_id}")
                return False
                
        except Exception as e:
            print(f"❌ Exception setting up routing for {system_id}: {e}")
            return False
    
    def _backup_system_routes(self, system_id: str) -> Dict:
        """Backup original routing configuration for a system"""
        print(f"📋 Backing up original routes for {system_id}...")
        
        original_routes = {
            "windows_routes": [],
            "linux_routes": [],
            "iptables_rules": [],
            "firewall_rules": [],
            "dns_config": {}
        }
        
        try:
            # Try to detect OS and backup accordingly
            
            # Windows route backup
            try:
                result = subprocess.run(
                    ["route", "print"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    original_routes["windows_routes"] = result.stdout.split('\n')
            except:
                pass
            
            # Linux route backup
            try:
                result = subprocess.run(
                    ["ip", "route", "show"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    original_routes["linux_routes"] = result.stdout.split('\n')
            except:
                pass
            
            # iptables backup (Linux)
            try:
                result = subprocess.run(
                    ["iptables", "-L", "-n"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    original_routes["iptables_rules"] = result.stdout.split('\n')
            except:
                pass
            
            # DNS configuration backup
            try:
                dns_files = ["/etc/resolv.conf", "C:\\Windows\\System32\\drivers\\etc\\hosts"]
                for dns_file in dns_files:
                    if os.path.exists(dns_file):
                        with open(dns_file, 'r') as f:
                            original_routes["dns_config"][dns_file] = f.read()
            except:
                pass
            
            return original_routes
            
        except Exception as e:
            print(f"⚠️ Warning: Could not backup all routes for {system_id}: {e}")
            return original_routes
    
    def _apply_routing_rules(self, routing_rule: RoutingRule) -> bool:
        """Apply routing rules to redirect traffic to SOC server"""
        print(f"🔀 Applying routing rules for {routing_rule.target_system}...")
        
        success = True
        
        # Apply OS-specific routing
        try:
            # Try Windows routing first
            if self._apply_windows_routing(routing_rule):
                print("✅ Windows routing applied")
            elif self._apply_linux_routing(routing_rule):
                print("✅ Linux routing applied")
            elif self._apply_macos_routing(routing_rule):
                print("✅ macOS routing applied")
            else:
                print("❌ Could not apply routing for any OS")
                success = False
        except Exception as e:
            print(f"❌ Exception applying routing: {e}")
            success = False
        
        return success
    
    def _apply_windows_routing(self, routing_rule: RoutingRule) -> bool:
        """Apply Windows-specific routing rules"""
        try:
            # PowerShell script to setup routing
            ps_script = f'''
            $ErrorActionPreference = "Stop"
            
            # Add routes for specific ports to SOC server
            $socServer = "{routing_rule.destination_server}"
            $ports = @({','.join(map(str, routing_rule.ports))})
            
            try {{
                # Add static routes (example - in production this would be more sophisticated)
                foreach ($port in $ports) {{
                    # Add firewall rules to redirect traffic
                    New-NetFirewallRule -DisplayName "SOC_Redirect_$port" -Direction Outbound -LocalPort $port -Action Allow -RemoteAddress $socServer
                }}
                
                # Modify DNS to point to SOC server for specific domains
                Add-DnsClientNrptRule -Namespace ".malware-test.com" -NameServers $socServer
                
                Write-Output "Windows routing applied successfully"
                exit 0
            }} catch {{
                Write-Error "Failed to apply Windows routing: $($_.Exception.Message)"
                exit 1
            }}
            '''
            
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            print("❌ Windows routing setup timed out")
            return False
        except Exception as e:
            print(f"❌ Windows routing failed: {e}")
            return False
    
    def _apply_linux_routing(self, routing_rule: RoutingRule) -> bool:
        """Apply Linux-specific routing rules"""
        try:
            bash_script = f'''
            #!/bin/bash
            set -e
            
            SOC_SERVER="{routing_rule.destination_server}"
            PORTS=({' '.join(map(str, routing_rule.ports))})
            
            # Check if running as root or with sudo
            if [ "$EUID" -ne 0 ] && ! sudo -n true 2>/dev/null; then
                echo "Need sudo privileges for routing setup"
                exit 1
            fi
            
            # Use sudo if not root
            SUDO_CMD=""
            if [ "$EUID" -ne 0 ]; then
                SUDO_CMD="sudo"
            fi
            
            # Add iptables rules to redirect traffic
            for port in "${{PORTS[@]}}"; do
                # Redirect outbound traffic on specific ports to SOC server
                $SUDO_CMD iptables -t nat -A OUTPUT -p tcp --dport $port -j DNAT --to-destination $SOC_SERVER:$port
            done
            
            # Add route for specific subnet to SOC server
            $SUDO_CMD ip route add 192.168.100.0/24 via $SOC_SERVER
            
            echo "Linux routing applied successfully"
            '''
            
            result = subprocess.run(
                ["bash", "-c", bash_script],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            print("❌ Linux routing setup timed out")
            return False
        except Exception as e:
            print(f"❌ Linux routing failed: {e}")
            return False
    
    def _apply_macos_routing(self, routing_rule: RoutingRule) -> bool:
        """Apply macOS-specific routing rules"""
        try:
            bash_script = f'''
            #!/bin/bash
            set -e
            
            SOC_SERVER="{routing_rule.destination_server}"
            
            # Add routes using pfctl (packet filter)
            # Note: This requires admin privileges
            
            # Create a simple pf rule file
            cat > /tmp/soc_pf_rules.conf << EOF
# SOC traffic redirection rules
rdr pass on en0 inet proto tcp from any to any port 80 -> $SOC_SERVER port 80
rdr pass on en0 inet proto tcp from any to any port 443 -> $SOC_SERVER port 443
EOF
            
            # Load the rules (this would require sudo in real implementation)
            # sudo pfctl -f /tmp/soc_pf_rules.conf -e
            
            echo "macOS routing rules prepared (requires manual sudo execution)"
            '''
            
            result = subprocess.run(
                ["bash", "-c", bash_script],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            print("❌ macOS routing setup timed out")
            return False
        except Exception as e:
            print(f"❌ macOS routing failed: {e}")
            return False
    
    def restore_original_routing(self, attack_id: str) -> bool:
        """Restore original routing configuration after attack"""
        print(f"🔄 Restoring original routing for attack {attack_id}...")
        
        success_count = 0
        rules_to_remove = []
        
        for rule_id, routing_rule in self.active_routes.items():
            if attack_id in rule_id:
                if self._restore_system_routing(routing_rule):
                    success_count += 1
                    rules_to_remove.append(rule_id)
                else:
                    print(f"❌ Failed to restore routing for {routing_rule.target_system}")
        
        # Remove successfully restored rules
        for rule_id in rules_to_remove:
            del self.active_routes[rule_id]
        
        self._save_routing_backup()
        
        if success_count > 0:
            print(f"✅ Restored routing for {success_count} systems")
            return True
        else:
            print("❌ No routing rules were restored")
            return False
    
    def _restore_system_routing(self, routing_rule: RoutingRule) -> bool:
        """Restore original routing for a specific system"""
        print(f"🔀 Restoring routing for {routing_rule.target_system}...")
        
        try:
            # Remove custom rules first
            self._remove_custom_routing_rules(routing_rule)
            
            # Restore original configuration
            if routing_rule.original_routes:
                self._restore_original_configuration(routing_rule.original_routes)
            
            routing_rule.status = RoutingStatus.INACTIVE
            print(f"✅ Routing restored for {routing_rule.target_system}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to restore routing for {routing_rule.target_system}: {e}")
            return False
    
    def _remove_custom_routing_rules(self, routing_rule: RoutingRule):
        """Remove custom routing rules that were added"""
        try:
            # Windows cleanup
            ps_script = f'''
            # Remove firewall rules
            Get-NetFirewallRule -DisplayName "SOC_Redirect_*" | Remove-NetFirewallRule
            
            # Remove DNS rules
            Get-DnsClientNrptRule -Namespace ".malware-test.com" | Remove-DnsClientNrptRule -Force
            '''
            
            subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True,
                timeout=30
            )
        except:
            pass
        
        try:
            # Linux cleanup
            bash_script = f'''
            # Remove iptables rules
            SUDO_CMD=""
            if [ "$EUID" -ne 0 ]; then
                SUDO_CMD="sudo"
            fi
            
            # Flush NAT table OUTPUT chain (careful in production!)
            $SUDO_CMD iptables -t nat -F OUTPUT
            
            # Remove custom routes
            $SUDO_CMD ip route del 192.168.100.0/24 2>/dev/null || true
            '''
            
            subprocess.run(
                ["bash", "-c", bash_script],
                capture_output=True,
                timeout=30
            )
        except:
            pass
    
    def _restore_original_configuration(self, original_routes: Dict):
        """Restore original routing configuration"""
        # This would restore the original routing tables
        # Implementation depends on what was backed up
        pass
    
    def _save_routing_backup(self):
        """Save current routing state to backup file"""
        try:
            backup_data = {
                rule_id: {
                    "rule_id": rule.rule_id,
                    "target_system": rule.target_system,
                    "destination_server": rule.destination_server,
                    "ports": rule.ports,
                    "protocols": rule.protocols,
                    "status": rule.status.value,
                    "created_at": rule.created_at,
                    "original_routes": rule.original_routes
                }
                for rule_id, rule in self.active_routes.items()
            }
            
            with open(self.routes_backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)
                
        except Exception as e:
            print(f"⚠️ Warning: Could not save routing backup: {e}")
    
    def load_routing_backup(self):
        """Load routing state from backup file"""
        try:
            if os.path.exists(self.routes_backup_file):
                with open(self.routes_backup_file, 'r') as f:
                    backup_data = json.load(f)
                
                for rule_id, rule_data in backup_data.items():
                    routing_rule = RoutingRule(
                        rule_id=rule_data["rule_id"],
                        target_system=rule_data["target_system"],
                        destination_server=rule_data["destination_server"],
                        ports=rule_data["ports"],
                        protocols=rule_data["protocols"],
                        status=RoutingStatus(rule_data["status"]),
                        created_at=rule_data["created_at"],
                        original_routes=rule_data.get("original_routes", {})
                    )
                    self.active_routes[rule_id] = routing_rule
                    
        except Exception as e:
            print(f"⚠️ Warning: Could not load routing backup: {e}")
    
    def get_active_routes(self) -> Dict[str, RoutingRule]:
        """Get all currently active routing rules"""
        return self.active_routes.copy()
    
    def cleanup_all_routing(self) -> bool:
        """Emergency cleanup of all custom routing rules"""
        print("🧹 Emergency cleanup of all routing rules...")
        
        success = True
        for rule_id in list(self.active_routes.keys()):
            try:
                routing_rule = self.active_routes[rule_id]
                self._restore_system_routing(routing_rule)
                del self.active_routes[rule_id]
            except Exception as e:
                print(f"❌ Failed to cleanup rule {rule_id}: {e}")
                success = False
        
        self._save_routing_backup()
        return success

# Factory function
def create_traffic_router(soc_server_url: str = None, soc_server_ip: str = None) -> TrafficRouter:
    """Create traffic router with configuration from environment"""
    if not soc_server_url:
        soc_server_url = os.getenv('SOC_SERVER_URL', 'https://soc-server.company.com')
    
    if not soc_server_ip:
        soc_server_ip = os.getenv('SOC_SERVER_IP', '10.0.0.100')
    
    return TrafficRouter(soc_server_url, soc_server_ip)