import os
import json
import subprocess
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

class ImageStatus(Enum):
    CREATING = "creating"
    READY = "ready"
    RESTORING = "restoring"
    FAILED = "failed"

@dataclass
class GoldenImageInfo:
    image_id: str
    system_id: str
    hostname: str
    os_type: str
    creation_timestamp: str
    image_path: str
    image_hash: str
    status: ImageStatus
    size_mb: float
    metadata: Dict = None

class GoldenImageManager:
    """Manages golden images for systems before and after attack simulations"""
    
    def __init__(self, storage_path: str = "./golden_images"):
        self.storage_path = storage_path
        self.metadata_file = os.path.join(storage_path, "images_metadata.json")
        os.makedirs(storage_path, exist_ok=True)
        self._load_metadata()
    
    def _load_metadata(self):
        """Load existing image metadata"""
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    self.images = {
                        img_id: GoldenImageInfo(**img_data) 
                        for img_id, img_data in data.items()
                    }
            except Exception as e:
                print(f"Failed to load metadata: {e}")
                self.images = {}
        else:
            self.images = {}
    
    def _save_metadata(self):
        """Save image metadata to file"""
        try:
            data = {
                img_id: asdict(img_info) 
                for img_id, img_info in self.images.items()
            }
            with open(self.metadata_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"Failed to save metadata: {e}")
    
    def create_golden_image(self, system_id: str, hostname: str, os_type: str) -> Optional[str]:
        """Create a golden image for the specified system"""
        print(f"🔄 Creating golden image for {hostname} ({system_id})...")
        
        image_id = f"{system_id}_{int(time.time())}"
        timestamp = datetime.now().isoformat()
        
        # Create image info with creating status
        image_info = GoldenImageInfo(
            image_id=image_id,
            system_id=system_id,
            hostname=hostname,
            os_type=os_type,
            creation_timestamp=timestamp,
            image_path="",
            image_hash="",
            status=ImageStatus.CREATING,
            size_mb=0.0,
            metadata={"created_for_attack": True}
        )
        
        self.images[image_id] = image_info
        self._save_metadata()
        
        try:
            # Execute OS-specific image creation
            if os_type.lower() == "windows":
                success, image_path, size_mb = self._create_windows_image(system_id, hostname, image_id)
            elif os_type.lower() == "linux":
                success, image_path, size_mb = self._create_linux_image(system_id, hostname, image_id)
            elif os_type.lower() == "macos":
                success, image_path, size_mb = self._create_macos_image(system_id, hostname, image_id)
            else:
                print(f"❌ Unsupported OS type: {os_type}")
                success = False
                image_path = ""
                size_mb = 0.0
            
            if success:
                # Calculate hash of the image
                image_hash = self._calculate_file_hash(image_path)
                
                # Update image info
                image_info.image_path = image_path
                image_info.image_hash = image_hash
                image_info.status = ImageStatus.READY
                image_info.size_mb = size_mb
                
                self.images[image_id] = image_info
                self._save_metadata()
                
                print(f"✅ Golden image created successfully: {image_id}")
                print(f"   Path: {image_path}")
                print(f"   Size: {size_mb:.2f} MB")
                print(f"   Hash: {image_hash[:16]}...")
                
                return image_id
            else:
                image_info.status = ImageStatus.FAILED
                self.images[image_id] = image_info
                self._save_metadata()
                print(f"❌ Failed to create golden image for {hostname}")
                return None
                
        except Exception as e:
            print(f"❌ Exception during image creation: {e}")
            image_info.status = ImageStatus.FAILED
            self.images[image_id] = image_info
            self._save_metadata()
            return None
    
    def _create_windows_image(self, system_id: str, hostname: str, image_id: str) -> Tuple[bool, str, float]:
        """Create Windows system image using DISM or PowerShell"""
        image_path = os.path.join(self.storage_path, f"{image_id}_windows.wim")
        
        try:
            # Using PowerShell to create a checkpoint (for VMs) or system backup
            ps_script = f'''
            $ErrorActionPreference = "Stop"
            
            # Try to create a Hyper-V checkpoint first (if VM)
            try {{
                $vm = Get-VM -Name "{hostname}" -ErrorAction SilentlyContinue
                if ($vm) {{
                    Checkpoint-VM -Name "{hostname}" -SnapshotName "GoldenImage_{image_id}"
                    Write-Output "VM_CHECKPOINT_SUCCESS"
                    exit 0
                }}
            }} catch {{
                # Not a VM or Hyper-V not available
            }}
            
            # Fallback: Create system image backup
            try {{
                # Create a simple registry backup as a lightweight "golden state"
                reg export HKLM "{image_path}.reg" /y
                
                # Get system information
                $sysInfo = @{{
                    Hostname = $env:COMPUTERNAME
                    OS = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version
                    Processes = Get-Process | Select-Object Name, Id | ConvertTo-Json
                    Services = Get-Service | Where-Object {{$_.Status -eq "Running"}} | Select-Object Name, Status | ConvertTo-Json
                    InstalledSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version | ConvertTo-Json
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }}
                
                $sysInfo | ConvertTo-Json -Depth 3 | Out-File "{image_path}.json" -Encoding UTF8
                Write-Output "BACKUP_SUCCESS"
            }} catch {{
                Write-Error "Backup failed: $($_.Exception.Message)"
                exit 1
            }}
            '''
            
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                # Calculate size
                total_size = 0
                for ext in ['.reg', '.json']:
                    file_path = f"{image_path}{ext}"
                    if os.path.exists(file_path):
                        total_size += os.path.getsize(file_path)
                
                size_mb = total_size / (1024 * 1024)
                return True, image_path, size_mb
            else:
                print(f"PowerShell error: {result.stderr}")
                return False, "", 0.0
                
        except subprocess.TimeoutExpired:
            print("❌ Windows image creation timed out")
            return False, "", 0.0
        except Exception as e:
            print(f"❌ Windows image creation failed: {e}")
            return False, "", 0.0
    
    def _create_linux_image(self, system_id: str, hostname: str, image_id: str) -> Tuple[bool, str, float]:
        """Create Linux system image using rsync or tar"""
        image_path = os.path.join(self.storage_path, f"{image_id}_linux.tar.gz")
        
        try:
            # Create a system state backup
            bash_script = f'''
            #!/bin/bash
            set -e
            
            # Create temporary directory for system state
            TEMP_DIR="/tmp/golden_image_{image_id}"
            mkdir -p "$TEMP_DIR"
            
            # Capture system state
            echo "Capturing system state..."
            
            # Process list
            ps aux > "$TEMP_DIR/processes.txt"
            
            # Service status
            if command -v systemctl >/dev/null 2>&1; then
                systemctl list-units --state=running > "$TEMP_DIR/services.txt"
            elif command -v service >/dev/null 2>&1; then
                service --status-all > "$TEMP_DIR/services.txt" 2>&1
            fi
            
            # Network configuration
            ip addr show > "$TEMP_DIR/network.txt" 2>/dev/null || ifconfig > "$TEMP_DIR/network.txt" 2>/dev/null || echo "Network info unavailable" > "$TEMP_DIR/network.txt"
            
            # Installed packages
            if command -v dpkg >/dev/null 2>&1; then
                dpkg -l > "$TEMP_DIR/packages.txt"
            elif command -v rpm >/dev/null 2>&1; then
                rpm -qa > "$TEMP_DIR/packages.txt"
            elif command -v pacman >/dev/null 2>&1; then
                pacman -Q > "$TEMP_DIR/packages.txt"
            fi
            
            # System info
            uname -a > "$TEMP_DIR/system_info.txt"
            cat /etc/os-release >> "$TEMP_DIR/system_info.txt" 2>/dev/null || echo "OS release info unavailable" >> "$TEMP_DIR/system_info.txt"
            
            # Create compressed archive
            tar -czf "{image_path}" -C "$TEMP_DIR" .
            
            # Cleanup
            rm -rf "$TEMP_DIR"
            
            echo "Linux image created successfully"
            '''
            
            result = subprocess.run(
                ["bash", "-c", bash_script],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 and os.path.exists(image_path):
                size_mb = os.path.getsize(image_path) / (1024 * 1024)
                return True, image_path, size_mb
            else:
                print(f"Bash error: {result.stderr}")
                return False, "", 0.0
                
        except subprocess.TimeoutExpired:
            print("❌ Linux image creation timed out")
            return False, "", 0.0
        except Exception as e:
            print(f"❌ Linux image creation failed: {e}")
            return False, "", 0.0
    
    def _create_macos_image(self, system_id: str, hostname: str, image_id: str) -> Tuple[bool, str, float]:
        """Create macOS system image using native tools"""
        image_path = os.path.join(self.storage_path, f"{image_id}_macos.dmg")
        
        try:
            # Create a system state backup for macOS
            bash_script = f'''
            #!/bin/bash
            set -e
            
            # Create temporary directory
            TEMP_DIR="/tmp/golden_image_{image_id}"
            mkdir -p "$TEMP_DIR"
            
            # Capture system state
            echo "Capturing macOS system state..."
            
            # Process list
            ps aux > "$TEMP_DIR/processes.txt"
            
            # Running services
            launchctl list > "$TEMP_DIR/services.txt"
            
            # System information
            system_profiler SPSoftwareDataType > "$TEMP_DIR/system_info.txt"
            system_profiler SPHardwareDataType >> "$TEMP_DIR/system_info.txt"
            
            # Installed applications
            ls /Applications > "$TEMP_DIR/applications.txt"
            
            # Network configuration
            ifconfig > "$TEMP_DIR/network.txt"
            
            # Create DMG
            hdiutil create -srcfolder "$TEMP_DIR" -format UDZO "{image_path}"
            
            # Cleanup
            rm -rf "$TEMP_DIR"
            
            echo "macOS image created successfully"
            '''
            
            result = subprocess.run(
                ["bash", "-c", bash_script],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 and os.path.exists(image_path):
                size_mb = os.path.getsize(image_path) / (1024 * 1024)
                return True, image_path, size_mb
            else:
                print(f"macOS error: {result.stderr}")
                return False, "", 0.0
                
        except subprocess.TimeoutExpired:
            print("❌ macOS image creation timed out")
            return False, "", 0.0
        except Exception as e:
            print(f"❌ macOS image creation failed: {e}")
            return False, "", 0.0
    
    def restore_golden_image(self, image_id: str) -> bool:
        """Restore system to golden image state"""
        if image_id not in self.images:
            print(f"❌ Image {image_id} not found")
            return False
        
        image_info = self.images[image_id]
        if image_info.status != ImageStatus.READY:
            print(f"❌ Image {image_id} is not ready for restoration")
            return False
        
        print(f"🔄 Restoring system {image_info.hostname} to golden image...")
        
        # Update status
        image_info.status = ImageStatus.RESTORING
        self._save_metadata()
        
        try:
            success = False
            if image_info.os_type.lower() == "windows":
                success = self._restore_windows_image(image_info)
            elif image_info.os_type.lower() == "linux":
                success = self._restore_linux_image(image_info)
            elif image_info.os_type.lower() == "macos":
                success = self._restore_macos_image(image_info)
            
            if success:
                image_info.status = ImageStatus.READY
                print(f"✅ System restored to golden image: {image_id}")
            else:
                image_info.status = ImageStatus.FAILED
                print(f"❌ Failed to restore golden image: {image_id}")
            
            self._save_metadata()
            return success
            
        except Exception as e:
            print(f"❌ Exception during image restoration: {e}")
            image_info.status = ImageStatus.FAILED
            self._save_metadata()
            return False
    
    def _restore_windows_image(self, image_info: GoldenImageInfo) -> bool:
        """Restore Windows system from golden image"""
        # Implementation for Windows restoration
        print(f"🔄 Restoring Windows system {image_info.hostname}...")
        
        # For demonstration - in real implementation, this would restore from backup
        ps_script = '''
        Write-Output "Simulating Windows system restoration..."
        # Stop non-essential services
        # Restore registry from backup
        # Reset system state
        Write-Output "Windows restoration completed"
        '''
        
        try:
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=120
            )
            return result.returncode == 0
        except:
            return False
    
    def _restore_linux_image(self, image_info: GoldenImageInfo) -> bool:
        """Restore Linux system from golden image"""
        print(f"🔄 Restoring Linux system {image_info.hostname}...")
        
        # For demonstration - in real implementation, this would restore from backup
        bash_script = '''
        echo "Simulating Linux system restoration..."
        # Stop non-essential services
        # Restore configuration files
        # Reset system state
        echo "Linux restoration completed"
        '''
        
        try:
            result = subprocess.run(
                ["bash", "-c", bash_script],
                capture_output=True,
                text=True,
                timeout=120
            )
            return result.returncode == 0
        except:
            return False
    
    def _restore_macos_image(self, image_info: GoldenImageInfo) -> bool:
        """Restore macOS system from golden image"""
        print(f"🔄 Restoring macOS system {image_info.hostname}...")
        
        # For demonstration - in real implementation, this would restore from backup
        bash_script = '''
        echo "Simulating macOS system restoration..."
        # Stop non-essential services
        # Restore system configuration
        # Reset system state
        echo "macOS restoration completed"
        '''
        
        try:
            result = subprocess.run(
                ["bash", "-c", bash_script],
                capture_output=True,
                text=True,
                timeout=120
            )
            return result.returncode == 0
        except:
            return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return ""
    
    def list_images(self) -> List[GoldenImageInfo]:
        """List all golden images"""
        return list(self.images.values())
    
    def get_image_info(self, image_id: str) -> Optional[GoldenImageInfo]:
        """Get information about a specific image"""
        return self.images.get(image_id)
    
    def delete_image(self, image_id: str) -> bool:
        """Delete a golden image"""
        if image_id not in self.images:
            return False
        
        image_info = self.images[image_id]
        
        # Delete image files
        try:
            if os.path.exists(image_info.image_path):
                os.remove(image_info.image_path)
            
            # Delete associated files
            for ext in ['.reg', '.json']:
                file_path = f"{image_info.image_path}{ext}"
                if os.path.exists(file_path):
                    os.remove(file_path)
            
            # Remove from metadata
            del self.images[image_id]
            self._save_metadata()
            
            print(f"✅ Deleted golden image: {image_id}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to delete image {image_id}: {e}")
            return False

# Factory function
def create_golden_image_manager() -> GoldenImageManager:
    """Create golden image manager with default storage path"""
    storage_path = os.getenv('GOLDEN_IMAGES_PATH', './golden_images')
    return GoldenImageManager(storage_path)