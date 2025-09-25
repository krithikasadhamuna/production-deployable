"""
Golden Image Management Tools for Attack Agent
Handles system snapshots and restoration
"""

import os
import json
import hashlib
import shutil
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import uuid

logger = logging.getLogger(__name__)

class GoldenImageTool:
    """Tool for creating and managing golden images/snapshots"""
    
    def __init__(self, base_path: str = "golden_images", db_path: str = "soc_database.db"):
        self.base_path = base_path
        self.db_path = db_path
        self.name = "golden_image_manager"
        self.description = "Create, manage, and restore system snapshots"
        
        # Create base directory
        os.makedirs(self.base_path, exist_ok=True)
        
        # Initialize database table for golden images
        self._init_database()
    
    def _init_database(self):
        """Initialize golden images table in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS golden_images (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    image_type TEXT DEFAULT 'snapshot',
                    created_at TIMESTAMP,
                    created_by TEXT,
                    checksum TEXT,
                    size_bytes INTEGER,
                    metadata TEXT,
                    status TEXT DEFAULT 'ready',
                    restore_count INTEGER DEFAULT 0,
                    last_restored TIMESTAMP,
                    notes TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
    
    def create_golden_image(self, agent_id: str, image_type: str = "full", 
                          metadata: Dict = None) -> Dict[str, Any]:
        """
        Create a golden image for an agent
        
        Args:
            agent_id: ID of the agent to snapshot
            image_type: Type of image - 'full', 'config', 'state'
            metadata: Additional metadata to store
        
        Returns:
            Dict with image creation status and details
        """
        try:
            # Generate unique image ID
            image_id = f"golden_{agent_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            image_path = os.path.join(self.base_path, image_id)
            
            # Create image directory
            os.makedirs(image_path, exist_ok=True)
            
            # Get agent information from database
            agent_info = self._get_agent_info(agent_id)
            if not agent_info:
                return {
                    'success': False,
                    'error': f'Agent {agent_id} not found'
                }
            
            # Create snapshot metadata
            snapshot_metadata = {
                'image_id': image_id,
                'agent_id': agent_id,
                'agent_info': agent_info,
                'image_type': image_type,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'created_by': 'attack_agent',
                'platform': agent_info.get('platform', 'unknown'),
                'status': agent_info.get('status', 'unknown'),
                'custom_metadata': metadata or {}
            }
            
            # Save metadata
            metadata_file = os.path.join(image_path, 'metadata.json')
            with open(metadata_file, 'w') as f:
                json.dump(snapshot_metadata, f, indent=2)
            
            # Create checksum
            checksum = hashlib.sha256(json.dumps(snapshot_metadata).encode()).hexdigest()
            
            # In production, this would:
            # 1. Connect to hypervisor API (VMware, Hyper-V, etc.)
            # 2. Create VM snapshot
            # 3. Backup critical files
            # 4. Save registry/configuration
            # 5. Create memory dump if needed
            
            # Simulate creating snapshot files
            self._simulate_snapshot_creation(image_path, agent_info, image_type)
            
            # Calculate size (simulated)
            size_bytes = self._calculate_image_size(image_path)
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO golden_images 
                (id, agent_id, image_type, created_at, created_by, checksum, 
                 size_bytes, metadata, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                image_id,
                agent_id,
                image_type,
                snapshot_metadata['created_at'],
                'attack_agent',
                checksum,
                size_bytes,
                json.dumps(snapshot_metadata),
                'ready'
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Golden image created: {image_id}")
            
            return {
                'success': True,
                'image_id': image_id,
                'agent_id': agent_id,
                'checksum': checksum,
                'size_bytes': size_bytes,
                'path': image_path,
                'status': 'ready'
            }
            
        except Exception as e:
            logger.error(f"Failed to create golden image: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def restore_golden_image(self, agent_id: str, image_id: str = None) -> Dict[str, Any]:
        """
        Restore an agent from golden image
        
        Args:
            agent_id: ID of agent to restore
            image_id: Specific image to restore (latest if None)
        
        Returns:
            Dict with restoration status
        """
        try:
            # Get image to restore
            if not image_id:
                image_id = self._get_latest_image(agent_id)
                if not image_id:
                    return {
                        'success': False,
                        'error': f'No golden image found for {agent_id}'
                    }
            
            # Verify image exists
            image_path = os.path.join(self.base_path, image_id)
            if not os.path.exists(image_path):
                return {
                    'success': False,
                    'error': f'Image path not found: {image_path}'
                }
            
            # Load metadata
            metadata_file = os.path.join(image_path, 'metadata.json')
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Verify checksum
            current_checksum = hashlib.sha256(json.dumps(metadata).encode()).hexdigest()
            stored_checksum = self._get_stored_checksum(image_id)
            
            if current_checksum != stored_checksum:
                logger.warning(f"Checksum mismatch for {image_id}")
            
            # In production, this would:
            # 1. Stop the agent service
            # 2. Restore VM from snapshot
            # 3. Restore files and configuration
            # 4. Restore registry/system state
            # 5. Restart services
            
            # Simulate restoration
            restoration_log = self._simulate_restoration(agent_id, image_path, metadata)
            
            # Update database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE golden_images 
                SET restore_count = restore_count + 1,
                    last_restored = ?
                WHERE id = ?
            """, (datetime.now(timezone.utc).isoformat(), image_id))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Restored {agent_id} from golden image {image_id}")
            
            return {
                'success': True,
                'agent_id': agent_id,
                'image_id': image_id,
                'restored_at': datetime.now(timezone.utc).isoformat(),
                'restoration_log': restoration_log
            }
            
        except Exception as e:
            logger.error(f"Failed to restore golden image: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def verify_golden_images(self, agent_ids: List[str]) -> Dict[str, Any]:
        """
        Verify golden images exist for specified agents
        
        Args:
            agent_ids: List of agent IDs to verify
        
        Returns:
            Dict with verification status
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            verification = {
                'all_ready': True,
                'agents': {},
                'missing': [],
                'ready': [],
                'corrupted': []
            }
            
            for agent_id in agent_ids:
                cursor.execute("""
                    SELECT id, checksum, status 
                    FROM golden_images 
                    WHERE agent_id = ? AND status = 'ready'
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (agent_id,))
                
                image = cursor.fetchone()
                
                if image:
                    # Verify image integrity
                    image_id = image[0]
                    image_path = os.path.join(self.base_path, image_id)
                    
                    if os.path.exists(image_path):
                        verification['agents'][agent_id] = {
                            'has_image': True,
                            'image_id': image_id,
                            'status': 'ready'
                        }
                        verification['ready'].append(agent_id)
                    else:
                        verification['agents'][agent_id] = {
                            'has_image': False,
                            'status': 'corrupted',
                            'error': 'Image files missing'
                        }
                        verification['corrupted'].append(agent_id)
                        verification['all_ready'] = False
                else:
                    verification['agents'][agent_id] = {
                        'has_image': False,
                        'status': 'missing'
                    }
                    verification['missing'].append(agent_id)
                    verification['all_ready'] = False
            
            conn.close()
            
            return verification
            
        except Exception as e:
            logger.error(f"Verification error: {e}")
            return {
                'all_ready': False,
                'error': str(e)
            }
    
    def list_golden_images(self, agent_id: str = None) -> List[Dict]:
        """
        List golden images for an agent or all agents
        
        Args:
            agent_id: Optional agent ID filter
        
        Returns:
            List of golden images
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if agent_id:
                cursor.execute("""
                    SELECT * FROM golden_images 
                    WHERE agent_id = ?
                    ORDER BY created_at DESC
                """, (agent_id,))
            else:
                cursor.execute("""
                    SELECT * FROM golden_images 
                    ORDER BY created_at DESC
                """)
            
            images = []
            for row in cursor.fetchall():
                images.append({
                    'id': row[0],
                    'agent_id': row[1],
                    'type': row[2],
                    'created_at': row[3],
                    'checksum': row[5],
                    'size_bytes': row[6],
                    'status': row[8],
                    'restore_count': row[9],
                    'last_restored': row[10]
                })
            
            conn.close()
            return images
            
        except Exception as e:
            logger.error(f"Error listing golden images: {e}")
            return []
    
    def delete_golden_image(self, image_id: str) -> bool:
        """
        Delete a golden image
        
        Args:
            image_id: Image ID to delete
        
        Returns:
            Success boolean
        """
        try:
            # Remove from filesystem
            image_path = os.path.join(self.base_path, image_id)
            if os.path.exists(image_path):
                shutil.rmtree(image_path)
            
            # Remove from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM golden_images WHERE id = ?", (image_id,))
            conn.commit()
            conn.close()
            
            logger.info(f"Deleted golden image: {image_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete golden image: {e}")
            return False
    
    # ========== Helper Methods ==========
    
    def _get_agent_info(self, agent_id: str) -> Optional[Dict]:
        """Get agent information from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM agents WHERE id = ?
            """, (agent_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return dict(row)
            return None
            
        except Exception as e:
            logger.error(f"Error getting agent info: {e}")
            return None
    
    def _simulate_snapshot_creation(self, image_path: str, agent_info: Dict, image_type: str):
        """Simulate creating snapshot files"""
        # Create simulated snapshot files
        files_to_create = {
            'system_state.json': {
                'platform': agent_info.get('platform'),
                'hostname': agent_info.get('hostname'),
                'ip_address': agent_info.get('ip_address'),
                'snapshot_time': datetime.now(timezone.utc).isoformat()
            },
            'configuration.json': agent_info.get('configuration', {}),
            'capabilities.json': agent_info.get('capabilities', [])
        }
        
        if image_type == 'full':
            files_to_create['memory_dump.bin'] = b'SIMULATED_MEMORY_DUMP'
            files_to_create['disk_image.img'] = b'SIMULATED_DISK_IMAGE'
        
        for filename, content in files_to_create.items():
            filepath = os.path.join(image_path, filename)
            if isinstance(content, bytes):
                with open(filepath, 'wb') as f:
                    f.write(content)
            else:
                with open(filepath, 'w') as f:
                    json.dump(content, f, indent=2)
    
    def _simulate_restoration(self, agent_id: str, image_path: str, metadata: Dict) -> Dict:
        """Simulate system restoration"""
        return {
            'steps_completed': [
                'Agent service stopped',
                'System state restored',
                'Configuration applied',
                'Services restarted',
                'Verification completed'
            ],
            'restoration_time': '45 seconds',
            'status': 'success'
        }
    
    def _calculate_image_size(self, image_path: str) -> int:
        """Calculate total size of image directory"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(image_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                total_size += os.path.getsize(filepath)
        return total_size
    
    def _get_latest_image(self, agent_id: str) -> Optional[str]:
        """Get the latest golden image ID for an agent"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id FROM golden_images 
                WHERE agent_id = ? AND status = 'ready'
                ORDER BY created_at DESC
                LIMIT 1
            """, (agent_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result else None
            
        except Exception as e:
            logger.error(f"Error getting latest image: {e}")
            return None
    
    def _get_stored_checksum(self, image_id: str) -> Optional[str]:
        """Get stored checksum for an image"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT checksum FROM golden_images WHERE id = ?
            """, (image_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result else None
            
        except Exception as e:
            logger.error(f"Error getting checksum: {e}")
            return None
