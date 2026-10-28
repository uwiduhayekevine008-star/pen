"""Directory and File Discovery Scanner"""
import asyncio
import aiohttp
from typing import List, Dict, Set
from dataclasses import dataclass


@dataclass
class DiscoveredFile:
    url: str
    status: int
    size: int
    is_sensitive: bool
    risk: str


class DirectoryScanner:
    """Directory and file discovery scanner"""
    
    SENSITIVE_FILES = {
        # Configuration files
        '.env': 'HIGH', '.git/config': 'CRITICAL', '.svn/entries': 'HIGH',
        'web.config': 'HIGH', 'wp-config.php': 'CRITICAL', 'config.php': 'HIGH',
        'configuration.php': 'HIGH', 'settings.php': 'MEDIUM',
        
        # Credentials & keys
        'id_rsa': 'CRITICAL', 'id_dsa': 'CRITICAL', '.ssh/id_rsa': 'CRITICAL',
        '.pgpass': 'CRITICAL', '.my.cnf': 'HIGH', 'credentials.json': 'CRITICAL',
        'service-account.json': 'CRITICAL', '.npmrc': 'MEDIUM',
        
        # Database files
        'database.sql': 'HIGH', 'db.sql': 'HIGH', 'dump.sql': 'HIGH',
        'backup.sql': 'HIGH', 'users.db': 'CRITICAL', 'data.db': 'MEDIUM',
        
        # Backup files
        'backup.zip': 'MEDIUM', 'backup.tar.gz': 'MEDIUM', 'backups/': 'MEDIUM',
        'backup/': 'MEDIUM', 'old/': 'LOW', 'temp/': 'LOW',
        
        # Admin interfaces
        'admin/': 'HIGH', 'administrator/': 'HIGH', 'wp-admin/': 'MEDIUM',
        'phpmyadmin/': 'HIGH', 'adminer.php': 'HIGH', 'solr/': 'HIGH',
        'manager/': 'HIGH', 'cpanel/': 'HIGH',
        
        # Logs and debugging
        'error.log': 'MEDIUM', 'access.log': 'MEDIUM', 'debug.log': 'MEDIUM',
        'php_errors.log': 'MEDIUM', 'server-status': 'HIGH',
        'server-info': 'HIGH', '.ds_store': 'LOW',
        
        # Cloud metadata
        '.well-known/security.txt': 'LOW', 'crossdomain.xml': 'LOW',
        'robots.txt': 'LOW', 'sitemap.xml': 'LOW'
    }
    
    COMMON_DIRS = [
        'admin', 'backup', 'api', 'uploads', 'images', 'assets',
        'files', 'docs', 'test', 'dev', 'staging', 'config',
        'data', 'logs', 'tmp', 'cache', 'vendor', 'node_modules'
    ]
    
    def __init__(self, timeout: int = 5, threads: int = 20):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.threads = threads
        self.session = None
    
    async def init(self):
        self.session = aiohttp.ClientSession(timeout=self.timeout)
    
    async def close(self):
        if self.session:
            await self.session.close()
    
    async def check_path(self, base_url: str, path: str) -> DiscoveredFile:
        """Check single path"""
        url = f"{base_url.rstrip('/')}/{path}"
        try:
            async with self.session.get(url, allow_redirects=False) as resp:
                if resp.status in [200, 301, 302, 403]:
                    is_sensitive = path in self.SENSITIVE_FILES
                    risk = self.SENSITIVE_FILES.get(path, 'LOW')
                    
                    return DiscoveredFile(
                        url=url, status=resp.status,
                        size=resp.content_length or 0,
                        is_sensitive=is_sensitive, risk=risk
                    )
        except:
            pass
        return None
    
    async def scan_files(self, base_url: str, file_list: List[str] = None) -> List[DiscoveredFile]:
        """Scan for sensitive files"""
        files = file_list or list(self.SENSITIVE_FILES.keys())
        await self.init()
        
        results = []
        semaphore = asyncio.Semaphore(self.threads)
        
        async def limited_check(path):
            async with semaphore:
                return await self.check_path(base_url, path)
        
        tasks = [limited_check(f) for f in files]
        found = await asyncio.gather(*tasks)
        
        await self.close()
        return [f for f in found if f is not None]
    
    async def scan_directories(self, base_url: str) -> List[DiscoveredFile]:
        """Scan for directories"""
        await self.init()
        
        found = []
        for dirname in self.COMMON_DIRS:
            result = await self.check_path(base_url, dirname + '/')
            if result:
                found.append(result)
        
        await self.close()
        return found
    
    async def full_scan(self, base_url: str) -> List[DiscoveredFile]:
        """Run full directory and file scan"""
        files = await self.scan_files(base_url)
        dirs = await self.scan_directories(base_url)
        return files + dirs
