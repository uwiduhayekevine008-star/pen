"""Directory and File Discovery Scanner with Modern Techniques"""
import asyncio
import aiohttp
from typing import List, Dict, Set
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class DiscoveredFile:
    url: str
    status: int
    size: int
    is_sensitive: bool
    risk: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


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
    
    async def scan_backup_files(self, base_url: str) -> List[DiscoveredFile]:
        """Scan for backup files"""
        backup_patterns = [
            'backup.zip', 'backup.tar.gz', 'backup.tar', 'backup.sql',
            'database.sql', 'dump.sql', 'db.sql', 'backup.tar.bz2',
            'old.zip', 'old.tar.gz', 'site.zip', 'site.tar.gz',
            'www.zip', 'www.tar.gz', 'web.zip', 'web.tar.gz'
        ]
        return await self.scan_files(base_url, backup_patterns)
    
    async def scan_git_exposed(self, base_url: str) -> List[DiscoveredFile]:
        """Scan for exposed Git repositories"""
        git_patterns = [
            '.git/config', '.git/HEAD', '.git/index', '.git/logs/HEAD',
            '.git/objects', '.git/refs', '.gitignore', '.gitattributes'
        ]
        return await self.scan_files(base_url, git_patterns)
    
    async def scan_svn_exposed(self, base_url: str) -> List[DiscoveredFile]:
        """Scan for exposed SVN repositories"""
        svn_patterns = [
            '.svn/entries', '.svn/wc.db', '.svn/props', '.svn/text-base/',
            'svn-base/', 'entries', 'format'
        ]
        return await self.scan_files(base_url, svn_patterns)
    
    async def scan_cloud_configs(self, base_url: str) -> List[DiscoveredFile]:
        """Scan for cloud configuration files"""
        cloud_patterns = [
            'credentials.json', 'service-account.json', 'gcp-credentials.json',
            'aws-credentials.json', 'azure-credentials.json',
            'credentials.csv', 'credentials.txt', 'secrets.json',
            'secrets.yaml', 'secrets.yml', 'env.json', 'env.yaml'
        ]
        return await self.scan_files(base_url, cloud_patterns)
    
    async def full_scan(self, base_url: str) -> List[DiscoveredFile]:
        """Run full directory and file scan"""
        files = await self.scan_files(base_url)
        dirs = await self.scan_directories(base_url)
        backups = await self.scan_backup_files(base_url)
        git = await self.scan_git_exposed(base_url)
        svn = await self.scan_svn_exposed(base_url)
        cloud = await self.scan_cloud_configs(base_url)
        
        all_results = files + dirs + backups + git + svn + cloud
        
        # Remove duplicates
        seen = set()
        unique = []
        for f in all_results:
            if f.url not in seen:
                seen.add(f.url)
                unique.append(f)
        
        return unique
