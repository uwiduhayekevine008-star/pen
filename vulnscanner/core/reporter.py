"""Advanced Report Generator with Professional Output"""
import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import asdict


class ReportGenerator:
    """Professional report generator with multiple output formats"""
    
    def __init__(self, vulnerabilities: List = None, exploits: List = None):
        self.vulnerabilities = vulnerabilities or []
        self.exploits = exploits or []
        
    def _vuln_to_dict(self, vuln) -> Dict:
        if hasattr(vuln, '__dataclass_fields__'):
            return asdict(vuln)
        return {
            'vuln_id': vuln.vuln_id,
            'name': vuln.name,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'description': vuln.description,
            'affected_component': vuln.affected_component,
            'remediation': vuln.remediation,
            'cwe_id': vuln.cwe_id,
            'cve_id': vuln.cve_id,
            'exploit_available': vuln.exploit_available,
            'timestamp': vuln.timestamp
        }
    
    def _calculate_statistics(self) -> Dict:
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in self.vulnerabilities:
            sev = vuln.severity.upper() if hasattr(vuln, 'severity') else 'INFO'
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        total = len(self.vulnerabilities)
        exploitables = sum(1 for v in self.vulnerabilities if hasattr(v, 'exploit_available') and v.exploit_available)
        
        avg_cvss = 0.0
        if total > 0:
            scores = [v.cvss_score for v in self.vulnerabilities if hasattr(v, 'cvss_score') and v.cvss_score]
            avg_cvss = sum(scores) / len(scores) if scores else 0.0
        
        return {
            'total_vulnerabilities': total,
            'severity_distribution': severity_counts,
            'exploitable_count': exploitables,
            'average_cvss': round(avg_cvss, 2),
            'report_generated': datetime.now().isoformat()
        }
    
    def export_json(self, output_path: str) -> None:
        data = {
            'statistics': self._calculate_statistics(),
            'vulnerabilities': [self._vuln_to_dict(v) for v in self.vulnerabilities],
            'exploits': [{'target': e.target, 'name': e.exploit_name, 'success': e.success, 'output': e.output} for e in self.exploits]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"[+] JSON report saved: {output_path}")
    
    def export_csv(self, output_path: str) -> None:
        vuln_dicts = [self._vuln_to_dict(v) for v in self.vulnerabilities]
        
        if not vuln_dicts:
            print("[-] No vulnerabilities to export")
            return
        
        fieldnames = list(vuln_dicts[0].keys()) if vuln_dicts else []
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(vuln_dicts)
        
        print(f"[+] CSV report saved: {output_path}")
    
    def export_html(self, output_path: str) -> None:
        stats = self._calculate_statistics()
        vulns = [self._vuln_to_dict(v) for v in self.vulnerabilities]
        
        severity_colors = {
            'CRITICAL': '#9c27b0', 'HIGH': '#f44336',
            'MEDIUM': '#ff9800', 'LOW': '#4caf50', 'INFO': '#2196f3'
        }
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #00d9ff; margin-bottom: 30px; text-align: center; }}
        h2 {{ color: #00ff88; margin: 20px 0; border-bottom: 2px solid #00ff88; padding-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: linear-gradient(145deg, #16213e, #1a1a2e); border: 1px solid #0f3460; border-radius: 10px; padding: 20px; text-align: center; }}
        .stat-value {{ font-size: 2.5em; font-weight: bold; color: #00d9ff; }}
        .stat-label {{ color: #888; margin-top: 5px; }}
        .severity-bar {{ display: flex; gap: 5px; margin-top: 10px; height: 30px; border-radius: 5px; overflow: hidden; }}
        .severity-segment {{ transition: width 0.3s; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #16213e; }}
        th {{ background: #0f3460; color: #00d9ff; padding: 15px; text-align: left; }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #0f3460; }}
        tr:hover {{ background: #1a1a2e; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }}
        .cvss-score {{ font-weight: bold; }}
        .remediation {{ font-size: 0.9em; color: #4caf50; }}
        .header {{ text-align: center; padding: 40px 0; }}
        .header h1 {{ font-size: 2.5em; }}
        .timestamp {{ color: #888; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Vulnerability Assessment Report</h1>
            <p class="timestamp">Generated: {stats['report_generated']}</p>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats['total_vulnerabilities']}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #f44336;">{stats['severity_distribution']['CRITICAL'] + stats['severity_distribution']['HIGH']}</div>
                <div class="stat-label">Critical & High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ff9800;">{stats['severity_distribution']['MEDIUM']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #4caf50;">{stats['severity_distribution']['LOW']}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['average_cvss']}</div>
                <div class="stat-label">Avg CVSS Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #e91e63;">{stats['exploitable_count']}</div>
                <div class="stat-label">Exploitable</div>
            </div>
        </div>
        
        <h2>Vulnerability Details</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Affected Component</th>
                    <th>CVE/CWE</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>'''
        
        for vuln in vulns:
            color = severity_colors.get(vuln.get('severity', 'INFO').upper(), '#888')
            html += f'''
                <tr>
                    <td>{vuln.get('vuln_id', 'N/A')}</td>
                    <td>{vuln.get('name', 'N/A')}</td>
                    <td><span class="severity-badge" style="background: {color};">{vuln.get('severity', 'INFO')}</span></td>
                    <td class="cvss-score">{vuln.get('cvss_score', 0)}</td>
                    <td>{vuln.get('affected_component', 'N/A')}</td>
                    <td>{vuln.get('cve_id', vuln.get('cwe_id', '-'))}</td>
                    <td class="remediation">{vuln.get('remediation', 'N/A')[:80]}...</td>
                </tr>'''
        
        html += '''
            </tbody>
        </table>
    </div>
</body>
</html>'''
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"[+] HTML report saved: {output_path}")
    
    def generate_executive_summary(self) -> str:
        stats = self._calculate_statistics()
        
        summary = f"""
================================================================================
                    VULNERABILITY ASSESSMENT EXECUTIVE SUMMARY
================================================================================

Report Generated: {stats['report_generated']}

FINDINGS OVERVIEW
-----------------
Total Vulnerabilities Found: {stats['total_vulnerabilities']}

Severity Distribution:
  - CRITICAL: {stats['severity_distribution']['CRITICAL']}
  - HIGH:     {stats['severity_distribution']['HIGH']}
  - MEDIUM:   {stats['severity_distribution']['MEDIUM']}
  - LOW:      {stats['severity_distribution']['LOW']}
  - INFO:     {stats['severity_distribution']['INFO']}

Risk Metrics:
  - Average CVSS Score: {stats['average_cvss']}
  - Exploitable Vulnerabilities: {stats['exploitable_count']}

PRIORITY RECOMMENDATIONS
------------------------
"""
        
        critical_high = stats['severity_distribution']['CRITICAL'] + stats['severity_distribution']['HIGH']
        if critical_high > 0:
            summary += f"1. IMMEDIATE ACTION REQUIRED: {critical_high} critical/high severity issues need urgent attention.\n"
        
        if stats['exploitable_count'] > 0:
            summary += f"2. EXPLOIT RISK: {stats['exploitable_count']} vulnerabilities have known exploits.\n"
        
        summary += "3. Patch management process should be reviewed and accelerated.\n"
        summary += "4. Implement network segmentation to limit lateral movement.\n"
        summary += "5. Deploy Web Application Firewall (WAF) for web services.\n"
        summary += "6. Enable comprehensive logging and monitoring.\n"
        
        summary += "\n================================================================================\n"
        
        return summary
    
    def export_all(self, output_dir: str) -> None:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        self.export_json(os.path.join(output_dir, f"report_{timestamp}.json"))
        self.export_csv(os.path.join(output_dir, f"report_{timestamp}.csv"))
        self.export_html(os.path.join(output_dir, f"report_{timestamp}.html"))
        
        summary = self.generate_executive_summary()
        with open(os.path.join(output_dir, f"summary_{timestamp}.txt"), 'w') as f:
            f.write(summary)
        
        print(f"\n[+] All reports saved to: {output_dir}")
