import json
from typing import List
from ..scanners.base import Vulnerability
from ..core.target import Target

class Reporter:
    def __init__(self, target: Target, vulnerabilities: List[Vulnerability]):
        self.target = target
        self.vulnerabilities = vulnerabilities

    def generate_json(self, filepath: str):
        data = {
            "target": self.target.url,
            "tech_stack": self.target.tech_stack,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)

    def generate_markdown(self, filepath: str):
        content = f"# Scan Report for {self.target.url}\n\n"
        content += "## Target Information\n"
        content += f"- **URL**: {self.target.url}\n"
        content += f"- **Tech Stack**: {', '.join(self.target.tech_stack)}\n\n"
        content += "## Vulnerabilities\n"
        
        if not self.vulnerabilities:
            content += "No vulnerabilities found.\n"
        else:
            for v in self.vulnerabilities:
                content += f"### {v.name}\n"
                content += f"- **Severity**: {v.severity}\n"
                content += f"- **Description**: {v.description}\n"
                content += f"- **Evidence**: `{v.evidence}`\n\n"

        with open(filepath, 'w') as f:
            f.write(content)

    def generate_html(self, filepath: str):
        # Basic HTML template
        html = f"""
        <html>
        <head>
            <title>Scan Report - {self.target.url}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #2c3e50; }}
                .vuln {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #e74c3c; }}
                .high {{ border-left: 5px solid #e67e22; }}
                .medium {{ border-left: 5px solid #f1c40f; }}
                .low {{ border-left: 5px solid #3498db; }}
            </style>
        </head>
        <body>
            <h1>Scan Report: {self.target.url}</h1>
            <p><strong>Tech Stack:</strong> {', '.join(self.target.tech_stack)}</p>
            <h2>Vulnerabilities</h2>
        """
        
        if not self.vulnerabilities:
            html += "<p>No vulnerabilities found.</p>"
        else:
            for v in self.vulnerabilities:
                severity_class = v.severity.lower()
                html += f"""
                <div class="vuln {severity_class}">
                    <h3>{v.name} <span style="font-size: 0.8em; color: #7f8c8d;">({v.severity})</span></h3>
                    <p>{v.description}</p>
                    <pre>{v.evidence}</pre>
                </div>
                """
        
        html += "</body></html>"
        
        with open(filepath, 'w') as f:
            f.write(html)
