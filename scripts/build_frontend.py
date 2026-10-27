"""Render the existing UI for static hosting. Requires only Python's standard library."""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]


def build(output: Path):
    origin = os.environ.get('PCAP_API_BASE_URL', '').strip().rstrip('/')
    parsed = urlparse(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        raise ValueError('PCAP_API_BASE_URL must be an HTTPS origin, e.g. https://pcap.example.com')
    output = output.resolve()
    if output == ROOT or output in (ROOT / 'static', ROOT / 'templates'):
        raise ValueError('Invalid build output directory')
    output.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / 'static', output / 'static', dirs_exist_ok=True)
    replacements = {'app_name': 'PCAP Analyzer Pro', 'version': '2.0', 'max_file_size_gb': '3'}
    for name, filename in {
        'nomios_css': 'css/nomios.css', 'identity_ui_js': 'js/identity-ui.js',
        'style_css': 'css/style.css', 'app_js': 'js/app.js',
        'advanced_features_js': 'js/advanced_features.js', 'connection_js': 'js/connection.js',
    }.items():
        replacements['assets_version.' + name] = hashlib.sha256((ROOT / 'static' / filename).read_bytes()).hexdigest()[:12]
    template = (ROOT / 'templates/index.html').read_text()
    def replace(match):
        key = match.group(1).strip()
        if key not in replacements:
            raise ValueError(f'Unsupported template expression: {key}')
        return html.escape(replacements[key])
    rendered = re.sub(r'{{\s*(.*?)\s*}}', replace, template)
    if '{%' in rendered or '{{' in rendered:
        raise ValueError('Unrendered template syntax')
    (output / 'index.html').write_text(rendered)
    # Public configuration only. Never copy process environment or .env files.
    (output / 'static/js/runtime-config.js').write_text(
        'window.PCAP_CONFIG = ' + json.dumps({'apiBaseUrl': origin}) + ';\n'
    )
    print(f'Static interface built in {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    build(args.output)
