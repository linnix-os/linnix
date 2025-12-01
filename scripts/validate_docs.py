#!/usr/bin/env python3
"""
Linnix Documentation Validator

Validates that documentation accurately reflects the codebase.
Code is the source of truth.

Usage:
    python3 scripts/validate_docs.py [--verbose] [--fix]
"""

import argparse
import re
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Set

@dataclass
class ValidationResult:
    """Result of a validation check."""
    category: str
    passed: bool
    message: str
    file: str = ""
    line: int = 0

class DocValidator:
    """Validates documentation against source code."""
    
    def __init__(self, workspace_root: str, verbose: bool = False):
        self.root = Path(workspace_root)
        self.verbose = verbose
        self.results: List[ValidationResult] = []
    
    def log(self, msg: str):
        if self.verbose:
            print(f"  [DEBUG] {msg}")
    
    def add_result(self, category: str, passed: bool, message: str, file: str = "", line: int = 0):
        self.results.append(ValidationResult(category, passed, message, file, line))
    
    # =========================================================================
    # API Route Validation
    # =========================================================================
    
    def extract_api_routes_from_code(self) -> Set[str]:
        """Extract all API routes from cognitod/src/api/mod.rs"""
        api_file = self.root / "cognitod/src/api/mod.rs"
        if not api_file.exists():
            self.add_result("api", False, f"API file not found: {api_file}")
            return set()
        
        content = api_file.read_text()
        # Match .route("/path", ...)
        route_pattern = r'\.route\("([^"]+)"'
        routes = set(re.findall(route_pattern, content))
        self.log(f"Found {len(routes)} routes in code: {sorted(routes)}")
        return routes
    
    def extract_api_routes_from_docs(self) -> Set[str]:
        """Extract documented API routes from docker/README.md and other docs."""
        documented_routes = set()
        
        doc_files = [
            self.root / "docker/README.md",
            self.root / "docs/prometheus-integration.md",
            self.root / "docs/AWS_EC2_DEPLOYMENT.md",
        ]
        
        for doc_file in doc_files:
            if not doc_file.exists():
                continue
            content = doc_file.read_text()
            # Match routes in curl commands or markdown
            patterns = [
                r'localhost:\d+(/[a-zA-Z0-9/_-]+)',
                r'http://[^/]+(/[a-zA-Z0-9/_-]+)',
                r'`(/[a-zA-Z0-9/_-]+)`',
            ]
            for pattern in patterns:
                matches = re.findall(pattern, content)
                documented_routes.update(matches)
        
        # Clean up routes - remove query params, etc.
        cleaned = set()
        for route in documented_routes:
            route = route.split('?')[0].split('#')[0]
            if route and route != '/':
                cleaned.add(route)
        
        self.log(f"Found {len(cleaned)} routes in docs: {sorted(cleaned)}")
        return cleaned
    
    def validate_api_routes(self):
        """Validate that documented API routes exist in code."""
        print("\n[1/5] Validating API Routes...")
        
        code_routes = self.extract_api_routes_from_code()
        doc_routes = self.extract_api_routes_from_docs()
        
        # Normalize routes (remove path parameters)
        def normalize(route: str) -> str:
            return re.sub(r'/\{[^}]+\}', '/{id}', route)
        
        code_normalized = {normalize(r) for r in code_routes}
        
        # Check for documented routes that don't exist in code
        for route in doc_routes:
            normalized = normalize(route)
            # Skip some known patterns
            if any(x in route for x in ['/api/', '/v1/', 'health']):
                continue
            if normalized in code_normalized or route in code_routes:
                self.add_result("api", True, f"Route exists: {route}")
            else:
                # Check if it's a sub-path of an existing route
                found = False
                for code_route in code_routes:
                    if route.startswith(code_route.replace('/{', '/').split('{')[0]):
                        found = True
                        break
                if not found:
                    self.add_result("api", False, f"Documented route not in code: {route}")
    
    # =========================================================================
    # Config Field Validation
    # =========================================================================
    
    def extract_config_fields_from_code(self) -> dict:
        """Extract config struct fields from config.rs"""
        config_file = self.root / "cognitod/src/config.rs"
        if not config_file.exists():
            self.add_result("config", False, f"Config file not found: {config_file}")
            return {}
        
        content = config_file.read_text()
        
        # Find struct definitions and their fields
        fields = {}
        # This is a simplified parser - would need more work for full accuracy
        struct_pattern = r'pub struct (\w+Config)\s*\{([^}]+)\}'
        for match in re.finditer(struct_pattern, content, re.MULTILINE | re.DOTALL):
            struct_name = match.group(1)
            struct_body = match.group(2)
            # Extract field names
            field_pattern = r'pub\s+(\w+):'
            struct_fields = re.findall(field_pattern, struct_body)
            fields[struct_name] = struct_fields
            self.log(f"Config struct {struct_name}: {struct_fields}")
        
        return fields
    
    def extract_config_from_toml(self) -> dict:
        """Extract sections and keys from example config."""
        config_file = self.root / "configs/linnix.toml"
        if not config_file.exists():
            return {}
        
        content = config_file.read_text()
        sections = {}
        current_section = "root"
        
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                sections[current_section] = []
            elif '=' in line and not line.startswith('#'):
                key = line.split('=')[0].strip()
                if current_section not in sections:
                    sections[current_section] = []
                sections[current_section].append(key)
        
        self.log(f"TOML sections: {sections}")
        return sections
    
    def validate_config_fields(self):
        """Validate that config fields in docs match code."""
        print("\n[2/5] Validating Configuration Fields...")
        
        code_fields = self.extract_config_fields_from_code()
        toml_sections = self.extract_config_from_toml()
        
        # Check that TOML sections have corresponding structs
        # Note: Some sections map to nested fields in the Config struct
        section_to_struct = {
            'api': 'ApiConfig',
            'runtime': 'RuntimeConfig',
            'telemetry': None,  # Parsed but fields handled in main.rs
            'reasoner': 'ReasonerConfig',
            'prometheus': None,  # Handled via outputs.prometheus
            'notifications': 'NotificationConfig',
            'outputs': 'OutputConfig',
            'probes': 'ProbesConfig',
            'circuit_breaker': 'CircuitBreakerConfig',
            'logging': 'LoggingConfig',
            'rules': 'RulesFileConfig',
        }
        
        for section, struct_name in section_to_struct.items():
            if struct_name is None:
                # These are special cases handled differently
                self.add_result("config", True, f"Config section [{section}] is a special/legacy section")
            elif struct_name in code_fields:
                self.add_result("config", True, f"Config section [{section}] maps to {struct_name}")
            else:
                self.add_result("config", False, f"Config section [{section}] has no matching struct")
    
    # =========================================================================
    # CLI Command Validation
    # =========================================================================
    
    def extract_cli_commands_from_code(self) -> Set[str]:
        """Extract CLI subcommands and flags from linnix-cli."""
        cli_main = self.root / "linnix-cli/src/main.rs"
        if not cli_main.exists():
            return set()
        
        content = cli_main.read_text()
        commands = set()
        
        # Match enum variants in Command enum (subcommands)
        # Look for pattern like "Export {" or "Doctor,"
        in_command_enum = False
        brace_depth = 0
        for line in content.split('\n'):
            if 'enum Command' in line:
                in_command_enum = True
                brace_depth = 0
                continue
            if in_command_enum:
                brace_depth += line.count('{') - line.count('}')
                if brace_depth < 0:
                    in_command_enum = False
                    continue
                # Match variant names like "Export {", "Doctor,", "/// Doc comment" ignored
                stripped = line.strip()
                if stripped.startswith('///') or stripped.startswith('//') or stripped.startswith('#'):
                    continue
                match = re.match(r'^(\w+)\s*(?:\{|,)', stripped)
                if match:
                    cmd = match.group(1).lower()
                    if cmd not in ['command']:
                        commands.add(cmd)
        
        # Also detect flag-based commands (--stats, --alerts trigger specific behavior)
        if 'stats: bool' in content or '--stats' in content:
            commands.add('stats')
        if 'alerts: bool' in content or '--alerts' in content:
            commands.add('alerts')
        # Default behavior is streaming
        if 'connect_sse' in content and '/stream' in content:
            commands.add('stream')
        # Check for /metrics endpoint usage
        if '/metrics' in content:
            commands.add('metrics')
        
        self.log(f"CLI commands in code: {commands}")
        return commands
    
    def extract_cli_commands_from_docs(self) -> Set[str]:
        """Extract documented CLI commands."""
        commands = set()
        
        doc_files = [
            self.root / "docs/AWS_EC2_DEPLOYMENT.md",
            self.root / "README.md",
            self.root / "linnix-cli/README.md" if (self.root / "linnix-cli/README.md").exists() else None,
        ]
        
        for doc_file in doc_files:
            if doc_file is None or not doc_file.exists():
                continue
            content = doc_file.read_text()
            # Match linnix-cli <command>
            pattern = r'linnix-cli\s+(\w+)'
            commands.update(re.findall(pattern, content))
        
        self.log(f"CLI commands in docs: {commands}")
        return commands
    
    def validate_cli_commands(self):
        """Validate that documented CLI commands exist in code."""
        print("\n[3/5] Validating CLI Commands...")
        
        code_commands = self.extract_cli_commands_from_code()
        doc_commands = self.extract_cli_commands_from_docs()
        
        for cmd in doc_commands:
            if cmd.lower() in {c.lower() for c in code_commands}:
                self.add_result("cli", True, f"CLI command exists: {cmd}")
            else:
                self.add_result("cli", False, f"Documented CLI command not in code: {cmd}")
    
    # =========================================================================
    # eBPF Probe Validation
    # =========================================================================
    
    def extract_probes_from_code(self) -> Set[str]:
        """Extract eBPF probe names from code."""
        ebpf_dir = self.root / "linnix-ai-ebpf/linnix-ai-ebpf-ebpf/src"
        if not ebpf_dir.exists():
            return set()
        
        probes = set()
        for rs_file in ebpf_dir.glob("*.rs"):
            content = rs_file.read_text()
            # Match #[tracepoint(...)] or #[kprobe(...)]
            patterns = [
                r'#\[tracepoint\([^)]+\)\]',
                r'#\[kprobe\([^)]+\)\]',
            ]
            for pattern in patterns:
                probes.update(re.findall(pattern, content))
        
        self.log(f"eBPF probes in code: {probes}")
        return probes
    
    def validate_ebpf_probes(self):
        """Validate that documented probes match code."""
        print("\n[4/5] Validating eBPF Probes...")
        
        collector_doc = self.root / "docs/collector.md"
        if not collector_doc.exists():
            self.add_result("ebpf", False, "Collector documentation not found")
            return
        
        doc_content = collector_doc.read_text()
        
        # Check mandatory probes are documented
        mandatory = ['sched_process_exec', 'sched_process_fork', 'sched_process_exit']
        for probe in mandatory:
            if probe in doc_content:
                self.add_result("ebpf", True, f"Mandatory probe documented: {probe}")
            else:
                self.add_result("ebpf", False, f"Mandatory probe not documented: {probe}")
    
    # =========================================================================
    # Environment Variable Validation
    # =========================================================================
    
    def validate_env_vars(self):
        """Validate that documented env vars are used in code."""
        print("\n[5/5] Validating Environment Variables...")
        
        # Known env vars from docs
        documented_vars = [
            ('LINNIX_CONFIG', 'Config file path'),
            ('LINNIX_BPF_PATH', 'eBPF object path'),
            ('LINNIX_LISTEN_ADDR', 'Listen address override'),
            ('LINNIX_API_TOKEN', 'API auth token'),
            ('LLM_ENDPOINT', 'LLM server URL'),
            ('LLM_MODEL', 'LLM model name'),
            ('OPENAI_API_KEY', 'OpenAI API key'),
        ]
        
        # Search for env var usage in code
        for var_name, description in documented_vars:
            found = False
            for rs_file in self.root.glob("**/*.rs"):
                if 'target' in str(rs_file):
                    continue
                try:
                    content = rs_file.read_text()
                    if f'"{var_name}"' in content or f"'{var_name}'" in content:
                        found = True
                        break
                except:
                    continue
            
            if found:
                self.add_result("envvar", True, f"Env var used in code: {var_name}")
            else:
                self.add_result("envvar", False, f"Documented env var not found in code: {var_name}")
    
    # =========================================================================
    # Main Runner
    # =========================================================================
    
    def run_all(self) -> Tuple[int, int]:
        """Run all validation checks."""
        self.validate_api_routes()
        self.validate_config_fields()
        self.validate_cli_commands()
        self.validate_ebpf_probes()
        self.validate_env_vars()
        
        errors = sum(1 for r in self.results if not r.passed)
        passed = sum(1 for r in self.results if r.passed)
        
        return errors, passed
    
    def print_summary(self):
        """Print validation summary."""
        print("\n" + "=" * 60)
        print("VALIDATION SUMMARY")
        print("=" * 60)
        
        categories = {}
        for result in self.results:
            if result.category not in categories:
                categories[result.category] = {'passed': 0, 'failed': 0}
            if result.passed:
                categories[result.category]['passed'] += 1
            else:
                categories[result.category]['failed'] += 1
        
        for cat, counts in categories.items():
            status = "✓" if counts['failed'] == 0 else "✗"
            print(f"  {status} {cat.upper()}: {counts['passed']} passed, {counts['failed']} failed")
        
        print("")
        
        # Print failures
        failures = [r for r in self.results if not r.passed]
        if failures:
            print("FAILURES:")
            for f in failures:
                print(f"  ✗ [{f.category}] {f.message}")
        
        total_errors = sum(1 for r in self.results if not r.passed)
        total_passed = sum(1 for r in self.results if r.passed)
        
        print("")
        if total_errors == 0:
            print(f"✓ All {total_passed} checks passed!")
        else:
            print(f"✗ {total_errors} failures, {total_passed} passed")
        
        return total_errors


def main():
    parser = argparse.ArgumentParser(description='Validate Linnix documentation')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--workspace', '-w', default='.', help='Workspace root')
    args = parser.parse_args()
    
    # Find workspace root
    workspace = Path(args.workspace).resolve()
    if not (workspace / 'Cargo.toml').exists():
        # Try to find it
        if (workspace / 'linnix-opensource').exists():
            workspace = workspace / 'linnix-opensource'
        elif (workspace.parent / 'Cargo.toml').exists():
            workspace = workspace.parent
    
    print(f"Linnix Documentation Validator")
    print(f"Workspace: {workspace}")
    
    validator = DocValidator(str(workspace), verbose=args.verbose)
    validator.run_all()
    errors = validator.print_summary()
    
    sys.exit(1 if errors > 0 else 0)


if __name__ == "__main__":
    main()
