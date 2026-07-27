"""
FireBounty v2 - Central Execution Runner
Only the Runner controls execution workflow.
"""
import os
import urllib.parse
import importlib
import inspect
from typing import Tuple, Dict, Any

from utils.logger import log
from utils.helpers import sanitize_target
from core.toolcheck import check_tools

def run_module(module_name: str, target: str, is_pipeline: bool = False) -> bool:
    """
    Safely import and run a module's run() function.
    """
    log(f"[*] Starting module: {module_name}")
    try:
        module = importlib.import_module(f"modules.{module_name}")
        if not hasattr(module, "run"):
            log(f"[!] Module {module_name} has no run() function")
            return False
        
        run_func = getattr(module, "run")
        sig = inspect.signature(run_func)
        
        # Handle special modules with custom arguments or interactive requirements
        if module_name == "jwt_attack":
            # Pass is_pipeline flag if the module signature allows it
            if "is_pipeline" in sig.parameters:
                run_func(is_pipeline=is_pipeline)
            else:
                # If signature doesn't support it, but it expects a token, call it
                run_func()
        elif len(sig.parameters) == 0:
            run_func()
        else:
            run_func(target)
            
        log(f"[✓] Module {module_name} completed successfully")
        return True
    except Exception as e:
        log(f"[!] Module {module_name} encountered an error: {e}")
        return False

def run_pipeline(mode: str, target_raw: str) -> None:
    """
    Central orchestrator for all modes and pipelines in FireBounty v2.
    """
    log(f"[*] Initializing runner for mode: {mode}")
    
    # 1. Dependency Checking
    check_tools()
    
    # 2. Target Sanitization
    domain, base_url = sanitize_target(target_raw)
    log(f"[+] Sanitized Target: Domain = {domain} | Base URL = {base_url}")
    
    if mode == "recon":
        run_module("subdomain", domain)
        run_module("dirfuzz", base_url)
        
    elif mode == "waf":
        run_module("wafdetect", base_url)
        
    elif mode == "technology":
        run_module("technology", base_url)
        
    elif mode == "bypass":
        run_module("waf_bypass", base_url)
        
    elif mode == "js":
        run_module("js_analyzer", base_url)
        
    elif mode == "param":
        run_module("param_finder", base_url)
        
    elif mode == "api":
        run_module("api_fuzzer", base_url)
        
    elif mode == "idor":
        run_module("idor", base_url)
        
    elif mode == "auth":
        run_module("auth_bypass", base_url)
        
    elif mode == "brute":
        run_module("param_bruteforce", base_url)
        
    elif mode == "mutate":
        run_module("param_mutator", base_url)
        
    elif mode == "combo":
        run_module("combo_fuzzer", base_url)
        
    elif mode == "jwt":
        # Interactive by default when run as standalone mode
        run_module("jwt_attack", base_url, is_pipeline=False)
        
    elif mode == "race":
        run_module("race", base_url)

    elif mode == "takeover":
        run_module("takeover", domain)

    elif mode == "links":
        run_module("broken_links", base_url)

    elif mode == "correlate":
        run_module("correlate", base_url)

    elif mode == "report":
        run_module("report", base_url)

    elif mode == "parameters":
        run_module("parameters", base_url)
        
    elif mode == "full":
        log("\n[*] Starting Full Scan Pipeline\n")
        
        # Step 1: Subdomain gathering (takes raw domain)
        run_module("subdomain", domain)
        
        # Step 2: Alive Check Stop Gate
        # Verify if alive hosts file exists and has size > 0
        alive_file = os.path.join("outputs", domain, "recon", "alive.txt")
        if not os.path.exists(alive_file) or os.path.getsize(alive_file) == 0:
            log("[!] Stop scan: No alive hosts discovered in subdomain recon.")
            log("[SUCCESS] Scan Completed (No target active)")
            return
            
        # Step 3: Run technology discovery
        run_module("technology", base_url)
        
        # Step 4: Run GAU/Wayback/Katana
        run_module("recon", base_url)  # runs endpoint discovery
        
        # Step 4.5: Dynamic Parameter Extraction
        run_module("parameters", base_url)
        
        # Step 5: Active Scan Modules
        run_module("takeover", domain)
        run_module("broken_links", base_url)
        run_module("auth_bypass", base_url)
        run_module("param_bruteforce", base_url)
        run_module("wafdetect", base_url)
        run_module("waf_bypass", base_url)
        run_module("param_mutator", base_url)
        run_module("combo_fuzzer", base_url)
        run_module("js_analyzer", base_url)
        run_module("jwt_attack", base_url, is_pipeline=True)
        run_module("race", base_url)
        run_module("param_finder", base_url)
        run_module("api_fuzzer", base_url)
        run_module("idor", base_url)

        # Step 6: Attack Chain Correlation
        run_module("correlate", base_url)

        # Step 7: Compile Reports
        run_module("report", base_url)
        
        log("\n[SUCCESS] Full Scan Pipeline Completed\n")


    else:
        # Check dynamic plugins
        from core.plugin_manager import PluginManager
        pm = PluginManager()
        if pm.execute_plugin(mode, base_url):
            return
        log(f"[!] Invalid execution mode: {mode}")

