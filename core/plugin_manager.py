"""
FireBounty v2 - Plugin Manager
Dynamically discovers, validates, and loads user-defined custom plugins from plugins/ directory.
"""

import os
import json
import sys
import importlib.util
from typing import Dict, Any
from utils.logger import log

class PluginManager:
    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = plugins_dir
        self.plugins: Dict[str, Dict[str, Any]] = {}
        self.discover_plugins()

    def discover_plugins(self) -> None:
        """
        Scan plugins directory for folders containing valid plugin.json files.
        """
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir, exist_ok=True)
            return

        for folder in os.listdir(self.plugins_dir):
            folder_path = os.path.join(self.plugins_dir, folder)
            if not os.path.isdir(folder_path):
                continue

            config_path = os.path.join(folder_path, "plugin.json")
            if not os.path.exists(config_path):
                continue

            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                
                # Validation
                mode = meta.get("mode")
                entrypoint = meta.get("entrypoint", "main.py")
                classname = meta.get("classname", "Plugin")
                
                if not mode:
                    log(f"[!] Skipping plugin in {folder}: missing 'mode' configuration.")
                    continue

                self.plugins[mode] = {
                    "name": meta.get("name", folder),
                    "dir": folder_path,
                    "entrypoint": entrypoint,
                    "classname": classname
                }
            except Exception as e:
                log(f"[!] Error reading plugin metadata in {folder}: {e}")

    def execute_plugin(self, mode: str, target: str) -> bool:
        """
        Load and run the plugin matching the requested mode.
        """
        plugin_meta = self.plugins.get(mode)
        if not plugin_meta:
            return False

        log(f"[*] Dynamically loading plugin: {plugin_meta['name']} (mode: {mode})")
        
        entrypoint_path = os.path.join(plugin_meta["dir"], plugin_meta["entrypoint"])
        if not os.path.exists(entrypoint_path):
            log(f"[!] Plugin entrypoint missing: {entrypoint_path}")
            return False

        try:
            # Dynamic module import
            spec = importlib.util.spec_from_file_location(
                f"plugins_{mode}",
                entrypoint_path
            )
            if not spec or not spec.loader:
                return False
                
            module = importlib.util.module_from_spec(spec)
            # Add plugin directory to path temporarily to resolve local imports inside plugin
            sys.path.insert(0, plugin_meta["dir"])
            spec.loader.exec_module(module)
            sys.path.pop(0)

            classname = plugin_meta["classname"]
            if not hasattr(module, classname):
                log(f"[!] Plugin class {classname} not found in {entrypoint_path}")
                return False

            plugin_class = getattr(module, classname)
            instance = plugin_class()
            
            if hasattr(instance, "run"):
                instance.run(target)
                log(f"[✓] Plugin {plugin_meta['name']} executed successfully.")
                return True
            else:
                log(f"[!] Plugin class {classname} missing run() method.")
                return False
        except Exception as e:
            log(f"[!] Plugin execution failed: {e}")
            return False
