"""
FireBounty v2 - Dynamic Plugin Manager
Allows runtime loading of custom scripts from the plugins directory.
"""

import os
import importlib.util
from utils.logger import log

class PluginManager:
    """
    Manager to discover, load, and execute third-party plugins dynamically.
    """
    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = plugins_dir
        os.makedirs(self.plugins_dir, exist_ok=True)

    def find_plugins(self) -> list:
        """
        Scans the plugins directory for Python modules.
        Returns a list of absolute filepaths to plugin scripts.
        """
        plugins = []
        if not os.path.exists(self.plugins_dir):
            return plugins
            
        for file in os.listdir(self.plugins_dir):
            if file.endswith(".py") and not file.startswith("__"):
                plugins.append(os.path.join(self.plugins_dir, file))
        return plugins

    def load_plugin_module(self, filepath: str):
        """
        Dynamically imports a Python module from a given file path.
        """
        try:
            module_name = os.path.splitext(os.path.basename(filepath))[0]
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module
        except Exception as e:
            log(f"[Plugin Manager] Error loading plugin from {filepath}: {e}")
        return None

    def execute_plugin(self, mode: str, target: str) -> bool:
        """
        Checks all discovered plugins. If a plugin's MODE attribute matches the requested mode,
        executes its run() function.
        Returns True if a plugin was found and run, False otherwise.
        """
        plugin_files = self.find_plugins()
        
        for filepath in plugin_files:
            module = self.load_plugin_module(filepath)
            if not module:
                continue
                
            # A valid plugin must define a 'MODE' attribute and a 'run' function
            plugin_mode = getattr(module, "MODE", None)
            run_func = getattr(module, "run", None)
            
            if plugin_mode == mode and run_func:
                plugin_name = getattr(module, "NAME", os.path.splitext(os.path.basename(filepath))[0])
                log(f"[Plugin Manager] Executing custom plugin: {plugin_name} (Mode: {plugin_mode})")
                
                try:
                    run_func(target)
                    return True
                except Exception as e:
                    log(f"[Plugin Manager] Plugin {plugin_name} failed during execution: {e}")
                    return True  # Returned True because the mode matched, even though it failed
                    
        return False
