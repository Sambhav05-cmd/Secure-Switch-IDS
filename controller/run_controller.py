import sys
import traceback
import time

def start():
    try:
        import os_ken
        print(f"[*] os-ken version: {os_ken.__version__}", flush=True)

        sys.path.insert(0, "/app")

        from os_ken.base.app_manager import AppManager

        print("[*] Loading simple_switch_13 ...", flush=True)

        app_mgr = AppManager.get_instance()
        app_mgr.load_apps(["simple_switch_13"])   # pure original — no REST dep
        contexts = app_mgr.create_contexts()
        services = app_mgr.instantiate_apps(**contexts)

        print("[*] Controller running on :6633", flush=True)
        app_mgr.run_apps()

        app_mgr.uninstantiate_apps()
        app_mgr.close()

    except Exception as e:
        print(f"[FATAL] {e}", flush=True)
        traceback.print_exc()
        time.sleep(3600)

start()
