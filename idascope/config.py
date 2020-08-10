import os
import idaapi

configuration = {
    "config_path_sep": "\\",
    "plugin_only": False,
    "debug": False,
    "paths": {
        # "idascope_root_dir": "C:\\Program Files\\IDA 6.9\\plugins",
        "idascope_root_dir": "",
        "inspection_tags_file": "idascope\\data\\inspection_tags.json",
        "inspection_profiles_folder": "idascope\\data\\inspection_profiles",
        "winapi_keywords_file": "idascope\\data\\winapi_keywords.json",
        "winapi_rootdir": "C:\\WinAPI\\" if os.name == "nt" else os.path.join(idaapi.get_user_idadir(), "winapi", "").replace(os.sep, "\\")
        # example of file path from working directory 
        # "winapi_rootdir": "idascope\\data\\WinAPI" if os.name == "nt" else os.path.join(idaapi.get_user_idadir(), "winapi", "").replace(os.sep, "\\")
        },
    "winapi": {
        "search_hotkey": "ctrl+y",
        "load_keyword_database": True,
        "online_enabled": True
        },
    "inspection": {
        "default_semantics": "win-ring3"
        },
    "semantic_explorer": {
        "enum_file": "idascope\\data\\semantic_explorer\\enums.json",
        "semantics_file": "idascope\\data\\semantic_explorer\\semantics\\semantics.json",
        },
    "yara": {
        # relative path "idascope\\data\\yara\\" is added on plugin startup.
        "yara_sigs": ["C:\\yara" if os.name == 'nt' else os.path.join(idaapi.get_user_idadir(), "yara")]
        }
}
