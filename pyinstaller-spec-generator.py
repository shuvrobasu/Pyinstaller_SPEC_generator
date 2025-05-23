import os
import re
import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import BooleanVar, StringVar, IntVar
import subprocess
import threading
from pathlib import Path
import sys
import platform  # For OS detection
import urllib.request  # For downloading UPX
import zipfile  # For extracting UPX on Windows
import tarfile  # For extracting UPX on Linux/macOS
import shutil  # For moving/deleting files/directories


class PyInstallerSpecGenerator:
    def __init__(self, root):
        self.root = root

        # --- IMPORTANT FIX: Initialize all StringVar/BooleanVar/IntVar first ---
        # This ensures they exist before setup_ui tries to assign them to widgets.
        self.var_show_paths = BooleanVar(value=False)
        self.var_recursive_scan = BooleanVar(value=True)
        self.var_debug = BooleanVar(value=False)
        self.var_console = BooleanVar(value=False)
        self.var_onefile = BooleanVar(value=True)
        self.var_windowed = BooleanVar(value=False)
        self.var_upx = BooleanVar(value=True)
        self.var_strip = BooleanVar(value=False)
        self.var_noarchive = BooleanVar(value=False)
        self.var_optimize = IntVar(value=0)
        self.search_var = StringVar()
        self.upx_custom_path = StringVar()  # Initialize this here as well!

        # Platform-specific BooleanVars (initialize regardless of OS, then set default for current OS)
        if platform.system() == "Windows":
            self.var_uac_admin = BooleanVar(value=False)
            self.var_uac_uiaccess = BooleanVar(value=False)
            # Other Windows-specific entry variables will be initialized via self.entry_xxx = ttk.Entry(...)
        elif platform.system() == "Darwin":
            self.var_target_arch = StringVar(value="auto")
            # Other macOS-specific entry variables will be initialized via self.entry_xxx = ttk.Entry(...)

        self.additional_files_list = []
        self.hidden_modules_list = []
        self.imports_node = None
        self.files_node = None
        self.config_file = "spec_generator_config.json"

        # New variables for tool availability
        self.pyinstaller_available = False
        self.upx_available = False
        self.current_process = None  # To store the running subprocess for abortion

        # Now call setup_ui after all necessary variables are initialized
        self.setup_ui()

        self.load_config()
        # Initial checks on startup are now explicitly called AFTER setup_ui
        # to ensure all widgets are fully initialized.
        self.check_pyinstaller_availability()
        self.check_upx_availability()

    def setup_ui(self):
        self.root.title("PyInstaller Spec File Generator v2.0")
        self.root.geometry("1200x850")  # Increased size for more options
        self.root.configure(bg="#f0f4f8")

        # Configure styles
        self.setup_styles()

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root, style="Custom.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Main tab
        self.main_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text="Main")

        # Advanced tab
        self.advanced_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.advanced_frame, text="Advanced")

        # Build tab
        self.build_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.build_frame, text="Build")

        # Call setup methods for each tab
        self.setup_main_tab()
        self.setup_advanced_tab()
        self.setup_build_tab()

    def setup_styles(self):
        style = ttk.Style()

        # General Treeview style (from previous code, ensures readability)
        style.configure("Treeview", background="#ffffff", fieldbackground="#ffffff", foreground="#333333")
        style.configure("Treeview.Heading", background="#4a90e2", foreground="#ffffff", font=("Arial", 10, "bold"))
        style.map("Treeview", background=[("selected", "#4a90e2")], foreground=[("selected", "#ffffff")])

        # --- Notebook Tab Highlighting Styles ---
        style.configure("Custom.TNotebook",
                        background="#f0f0f0",
                        bordercolor="#cccccc",
                        lightcolor="#f0f0f0",
                        darkcolor="#e0e0e0",
                        tabposition="nw")

        style.configure("Custom.TNotebook.Tab",
                        background="#e0e0e0",
                        foreground="#333333",
                        padding=[8, 4],
                        font=("Arial", 10))  # Base font not bold

        style.map("Custom.TNotebook.Tab",
                  background=[("selected", "#ffffff")],
                  foreground=[("selected", "#000000")],
                  font=[("selected", ("Arial", 10, "bold"))]  # Bold only when selected
                  )

        style.layout("Custom.TNotebook.Tab",
                     [("Custom.TNotebook.tab",
                       {"sticky": "nswe",
                        "children": [("Custom.TNotebook.padding",
                                      {"sticky": "nswe",
                                       "children": [("Custom.TNotebook.focus",
                                                     {"sticky": "nswe",
                                                      "children": [("Custom.TNotebook.label", {"sticky": "nswe"})]
                                                      })
                                                    ]
                                       })
                                     ]
                        })]
                     )

        style.configure("Custom.TNotebook.padding",
                        bordercolor="#e0e0e0",
                        borderwidth=0,  # Default to 0 to prevent visible border when not selected
                        relief="flat"
                        )

        style.map("Custom.TNotebook.padding",
                  bordercolor=[("selected", "green")],
                  borderwidth=[("selected", 2)],
                  relief=[("selected", "solid")]
                  )
        # --- End Notebook Tab Highlighting Styles ---

        # --- Abort Button Red Style ---
        # FIX: Explicitly set foreground for the normal state
        style.configure("Abort.TButton",
                        background="red",
                        foreground="white",  # This ensures text is white in normal state
                        font=("Arial", 10, "bold"))
        style.map("Abort.TButton",
                  background=[("disabled", "#d3d3d3")],  # Light grey for disabled
                  foreground=[("disabled", "#808080")]  # Darker grey for disabled foreground
                  )
        # --- End Abort Button Red Style ---

    def setup_main_tab(self):
        # File selection frame
        file_frame = ttk.LabelFrame(self.main_frame, text="Script Selection")
        file_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(file_frame, text="Python Script:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.entry_path = ttk.Entry(file_frame, width=50)
        self.entry_path.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.select_file).grid(row=0, column=2, padx=5, pady=5)

        # var_show_paths initialized in __init__
        ttk.Checkbutton(file_frame, text="Show Full Paths", variable=self.var_show_paths,
                        command=self.refresh_analysis).grid(row=0, column=3, padx=5, pady=5)

        # var_recursive_scan initialized in __init__
        ttk.Checkbutton(file_frame, text="Recursive Import Scan",
                        variable=self.var_recursive_scan).grid(row=1, column=1, sticky="w", padx=5, pady=5)

        file_frame.columnconfigure(1, weight=1)

        # Files and modules frame
        self.files_frame = ttk.LabelFrame(self.main_frame, text="Additional Files & Modules")
        self.files_frame.pack(fill="x", padx=10, pady=5)

        # Buttons row
        btn_frame = ttk.Frame(self.files_frame)
        btn_frame.pack(fill="x", padx=5, pady=5)

        self.btn_add_files = ttk.Button(btn_frame, text="Add Files", command=self.add_additional_files)
        self.btn_add_files.pack(side="left", padx=5)
        self.btn_add_directory = ttk.Button(btn_frame, text="Add Directory", command=self.add_directory)
        self.btn_add_directory.pack(side="left", padx=5)
        self.btn_auto_detect = ttk.Button(btn_frame, text="Auto-detect Assets", command=self.auto_detect_assets)
        self.btn_auto_detect.pack(side="left", padx=5)

        # Hook directory
        hook_frame = ttk.Frame(self.files_frame)
        hook_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(hook_frame, text="Hook Directory:").pack(side="left", padx=5)
        self.entry_hook_dir = ttk.Entry(hook_frame, width=30)
        self.entry_hook_dir.pack(side="left", fill="x", expand=True, padx=5)
        self.btn_browse_hook = ttk.Button(hook_frame, text="Browse", command=self.add_hook_dir)
        self.btn_browse_hook.pack(side="left", padx=5)

        # Hidden modules
        hidden_frame = ttk.Frame(self.files_frame)
        hidden_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(hidden_frame, text="Hidden Module:").pack(side="left", padx=5)
        self.entry_hidden_module = ttk.Entry(hidden_frame, width=30)
        self.entry_hidden_module.pack(side="left", fill="x", expand=True, padx=5)
        self.entry_hidden_module.bind("<Return>", lambda e: self.add_hidden_module())
        self.btn_add_hidden_module = ttk.Button(hidden_frame, text="Add", command=self.add_hidden_module)
        self.btn_add_hidden_module.pack(side="left", padx=5)

        # Analysis treeview
        self.tree_frame = ttk.LabelFrame(self.main_frame, text="Analysis Results")
        self.tree_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Add search functionality
        search_frame = ttk.Frame(self.tree_frame)
        search_frame.pack(fill="x", padx=5, pady=2)
        ttk.Label(search_frame, text="Search:").pack(side="left", padx=5)
        # search_var initialized in __init__
        self.search_var.trace("w", self.filter_tree)
        self.entry_search = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.entry_search.pack(side="left", padx=5)

        self.tree = ttk.Treeview(self.tree_frame, columns=("Type", "Status"), show="tree headings")
        self.tree.heading("#0", text="Name")
        self.tree.heading("Type", text="Type")
        self.tree.heading("Status", text="Status")

        # Add scrollbars
        v_scroll = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        h_scroll = ttk.Scrollbar(self.tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        v_scroll.pack(side="right", fill="y")
        h_scroll.pack(side="bottom", fill="x")

        # Context menu for tree
        self.tree_menu = tk.Menu(self.root, tearoff=0)
        self.tree_menu.add_command(label="Remove", command=self.remove_selected_item)
        self.tree_menu.add_command(label="Edit", command=self.edit_selected_item)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Buttons frame
        self.buttons_frame = ttk.Frame(self.main_frame)
        self.buttons_frame.pack(fill="x", padx=10, pady=5)

        self.btn_generate_spec = ttk.Button(self.buttons_frame, text="Generate Spec", command=self.generate_spec)
        self.btn_generate_spec.pack(side="left", padx=5)
        self.btn_validate_spec = ttk.Button(self.buttons_frame, text="Validate Spec", command=self.validate_spec)
        self.btn_validate_spec.pack(side="left", padx=5)
        self.btn_save_config = ttk.Button(self.buttons_frame, text="Save Config", command=self.save_config)
        self.btn_save_config.pack(side="left", padx=5)
        self.btn_load_config = ttk.Button(self.buttons_frame, text="Load Config", command=self.load_config_dialog)
        self.btn_load_config.pack(side="left", padx=5)

        # PyInstaller/UPX check and install buttons
        check_tools_frame = ttk.LabelFrame(self.main_frame, text="Tool Availability")
        check_tools_frame.pack(fill="x", padx=10, pady=5)

        self.btn_check_pyinstaller = ttk.Button(check_tools_frame, text="Check PyInstaller",
                                                command=self.check_pyinstaller_availability)
        self.btn_check_pyinstaller.pack(side="left", padx=5)
        self.btn_install_pyinstaller = ttk.Button(check_tools_frame, text="Install PyInstaller (pip)",
                                                  command=self.install_pyinstaller_via_pip, state="disabled")
        self.btn_install_pyinstaller.pack(side="left", padx=5)

        self.btn_check_upx = ttk.Button(check_tools_frame, text="Check UPX", command=self.check_upx_availability)
        self.btn_check_upx.pack(side="left", padx=5)
        self.btn_download_upx = ttk.Button(check_tools_frame, text="Download UPX", command=self.download_and_setup_upx,
                                           state="disabled")
        self.btn_download_upx.pack(side="left", padx=5)

        ttk.Label(check_tools_frame, text="UPX Path:").pack(side="left", padx=5)
        # upx_custom_path initialized in __init__
        self.entry_upx_path = ttk.Entry(check_tools_frame, textvariable=self.upx_custom_path, width=30,
                                        state="disabled")
        self.entry_upx_path.pack(side="left", fill="x", expand=True, padx=5)
        self.btn_browse_upx_path = ttk.Button(check_tools_frame, text="Browse", command=self.browse_upx_path,
                                              state="disabled")
        self.btn_browse_upx_path.pack(side="left", padx=5)

    def setup_advanced_tab(self):
        # Compilation options
        self.options_frame = ttk.LabelFrame(self.advanced_frame, text="Compilation Options")
        self.options_frame.pack(fill="x", padx=10, pady=5)

        # Basic options
        basic_frame = ttk.Frame(self.options_frame)
        basic_frame.pack(fill="x", padx=5, pady=5)

        # BooleanVars initialized in __init__
        self.chk_debug = ttk.Checkbutton(basic_frame, text="Debug Mode", variable=self.var_debug)
        self.chk_debug.grid(row=0, column=0, sticky="w", padx=5)
        self.chk_console = ttk.Checkbutton(basic_frame, text="Console Window", variable=self.var_console)
        self.chk_console.grid(row=0, column=1, sticky="w", padx=5)
        self.chk_onefile = ttk.Checkbutton(basic_frame, text="One File", variable=self.var_onefile)
        self.chk_onefile.grid(row=1, column=0, sticky="w", padx=5)
        self.chk_windowed = ttk.Checkbutton(basic_frame, text="Windowed", variable=self.var_windowed)
        self.chk_windowed.grid(row=1, column=1, sticky="w", padx=5)
        self.chk_upx = ttk.Checkbutton(basic_frame, text="UPX Compression", variable=self.var_upx)
        self.chk_upx.grid(row=2, column=0, sticky="w", padx=5)

        # Advanced options
        self.adv_frame = ttk.LabelFrame(self.advanced_frame, text="Advanced Options")
        self.adv_frame.pack(fill="x", padx=10, pady=5)

        # BooleanVars initialized in __init__
        self.chk_strip = ttk.Checkbutton(self.adv_frame, text="Strip Debug Symbols", variable=self.var_strip)
        self.chk_strip.grid(row=0, column=0, sticky="w", padx=5)
        self.chk_noarchive = ttk.Checkbutton(self.adv_frame, text="No Archive", variable=self.var_noarchive)
        self.chk_noarchive.grid(row=0, column=1, sticky="w", padx=5)

        ttk.Label(self.adv_frame, text="Optimization Level:").grid(row=1, column=0, sticky="w", padx=5)
        self.spin_optimize = ttk.Spinbox(self.adv_frame, from_=0, to=2, textvariable=self.var_optimize, width=10)
        self.spin_optimize.grid(row=1, column=1, sticky="w", padx=5)

        # Platform-specific options
        self.setup_platform_specific_options()

    def setup_platform_specific_options(self):
        # Icon and version info (general)
        self.info_frame = ttk.LabelFrame(self.advanced_frame, text="Application Info (Cross-Platform)")
        self.info_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(self.info_frame, text="Icon File:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.entry_icon = ttk.Entry(self.info_frame, width=40)
        self.entry_icon.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        self.btn_browse_icon = ttk.Button(self.info_frame, text="Browse", command=self.select_icon)
        self.btn_browse_icon.grid(row=0, column=2, padx=5, pady=2)

        # Windows Specific Options
        if platform.system() == "Windows":
            self.win_options_frame = ttk.LabelFrame(self.advanced_frame, text="Windows Specific Options")
            self.win_options_frame.pack(fill="x", padx=10, pady=5)

            # Version Info File
            ttk.Label(self.win_options_frame, text="Version Info File:").grid(row=0, column=0, sticky="w", padx=5,
                                                                              pady=2)
            self.entry_version = ttk.Entry(self.win_options_frame, width=40)
            self.entry_version.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
            self.btn_browse_version = ttk.Button(self.win_options_frame, text="Browse",
                                                 command=self.select_version_file)
            self.btn_browse_version.grid(row=0, column=2, padx=5, pady=2)

            # Manifest
            ttk.Label(self.win_options_frame, text="Manifest File/XML:").grid(row=1, column=0, sticky="w", padx=5,
                                                                              pady=2)
            self.entry_manifest = ttk.Entry(self.win_options_frame, width=40)
            self.entry_manifest.grid(row=1, column=1, sticky="ew", padx=5, pady=2)
            self.btn_browse_manifest = ttk.Button(self.win_options_frame, text="Browse",
                                                  command=lambda: self.select_file_for_entry(self.entry_manifest, [
                                                      ("Manifest Files", "*.manifest *.xml"), ("All Files", "*.*")]))
            self.btn_browse_manifest.grid(row=1, column=2, padx=5, pady=2)

            # UAC Options (BooleanVars initialized in __init__)
            self.chk_uac_admin = ttk.Checkbutton(self.win_options_frame, text="UAC Admin", variable=self.var_uac_admin)
            self.chk_uac_admin.grid(row=2, column=0, sticky="w", padx=5)

            self.chk_uac_uiaccess = ttk.Checkbutton(self.win_options_frame, text="UAC UI Access",
                                                    variable=self.var_uac_uiaccess)
            self.chk_uac_uiaccess.grid(row=2, column=1, sticky="w", padx=5)

            self.win_options_frame.columnconfigure(1, weight=1)

        # macOS Specific Options
        elif platform.system() == "Darwin":
            self.mac_options_frame = ttk.LabelFrame(self.advanced_frame, text="macOS Specific Options")
            self.mac_options_frame.pack(fill="x", padx=10, pady=5)

            # Bundle Identifier
            ttk.Label(self.mac_options_frame, text="Bundle Identifier:").grid(row=0, column=0, sticky="w", padx=5,
                                                                              pady=2)
            self.entry_bundle_identifier = ttk.Entry(self.mac_options_frame, width=40)
            self.entry_bundle_identifier.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

            # Codesign Identity
            ttk.Label(self.mac_options_frame, text="Codesign Identity:").grid(row=1, column=0, sticky="w", padx=5,
                                                                              pady=2)
            self.entry_codesign_identity = ttk.Entry(self.mac_options_frame, width=40)
            self.entry_codesign_identity.grid(row=1, column=1, sticky="ew", padx=5, pady=2)

            # Entitlements File
            ttk.Label(self.mac_options_frame, text="Entitlements File:").grid(row=2, column=0, sticky="w", padx=5,
                                                                              pady=2)
            self.entry_entitlements_file = ttk.Entry(self.mac_options_frame, width=40)
            self.entry_entitlements_file.grid(row=2, column=1, sticky="ew", padx=5, pady=2)
            self.btn_browse_entitlements = ttk.Button(self.mac_options_frame, text="Browse",
                                                      command=lambda: self.select_file_for_entry(
                                                          self.entry_entitlements_file,
                                                          [("Entitlements Files", "*.entitlements"),
                                                           ("All Files", "*.*")]))
            self.btn_browse_entitlements.grid(row=2, column=2, padx=5, pady=2)

            # Target Architecture (StringVar initialized in __init__)
            ttk.Label(self.mac_options_frame, text="Target Architecture:").grid(row=3, column=0, sticky="w", padx=5,
                                                                                pady=2)
            self.opt_target_arch = ttk.OptionMenu(self.mac_options_frame, self.var_target_arch, "auto", "x86_64",
                                                  "arm64", "universal2")
            self.opt_target_arch.grid(row=3, column=1, sticky="ew", padx=5, pady=2)

            self.mac_options_frame.columnconfigure(1, weight=1)

    def select_file_for_entry(self, entry_widget, filetypes):
        file_path = filedialog.askopenfilename(title="Select File", filetypes=filetypes)
        if file_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, file_path)

    def setup_build_tab(self):
        # Build commands
        self.build_frame_controls = ttk.LabelFrame(self.build_frame, text="Build Commands")
        self.build_frame_controls.pack(fill="x", padx=10, pady=5)

        self.btn_build_from_spec = ttk.Button(self.build_frame_controls, text="Build from Spec",
                                              command=self.build_from_spec)
        self.btn_build_from_spec.pack(side="left", padx=5, pady=5)
        self.btn_quick_build = ttk.Button(self.build_frame_controls, text="Quick Build (py to exe)",
                                          command=self.quick_build)
        self.btn_quick_build.pack(side="left", padx=5, pady=5)
        self.btn_clean_build = ttk.Button(self.build_frame_controls, text="Clean Build", command=self.clean_build)
        self.btn_clean_build.pack(side="left", padx=5, pady=5)

        # Abort Build Button
        self.btn_abort_build = ttk.Button(self.build_frame_controls, text="Abort Build", command=self.abort_build,
                                          state="disabled", style="Abort.TButton")
        self.btn_abort_build.pack(side="right", padx=5, pady=5)  # Place on the right

        # Progress frame
        progress_frame = ttk.Frame(self.build_frame)
        progress_frame.pack(fill="both", expand=True, padx=10, pady=5)

        ttk.Label(progress_frame, text="Build Progress:").pack(fill="x", padx=5, pady=2)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, mode='indeterminate')
        self.progress_bar.pack(fill="x", padx=5, pady=5)

        ttk.Label(progress_frame, text="Build Output:").pack(fill="x", padx=5, pady=2)
        self.output_text = tk.Text(progress_frame, height=20, wrap="word")
        output_scroll = ttk.Scrollbar(progress_frame, orient="vertical", command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=output_scroll.set)

        self.output_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        output_scroll.pack(side="right", fill="y")

    def enable_pyinstaller_features(self, enable):
        """Enables or disables PyInstaller-dependent UI elements."""
        state = "normal" if enable else "disabled"

        self.btn_generate_spec.config(state=state)
        self.btn_validate_spec.config(state=state)
        self.btn_build_from_spec.config(state=state)
        self.btn_quick_build.config(state=state)
        self.btn_clean_build.config(state=state)
        # Abort button state is managed dynamically by run_pyinstaller

        # Main tab controls for additional files/modules
        self.btn_add_files.config(state=state)
        self.btn_add_directory.config(state=state)
        self.btn_auto_detect.config(state=state)
        self.entry_hook_dir.config(state=state)
        self.btn_browse_hook.config(state=state)
        self.entry_hidden_module.config(state=state)
        self.btn_add_hidden_module.config(state=state)
        self.entry_search.config(state=state)

        # Advanced tab controls
        self.chk_debug.config(state=state)
        self.chk_console.config(state=state)
        self.chk_onefile.config(state=state)
        self.chk_windowed.config(state=state)
        self.chk_strip.config(state=state)
        self.chk_noarchive.config(state=state)
        self.spin_optimize.config(state=state)
        self.entry_icon.config(state=state)
        self.btn_browse_icon.config(state=state)

        # Platform-specific controls
        if platform.system() == "Windows":
            # Check if attributes exist before configuring (setup_platform_specific_options creates them)
            if hasattr(self, 'entry_version'):
                self.entry_version.config(state=state)
                self.btn_browse_version.config(state=state)
            if hasattr(self, 'entry_manifest'):
                self.entry_manifest.config(state=state)
                self.btn_browse_manifest.config(state=state)
            if hasattr(self, 'chk_uac_admin'):
                self.chk_uac_admin.config(state=state)
            if hasattr(self, 'chk_uac_uiaccess'):
                self.chk_uac_uiaccess.config(state=state)
        elif platform.system() == "Darwin":
            if hasattr(self, 'entry_bundle_identifier'):
                self.entry_bundle_identifier.config(state=state)
                self.entry_codesign_identity.config(state=state)
                self.entry_entitlements_file.config(state=state)
                self.btn_browse_entitlements.config(state=state)
                self.opt_target_arch.config(state=state)

        # Install/Download buttons enable/disable
        self.btn_install_pyinstaller.config(
            state="disabled" if enable else "normal")  # Enable install button if PyInstaller is NOT available
        # self.btn_download_upx.config(state="disabled" if enable else "normal") # Initially disable, actual state handled by UPX check

        # If PyInstaller is disabled, disable UPX checkbox and related controls too
        if not enable:
            self.enable_upx_feature(False)
        else:  # If PyInstaller is enabled, re-check and enable UPX if available
            self.enable_upx_feature(self.upx_available)

    def enable_upx_feature(self, enable):
        """Enables or disables the UPX compression checkbox and custom UPX path entry."""
        # UPX checkbox should only be enabled if PyInstaller is also available AND UPX itself is enabled
        self.chk_upx.config(state="normal" if enable and self.pyinstaller_available else "disabled")
        self.entry_upx_path.config(state="normal" if enable and self.pyinstaller_available else "disabled")
        self.btn_browse_upx_path.config(state="normal" if enable and self.pyinstaller_available else "disabled")

        # Only enable download UPX button if UPX is not available (self.upx_available is False) AND PyInstaller is available
        self.btn_download_upx.config(
            state="normal" if self.pyinstaller_available and not self.upx_available else "disabled")

        if not enable:
            self.var_upx.set(False)  # Uncheck UPX if not available

    def _check_internet_connectivity(self):
        """Basic check for internet connectivity."""
        try:
            urllib.request.urlopen('http://www.google.com', timeout=1)
            return True
        except urllib.error.URLError:
            return False
        except Exception:
            return False

    def check_pyinstaller_availability(self):
        """Checks if PyInstaller is installed and available. Offers to install if not found."""
        self.log_output("Checking PyInstaller availability...")
        try:
            import PyInstaller
            version_output = PyInstaller.__version__

            self.pyinstaller_available = True
            self.log_output(f"PyInstaller found: Version {version_output}. PyInstaller features enabled.")
            self.enable_pyinstaller_features(True)  # This will enable UPX if it's found
            messagebox.showinfo("PyInstaller Found",
                                f"PyInstaller is successfully detected.\nVersion: {version_output}")
        except ImportError:
            self.pyinstaller_available = False
            self.log_output(f"PyInstaller not found for '{sys.executable}'.")
            self.enable_pyinstaller_features(False)  # This will also enable the install button

            messagebox.showwarning(
                "PyInstaller Missing",
                f"PyInstaller is not installed for this Python interpreter:\n{sys.executable}\n\n"
                "You can install it using the 'Install PyInstaller (pip)' button."
            )
        except Exception as e:
            self.pyinstaller_available = False
            self.log_output(f"Error checking PyInstaller: {e}. PyInstaller features disabled.")
            messagebox.showerror("PyInstaller Check Error",
                                 f"An error occurred while checking PyInstaller: {e}\nPyInstaller features disabled.")
            self.enable_pyinstaller_features(False)

    def install_pyinstaller_via_pip(self):
        """Attempts to install PyInstaller using pip in a separate thread."""
        if not self._check_internet_connectivity():
            messagebox.showerror("No Internet", "No internet connection detected. Cannot install PyInstaller.")
            return

        def run_install():
            self.log_output("Attempting to install PyInstaller...")
            self.progress_bar.start()
            self._set_build_controls_state("disabled")  # Disable relevant buttons during installation
            self.btn_install_pyinstaller.config(state="disabled")  # Disable itself during install
            self.btn_check_pyinstaller.config(state="disabled")  # Disable check button during install

            try:
                install_cmd = [sys.executable, "-m", "pip", "install", "pyinstaller"]

                process = subprocess.Popen(
                    install_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )

                for line in process.stdout:
                    self.log_output(line.strip())

                process.wait()

                if process.returncode == 0:
                    self.log_output("PyInstaller installed successfully!")
                    messagebox.showinfo("Installation Complete",
                                        "PyInstaller has been successfully installed. Re-checking availability.")
                else:
                    self.log_output(f"PyInstaller installation failed with return code {process.returncode}.")
                    messagebox.showerror("Installation Failed",
                                         f"PyInstaller installation failed. Check the output log for details (return code {process.returncode}).")
            except Exception as e:
                self.log_output(f"Error during PyInstaller installation: {e}")
                messagebox.showerror("Installation Error", f"An error occurred during installation: {e}")
            finally:
                self.progress_bar.stop()
                self._set_build_controls_state("normal")  # Re-enable controls
                self.btn_check_pyinstaller.config(state="normal")  # Re-enable check button
                self.check_pyinstaller_availability()  # Re-check PyInstaller availability after installation attempt

        thread = threading.Thread(target=run_install, daemon=True)
        thread.start()

    def browse_upx_path(self):
        """Allows user to browse for UPX directory."""
        upx_dir = filedialog.askdirectory(title="Select UPX Executable Directory")
        if upx_dir:
            upx_exec_name = "upx.exe" if platform.system() == "Windows" else "upx"
            if os.path.exists(os.path.join(upx_dir, upx_exec_name)):
                self.upx_custom_path.set(upx_dir)
                self.upx_available = True
                self.log_output(f"UPX found at custom path: {upx_dir}. UPX compression enabled.")
                self.enable_upx_feature(True)
                messagebox.showinfo("UPX Found", f"UPX is successfully detected at: {upx_dir}")
            else:
                messagebox.showwarning("UPX Not Found",
                                       f"No UPX executable ('{upx_exec_name}') found in the selected directory: {upx_dir}")
                # Don't clear upx_custom_path automatically here, let the user decide.
                # It will be checked again by check_upx_availability on next run.
                self.upx_available = False
                self.enable_upx_feature(False)

    def check_upx_availability(self):
        """Checks if UPX is in system PATH or custom path."""
        if not self.pyinstaller_available:
            self.log_output("PyInstaller is not available, cannot use UPX.")
            self.enable_upx_feature(False)
            return

        self.log_output("Checking UPX availability...")
        upx_found_via_path = False
        upx_found_via_custom_path = False
        upx_version = "Unknown"
        upx_exec_name = "upx.exe" if platform.system() == "Windows" else "upx"

        # 1. Check system PATH first
        try:
            result = subprocess.run(["upx", "--version"], capture_output=True, check=True, text=True, timeout=5)
            upx_version_match = re.search(r"UPX\s+(\d+\.\d+(\.\d+)?)", result.stdout)
            upx_version = upx_version_match.group(1) if upx_version_match else "Unknown"
            upx_found_via_path = True

        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self.log_output(f"UPX not found in system PATH or command failed: {e}")
        except Exception as e:
            self.log_output(f"Unexpected error when checking UPX in system PATH: {e}")

        # 2. Check if a custom path is set and valid (only if not found in system PATH)
        if not upx_found_via_path and self.upx_custom_path.get():
            custom_upx_full_path = os.path.join(self.upx_custom_path.get(), upx_exec_name)
            if os.path.exists(custom_upx_full_path):
                try:
                    result = subprocess.run([custom_upx_full_path, "--version"], capture_output=True, check=True,
                                            text=True, timeout=5)
                    upx_version_match = re.search(r"UPX\s+(\d+\.\d+(\.\d+)?)", result.stdout)
                    upx_version = upx_version_match.group(1) if upx_version_match else "Unknown"
                    upx_found_via_custom_path = True
                except Exception as e:
                    self.log_output(
                        f"Error checking UPX at custom path {self.upx_custom_path.get()}: {e}. Clearing custom path.")
                    self.upx_custom_path.set("")  # Clear invalid custom path

        self.upx_available = upx_found_via_path or upx_found_via_custom_path

        if self.upx_available:
            self.log_output(f"UPX found: Version {upx_version}. UPX compression enabled.")
            self.enable_upx_feature(True)
            messagebox.showinfo("UPX Found", f"UPX is successfully detected.\nVersion: {upx_version}")
        else:
            self.log_output("UPX not available. Please download and add to PATH or specify custom path.")
            self.enable_upx_feature(False)  # Ensure UI reflects unavailable state
            messagebox.showwarning(
                "UPX Missing",
                "UPX executable ('upx.exe' or 'upx') not found.\n"
                "You can download it using the 'Download UPX' button, or manually specify its path."
            )

    def download_and_setup_upx(self):
        """Downloads and sets up UPX for the detected OS/architecture."""
        if not self._check_internet_connectivity():
            messagebox.showerror("No Internet", "No internet connection detected. Cannot download UPX.")
            return

        system = platform.system()
        machine = platform.machine()

        upx_url = None
        upx_archive_name = None
        upx_exec_in_archive_path = None  # Path within the archive to the executable
        upx_extract_name = "upx"  # Default executable name

        # Determine UPX download URL based on OS and architecture (using v4.0.2 which is stable)
        # Check https://github.com/upx/upx/releases for latest versions if needed
        if system == "Windows":
            if machine.endswith("64"):
                upx_url = "https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-win64.zip"
                upx_archive_name = "upx-4.0.2-win64.zip"
                upx_exec_in_archive_path = "upx-4.0.2-win64/upx.exe"
            elif machine.endswith("32"):
                upx_url = "https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-win32.zip"
                upx_archive_name = "upx-4.0.2-win32.zip"
                upx_exec_in_archive_path = "upx-4.0.2-win32/upx.exe"
            upx_extract_name = "upx.exe"
        elif system == "Linux":
            if machine == "x86_64":
                upx_url = "https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-amd64_linux.tar.xz"
                upx_archive_name = "upx-4.0.2-amd64_linux.tar.xz"
                upx_exec_in_archive_path = "upx-4.0.2-amd64_linux/upx"
            elif machine == "aarch64":  # ARM64 Linux
                upx_url = "https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-arm64_linux.tar.xz"
                upx_archive_name = "upx-4.0.2-arm64_linux.tar.xz"
                upx_exec_in_archive_path = "upx-4.0.2-arm64_linux/upx"
        elif system == "Darwin":  # macOS
            if machine == "x86_64":
                upx_url = "https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-amd64_mac.tar.xz"
                upx_archive_name = "upx-4.0.2-amd64_mac.tar.xz"
                upx_exec_in_archive_path = "upx-4.0.2-amd64_mac/upx"
            elif machine == "arm64":  # Apple Silicon
                upx_url = "https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-arm64_mac.tar.xz"
                upx_archive_name = "upx-4.0.2-arm64_mac.tar.xz"
                upx_exec_in_archive_path = "upx-4.0.2-arm64_mac/upx"

        if not upx_url:
            messagebox.showerror("Unsupported OS/Arch",
                                 f"UPX download not supported for your OS ({system}) or architecture ({machine}).")
            self.log_output(f"UPX download not supported for {system}/{machine}.")
            return

        def run_download_setup():
            self.log_output(f"Attempting to download and setup UPX from: {upx_url}")
            self.progress_bar.start()
            self._set_build_controls_state("disabled")  # Disable main controls
            self.btn_download_upx.config(state="disabled")  # Disable itself during download
            self.btn_check_upx.config(state="disabled")  # Disable check UPX button

            temp_dir = Path.home() / ".spec_gen_temp"
            temp_dir.mkdir(exist_ok=True)
            archive_path = temp_dir / upx_archive_name
            upx_install_dir = Path.home() / ".upx_local"  # Use a distinct local path

            try:
                # Download
                urllib.request.urlretrieve(upx_url, archive_path)
                self.log_output(f"Downloaded UPX to {archive_path}")

                # Clean previous install dir if it exists
                if upx_install_dir.exists():
                    shutil.rmtree(upx_install_dir)
                upx_install_dir.mkdir(exist_ok=True)

                # Extract
                if system == "Windows":
                    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                        # Find the correct member in the zip file
                        members_to_extract = [m for m in zip_ref.namelist() if
                                              Path(m) == Path(upx_exec_in_archive_path)]
                        if not members_to_extract:  # Fallback if specific path doesn't match
                            members_to_extract = [m for m in zip_ref.namelist() if m.endswith(upx_extract_name)]

                        if members_to_extract:
                            zip_ref.extract(members_to_extract[0], path=temp_dir)
                            # Move upx.exe to .upx_local folder
                            shutil.move(temp_dir / members_to_extract[0], upx_install_dir / upx_extract_name)
                        else:
                            raise ValueError(
                                f"Could not find '{upx_extract_name}' or '{upx_exec_in_archive_path}' in UPX zip file.")
                else:  # Linux, macOS (tar.xz)
                    with tarfile.open(archive_path, 'r:xz') as tar_ref:
                        # Find the correct member in the tar file
                        members_to_extract = [m for m in tar_ref.getnames() if
                                              Path(m) == Path(upx_exec_in_archive_path)]
                        if not members_to_extract:
                            members_to_extract = [m for m in tar_ref.getnames() if m.endswith(upx_extract_name)]

                        if members_to_extract:
                            tar_ref.extract(members_to_extract[0], path=temp_dir)
                            # Move upx executable to .upx_local folder
                            shutil.move(temp_dir / members_to_extract[0], upx_install_dir / upx_extract_name)
                            os.chmod(upx_install_dir / upx_extract_name, 0o755)  # Make executable
                        else:
                            raise ValueError(
                                f"Could not find '{upx_extract_name}' or '{upx_exec_in_archive_path}' in UPX tar.xz file.")

                self.log_output(f"UPX extracted to {upx_install_dir}")

                # Clean up temp files
                archive_path.unlink(missing_ok=True)
                if temp_dir.exists() and temp_dir.is_dir():
                    shutil.rmtree(temp_dir)

                self.upx_custom_path.set(str(upx_install_dir))  # Automatically set custom path entry

                response = messagebox.askyesno(
                    "UPX Setup Complete",
                    f"UPX has been downloaded and extracted to:\n{upx_install_dir}\n\n"
                    "The custom UPX path has been set. You can now use UPX compression.\n\n"
                    "Would you like to add this directory to your system's PATH environmental variable?\n"
                    "(This usually requires administrator privileges and a system restart to take full effect. If you select No, the path is set in the 'UPX Path' field.)"
                )
                if response:
                    messagebox.showinfo(
                        "Add to PATH Manually",
                        f"Please manually add the following path to your system's PATH environmental variable:\n\n{upx_install_dir}\n\n"
                        "You might need to restart your computer for changes to take effect system-wide. Until then, the path is set in the 'UPX Path' field."
                    )

            except Exception as e:
                self.log_output(f"Error during UPX download/setup: {e}")
                messagebox.showerror("UPX Download Error",
                                     f"An error occurred during UPX download or setup: {e}\nCheck the log for details.")
                # Clean up potentially partial downloads/extractions
                if upx_install_dir.exists():
                    shutil.rmtree(upx_install_dir)
                if temp_dir.exists():
                    shutil.rmtree(temp_dir)
                self.upx_custom_path.set("")  # Clear path if download/setup failed
            finally:
                self.progress_bar.stop()
                self._set_build_controls_state("normal")  # Re-enable controls
                self.check_upx_availability()  # Re-check UPX availability to update UI state

        thread = threading.Thread(target=run_download_setup, daemon=True)
        thread.start()

    def extract_imports_and_files(self, script_path, recursive=True):
        """Enhanced import and file extraction with recursive scanning"""
        imports = set()
        files = set()

        def scan_file(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()

                # Extract imports
                import_patterns = [
                    r'^\s*import\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)',
                    r'^\s*from\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s+import',
                    r'__import__\([\'"]([^\'\"]+)[\'"]'
                ]

                for pattern in import_patterns:
                    matches = re.findall(pattern, content, re.MULTILINE)
                    imports.update(matches)

                # Extract file paths
                file_patterns = [
                    r'[\'"]([^\'\"]+\.(?:json|png|gif|jpg|jpeg|dat|ttf|ogg|story|wav|txt|bin|xml|csv|xlsx|pdf|ico|bmp|svg))[\'"]',
                    r'open\s*\(\s*[\'"]([^\'\"]+)[\'"]',
                    r'Path\s*\(\s*[\'"]([^\'\"]+)[\'"]'
                ]

                for pattern in file_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if not any(c in '()[]{}|?*^<>' for c in match):
                            files.add(match)

                # Recursive scanning for imported local modules
                if recursive:
                    script_dir = os.path.dirname(file_path)  # Use file_path, not script_path directly from function arg
                    for imp in list(
                            imports):  # Iterate over a copy to allow modification if needed, though not strictly modifying `imports` here.
                        if '.' not in imp:
                            local_file = os.path.join(script_dir, f"{imp}.py")
                            if os.path.exists(local_file):
                                scan_file(local_file)

            except Exception as e:
                self.log_output(f"Error scanning {file_path}: {str(e)}")

        scan_file(script_path)

        # Process file paths
        processed_files = []
        for file_path in files:
            if self.var_show_paths.get():
                processed_files.append(file_path)
            else:
                processed_files.append(os.path.basename(file_path))

        return sorted(list(imports)), sorted(processed_files)

    def auto_detect_assets(self):
        """Auto-detect common asset directories and files"""
        script_path = self.entry_path.get()
        if not script_path:
            messagebox.showwarning("Warning", "Please select a Python script first.")
            return

        script_dir = os.path.dirname(script_path)
        asset_dirs = ['assets', 'data', 'resources', 'images', 'sounds', 'fonts', 'configs']
        asset_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.wav', '.ogg', '.mp3', '.ttf', '.json', '.xml', '.csv']

        found_files = []
        for asset_dir in asset_dirs:
            asset_path = os.path.join(script_dir, asset_dir)
            if os.path.exists(asset_path):
                for root, dirs, files in os.walk(asset_path):
                    for file in files:
                        if any(file.lower().endswith(ext) for ext in asset_extensions):
                            rel_path = os.path.relpath(os.path.join(root, file), script_dir)
                            found_files.append(rel_path)

        if found_files:
            for file_path in found_files:
                filename = os.path.basename(file_path) if not self.var_show_paths.get() else file_path
                if filename not in self.additional_files_list:
                    self.additional_files_list.append(filename)

            self.refresh_tree()
            messagebox.showinfo("Success", f"Found and added {len(found_files)} asset files.")
        else:
            messagebox.showinfo("No Assets", "No common asset files found.")

    def add_directory(self):
        """Add entire directory to data files"""
        directory = filedialog.askdirectory(title="Select Directory to Include")
        if directory:
            # Ensure path is relative to script directory if not showing full paths,
            # or keep it absolute if showing full paths.
            script_path = self.entry_path.get()
            if script_path and not self.var_show_paths.get():
                try:
                    dir_name = os.path.relpath(directory, os.path.dirname(script_path))
                except ValueError:  # handle case where directory is on different drive
                    dir_name = directory
            else:
                dir_name = directory

            # Add trailing slash to denote it's a directory
            if not dir_name.endswith('/'):
                dir_name += '/'

            if dir_name not in self.additional_files_list:
                self.additional_files_list.append(dir_name)
                self.refresh_tree()

    def filter_tree(self, *args):
        """Filter tree view based on search term"""
        search_term = self.search_var.get().lower()

        # Get all top-level items
        all_items = self.tree.get_children("")

        # First, ensure all items are detached to rebuild visibility
        for item in all_items:
            self.tree.detach(item)

        if not search_term:
            # Re-insert all items in their original order if search is empty
            for item in all_items:
                self.tree.insert("", "end", iid=item, text=self.tree.item(item, "text"),
                                 values=self.tree.item(item, "values"))
                # Recursively re-insert children
                self._reinsert_children(item)
            return

        # Perform search and re-insert only matching/parent items
        def matches(item_id):
            text = self.tree.item(item_id, "text").lower()
            return search_term in text

        def process_item(item_id, parent_id=""):
            has_child_match = False
            for child_id in self.tree.get_children(item_id):
                if process_item(child_id, item_id):
                    has_child_match = True

            if matches(item_id) or has_child_match:
                # If this item was previously detached (due to initial detach all), re-attach it
                if not self.tree.parent(item_id):
                    self.tree.insert(parent_id, "end", iid=item_id, text=self.tree.item(item_id, "text"),
                                     values=self.tree.item(item_id, "values"))
                self.tree.item(item_id, open=True)  # Open the item if it matches or has a matching child
                return True
            else:
                self.tree.detach(item_id)
                return False

        for item in all_items:
            process_item(item)

    def _reinsert_children(self, parent_id):
        """Helper to re-insert detached children for filter_tree"""
        for child_id in self.tree.get_children(parent_id):
            if not self.tree.parent(child_id):  # If it's not already re-inserted
                self.tree.insert(parent_id, "end", iid=child_id, text=self.tree.item(child_id, "text"),
                                 values=self.tree.item(child_id, "values"))
            self._reinsert_children(child_id)

    def show_context_menu(self, event):
        """Show context menu for tree items"""
        # Identify the item clicked
        item_id = self.tree.identify_row(event.y)
        if item_id:
            # Select the item
            self.tree.selection_set(item_id)
            self.tree_menu.post(event.x_root, event.y_root)

    def remove_selected_item(self):
        """Remove selected item from tree and lists"""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        text = self.tree.item(item, "text")
        item_type = self.tree.item(item, "values")[0] if self.tree.item(item, "values") else ""

        if item_type == "Additional File" or item_type == "Category":  # Category for directories
            if text.endswith('/'):  # It's a directory
                text_to_remove = text
            else:  # It's a file
                text_to_remove = text

            if text_to_remove in self.additional_files_list:
                self.additional_files_list.remove(text_to_remove)
            elif text_to_remove + '/' in self.additional_files_list:  # If it's a directory like "my_dir" but stored as "my_dir/"
                self.additional_files_list.remove(text_to_remove + '/')
            else:  # Try removing just the basename if full path was shown
                base_name_found = False
                for i, entry in enumerate(self.additional_files_list):
                    if os.path.basename(entry) == text_to_remove:
                        del self.additional_files_list[i]
                        base_name_found = True
                        break
                if not base_name_found:
                    messagebox.showwarning("Remove Item", f"Could not find '{text}' in additional files list.")
                    return
        elif item_type == "Hidden Module":
            if text in self.hidden_modules_list:
                self.hidden_modules_list.remove(text)
            else:
                messagebox.showwarning("Remove Item", f"Could not find '{text}' in hidden modules list.")
                return
        else:
            messagebox.showwarning("Remove Item",
                                   "Only 'Additional Files/Directories' and 'Hidden Modules' can be removed.")
            return

        self.tree.delete(item)
        self.refresh_tree()  # Re-render to ensure category nodes are correct after removal

    def edit_selected_item(self):
        """Edit selected item"""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        old_text = self.tree.item(item, "text")
        item_type = self.tree.item(item, "values")[0] if self.tree.item(item, "values") else ""

        if item_type not in ["Additional File", "Hidden Module", "Category"]:
            messagebox.showwarning("Edit Item",
                                   "Only 'Additional Files/Directories' and 'Hidden Modules' can be edited.")
            return

        new_text = tk.simpledialog.askstring("Edit Item", f"Edit item:", initialvalue=old_text)
        if new_text is None or new_text == old_text:  # User cancelled or didn't change
            return

        # Update in lists
        if item_type == "Additional File" or item_type == "Category":
            found = False
            for i, entry in enumerate(self.additional_files_list):
                if entry == old_text or entry == old_text + '/':  # Match both file and directory formats
                    self.additional_files_list[i] = new_text + ('/' if old_text.endswith('/') else '')
                    found = True
                    break
                elif self.var_show_paths.get() and os.path.basename(entry) == old_text:
                    # If full paths are shown, but we originally added basename
                    self.additional_files_list[i] = new_text + ('/' if old_text.endswith('/') else '')
                    found = True
                    break
            if not found:
                messagebox.showwarning("Edit Item", f"Could not find '{old_text}' in additional files list for update.")
                return

        elif item_type == "Hidden Module":
            try:
                idx = self.hidden_modules_list.index(old_text)
                self.hidden_modules_list[idx] = new_text
            except ValueError:
                messagebox.showwarning("Edit Item", f"Could not find '{old_text}' in hidden modules list for update.")
                return

        self.refresh_tree()  # Re-render to ensure tree accurately reflects changes

    def select_icon(self):
        """Select icon file"""
        icon_file = filedialog.askopenfilename(
            title="Select Icon File",
            filetypes=[("Icon Files", "*.ico *.png *.icns"), ("All Files", "*.*")]
        )
        if icon_file:
            self.entry_icon.delete(0, tk.END)
            self.entry_icon.insert(0, icon_file)

    def select_version_file(self):
        """Select version info file (for Windows only)"""
        version_file = filedialog.askopenfilename(
            title="Select Version File",
            filetypes=[("Version Files", "*.txt *.rc"), ("All Files", "*.*")]
        )
        if version_file:
            self.entry_version.delete(0, tk.END)
            self.entry_version.insert(0, version_file)

    def generate_spec_file(self, script_path, imports, files):
        """Generate enhanced spec file with advanced options"""
        script_name = os.path.splitext(os.path.basename(script_path))[0]
        hook_dir = self.entry_hook_dir.get().strip()
        hook_path = [hook_dir] if hook_dir else []

        # Combine extracted files with additional files
        all_files = list(set(files + self.additional_files_list))

        # Format files for PyInstaller
        formatted_files = []
        script_dir = os.path.dirname(script_path)
        for f in all_files:
            if self.var_show_paths.get() or os.path.isabs(f):
                source_path = f
            else:
                source_path = os.path.join(script_dir, f)

            if f.endswith('/'):
                formatted_files.append((source_path.rstrip('/'), os.path.basename(source_path.rstrip('/'))))
            else:
                formatted_files.append((source_path, '.'))

        # Combine imports with hidden modules
        all_imports = list(set(imports + self.hidden_modules_list))

        # Ensure that pathex includes the directory of the main script
        pathex_list = [repr(os.path.dirname(script_path))]
        if hook_dir and os.path.isabs(hook_dir):
            pathex_list.append(repr(hook_dir))

        spec_content = f"""# -*- mode: python ; coding: utf-8 -*-
# Generated by PyInstaller Spec Generator v2.0

block_cipher = None

a = Analysis(
    ['{os.path.basename(script_path)}'],
    pathex=[{', '.join(pathex_list)}],
    binaries=[],
    datas={formatted_files},
    hiddenimports={all_imports},
    hookspath={hook_path},
    hooksconfig={{}},
    runtime_hooks=[],
    # excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive={self.var_noarchive.get()},
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
"""

        # General EXE options
        common_exe_options = []
        if self.var_debug.get():
            common_exe_options.append("debug=True")
        common_exe_options.append(f"bootloader_ignore_signals=False")
        common_exe_options.append(f"strip={self.var_strip.get()}")
        common_exe_options.append(f"upx={self.var_upx.get()}")
        common_exe_options.append("upx_exclude=[]")
        common_exe_options.append("runtime_tmpdir=None")
        common_exe_options.append(f"console={self.var_console.get()}")

        # Icon (cross-platform, but handled by PyInstaller based on extension)
        if self.entry_icon.get().strip():
            common_exe_options.append(f"icon='{self.entry_icon.get().strip()}'")

        # Platform-specific EXE options
        platform_exe_options = []
        if platform.system() == "Windows":
            if hasattr(self, 'entry_version') and self.entry_version.get().strip():
                platform_exe_options.append(f"version_file='{self.entry_version.get().strip()}'")
            if hasattr(self, 'entry_manifest') and self.entry_manifest.get().strip():
                platform_exe_options.append(f"manifest='{self.entry_manifest.get().strip()}'")
            if hasattr(self, 'var_uac_admin') and self.var_uac_admin.get():
                platform_exe_options.append("uac_admin=True")
            if hasattr(self, 'var_uac_uiaccess') and self.var_uac_uiaccess.get():
                platform_exe_options.append("uac_uiaccess=True")

        elif platform.system() == "Darwin":
            if hasattr(self, 'entry_bundle_identifier') and self.entry_bundle_identifier.get().strip():
                platform_exe_options.append(f"bundle_identifier='{self.entry_bundle_identifier.get().strip()}'")
            if hasattr(self, 'entry_codesign_identity') and self.entry_codesign_identity.get().strip():
                platform_exe_options.append(f"codesign_identity='{self.entry_codesign_identity.get().strip()}'")
            if hasattr(self, 'entry_entitlements_file') and self.entry_entitlements_file.get().strip():
                platform_exe_options.append(f"entitlements_file='{self.entry_entitlements_file.get().strip()}'")
            if hasattr(self, 'var_target_arch') and self.var_target_arch.get() != "auto":
                platform_exe_options.append(f"target_arch='{self.var_target_arch.get()}'")

        all_exe_options = ", ".join(common_exe_options + platform_exe_options)

        if self.var_onefile.get():
            spec_content += f"""
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='{script_name}',
    {all_exe_options},
)
"""
        else:  # One directory mode
            spec_content += f"""
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='{script_name}',
    {all_exe_options},
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip={self.var_strip.get()},
    upx={self.var_upx.get()},
    upx_exclude=[],
    name='{script_name}',
)
"""

        spec_path = os.path.join(os.path.dirname(script_path), f"{script_name}.spec")

        if os.path.exists(spec_path):
            if not messagebox.askyesno("Overwrite File", "A spec file already exists. Overwrite?"):
                return None

        try:
            with open(spec_path, 'w', encoding='utf-8') as spec_file:
                spec_file.write(spec_content)

            self.log_output(f"Spec file generated: {spec_path}")
            messagebox.showinfo("Success", f"Spec file generated at {spec_path}")
            return spec_path

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate spec file: {str(e)}")
            return None

    def _set_build_controls_state(self, state):
        """Helper to enable/disable build-related controls."""
        # Enable/Disable main build buttons
        self.btn_build_from_spec.config(state=state)
        self.btn_quick_build.config(state=state)
        self.btn_clean_build.config(state=state)
        self.btn_generate_spec.config(state=state)
        self.btn_validate_spec.config(state=state)

        # Enable/Disable entry widgets and their associated browse/add buttons
        entry_widgets = [
            self.entry_path, self.entry_hook_dir, self.entry_icon,
            self.entry_hidden_module, self.entry_search
        ]
        for entry in entry_widgets:
            entry.config(state=state)

        buttons_to_toggle = [
            self.btn_add_files, self.btn_add_directory, self.btn_auto_detect,
            self.btn_browse_hook, self.btn_add_hidden_module,
            self.btn_browse_icon,
            self.spin_optimize  # Spinbox uses state like an entry
        ]
        for button in buttons_to_toggle:
            button.config(state=state)

        # Checkbuttons
        checkbuttons_to_toggle = [
            self.chk_debug, self.chk_console, self.chk_onefile,
            self.chk_windowed, self.chk_strip, self.chk_noarchive
        ]
        for chkbtn in checkbuttons_to_toggle:
            chkbtn.config(state=state)

        # Platform-specific controls
        if platform.system() == "Windows":
            if hasattr(self, 'entry_version'):  # Check if these widgets were created
                self.entry_version.config(state=state)
                self.btn_browse_version.config(state=state)
            if hasattr(self, 'entry_manifest'):
                self.entry_manifest.config(state=state)
                self.btn_browse_manifest.config(state=state)
            if hasattr(self, 'chk_uac_admin'):
                self.chk_uac_admin.config(state=state)
            if hasattr(self, 'chk_uac_uiaccess'):
                self.chk_uac_uiaccess.config(state=state)
        elif platform.system() == "Darwin":
            if hasattr(self, 'entry_bundle_identifier'):  # Check if these widgets were created
                self.entry_bundle_identifier.config(state=state)
                self.entry_codesign_identity.config(state=state)
                self.entry_entitlements_file.config(state=state)
                self.btn_browse_entitlements.config(state=state)
                self.opt_target_arch.config(state=state)

        # UPX controls and PyInstaller install buttons are managed separately based on availability.
        # So we re-call their setup to correctly set their states.
        # This will ensure their state (enabled/disabled) is correct after a build.
        self.enable_upx_feature(self.upx_available and (state == "normal"))
        self.btn_install_pyinstaller.config(state="disabled" if self.pyinstaller_available else "normal")

    def build_from_spec(self):
        """Build executable from spec file"""
        if not self.pyinstaller_available:
            messagebox.showwarning("PyInstaller Missing", "PyInstaller is not detected. Please install it.")
            return

        spec_file = filedialog.askopenfilename(
            title="Select Spec File",
            filetypes=[("Spec Files", "*.spec"), ("All Files", "*.*")]
        )
        if spec_file:
            cmd = [sys.executable, "-m", "PyInstaller", spec_file]
            # Add custom UPX path if set
            if self.upx_custom_path.get() and self.upx_available:
                cmd.extend(["--upx-dir", self.upx_custom_path.get()])
            self.run_pyinstaller(cmd)

    def quick_build(self):
        """Quick build without generating spec file"""
        if not self.pyinstaller_available:
            messagebox.showwarning("PyInstaller Missing", "PyInstaller is not detected. Please install it.")
            return

        script_path = self.entry_path.get()
        if not script_path:
            messagebox.showwarning("Warning", "Please select a Python script first.")
            return

        cmd = [sys.executable, "-m", "PyInstaller"]
        if self.var_onefile.get():
            cmd.append("--onefile")
        else:
            cmd.append("--onedir")  # Explicitly specify onedir if not onefile

        if self.var_windowed.get():
            cmd.append("--windowed")
        elif not self.var_console.get():
            cmd.append("--noconsole")
        else:
            cmd.append("--console")

        if self.var_debug.get():
            cmd.append("--debug=all")

        if not self.var_upx.get() or not self.upx_available:  # Explicitly add --noupx if UPX not available or unchecked
            cmd.append("--noupx")
        elif self.upx_custom_path.get() and self.upx_available:  # Add custom UPX path if set
            cmd.extend(["--upx-dir", self.upx_custom_path.get()])

        # Add icon if specified
        if self.entry_icon.get().strip():
            cmd.append(f"--icon={self.entry_icon.get().strip()}")

        # Add version info if specified (Windows only)
        if platform.system() == "Windows" and hasattr(self, 'entry_version') and self.entry_version.get().strip():
            cmd.append(f"--version-file={self.entry_version.get().strip()}")

        # Add manifest (Windows only)
        if platform.system() == "Windows" and hasattr(self, 'entry_manifest') and self.entry_manifest.get().strip():
            cmd.append(f"--manifest={self.entry_manifest.get().strip()}")

        # Add UAC options (Windows only)
        if platform.system() == "Windows" and hasattr(self, 'var_uac_admin') and self.var_uac_admin.get():
            cmd.append("--uac-admin")
        if platform.system() == "Windows" and hasattr(self, 'var_uac_uiaccess') and self.var_uac_uiaccess.get():
            cmd.append("--uac-uiaccess")

        # macOS specific options
        if platform.system() == "Darwin":
            if hasattr(self, 'entry_bundle_identifier') and self.entry_bundle_identifier.get().strip():
                cmd.append(f"--osx-bundle-identifier={self.entry_bundle_identifier.get().strip()}")
            if hasattr(self, 'entry_codesign_identity') and self.entry_codesign_identity.get().strip():
                cmd.append(f"--codesign-identity={self.entry_codesign_identity.get().strip()}")
            if hasattr(self, 'entry_entitlements_file') and self.entry_entitlements_file.get().strip():
                cmd.append(f"--osx-entitlements-file={self.entry_entitlements_file.get().strip()}")
            if hasattr(self, 'var_target_arch') and self.var_target_arch.get() != "auto":
                cmd.append(f"--target-architecture={self.var_target_arch.get()}")

        # Add optimization level
        if self.var_optimize.get() > 0:
            cmd.append(f"--optimize={self.var_optimize.get()}")

        # Add hidden imports from self.hidden_modules_list
        for mod in self.hidden_modules_list:
            cmd.append(f"--hidden-import={mod}")

        # Add additional files (via --add-data)
        script_dir = os.path.dirname(script_path)
        for f in self.additional_files_list:
            if f.endswith('/'):  # Directory
                source_path = os.path.join(script_dir, f.rstrip('/')) if not os.path.isabs(f) else f.rstrip('/')
                dest_path = os.path.basename(source_path)  # Name of directory in bundle
                cmd.append(f"--add-data={source_path}{os.pathsep}{dest_path}")
            else:  # File
                source_path = os.path.join(script_dir, f) if not os.path.isabs(f) else f
                cmd.append(f"--add-data={source_path}{os.pathsep}.")  # Add to root of bundle

        # Add hook directory
        hook_dir = self.entry_hook_dir.get().strip()
        if hook_dir:
            cmd.append(f"--additional-hooks-dir={hook_dir}")

        cmd.append(script_path)
        self.run_pyinstaller(cmd)

    def clean_build(self):
        """Clean build directories"""
        if not self.pyinstaller_available:
            messagebox.showwarning("PyInstaller Missing", "PyInstaller is not detected. Clean operation skipped.")
            return

        script_path = self.entry_path.get()
        if not script_path:
            messagebox.showwarning("Warning", "Please select a Python script first.")
            return

        script_dir = os.path.dirname(script_path)
        dirs_to_clean = ['build', 'dist', '__pycache__']
        # Also clean spec file
        spec_name = os.path.splitext(os.path.basename(script_path))[0] + ".spec"
        files_to_clean = [spec_name]

        import shutil  # Import shutil locally to ensure it's available when needed

        cleaned_something = False
        for dir_name in dirs_to_clean:
            dir_path = os.path.join(script_dir, dir_name)
            if os.path.exists(dir_path):
                try:
                    shutil.rmtree(dir_path)
                    self.log_output(f"Cleaned: {dir_path}")
                    cleaned_something = True
                except Exception as e:
                    self.log_output(f"Failed to clean {dir_path}: {str(e)}")

        for file_name in files_to_clean:
            file_path = os.path.join(script_dir, file_name)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    self.log_output(f"Cleaned: {file_path}")
                    cleaned_something = True
                except Exception as e:
                    self.log_output(f"Failed to clean {file_path}: {str(e)}")

        if cleaned_something:
            messagebox.showinfo("Clean Complete", "Build directories and spec file cleaned.")
        else:
            messagebox.showinfo("Clean Complete", "Nothing to clean.")

    def run_pyinstaller(self, cmd):
        """Run PyInstaller command in separate thread"""

        def run():
            # Disable build controls and enable abort button at the start of the build
            self._set_build_controls_state("disabled")
            self.btn_abort_build.config(state="normal")

            try:
                self.progress_bar.start()
                self.log_output(f"Running: {' '.join(cmd)}")

                self.current_process = subprocess.Popen(  # Store the process object
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    cwd=os.path.dirname(self.entry_path.get()) if self.entry_path.get() else None
                )

                for line in self.current_process.stdout:
                    self.log_output(line.strip())

                self.current_process.wait()

                if self.current_process.returncode == 0:
                    self.log_output("Build completed successfully!")
                elif self.current_process.returncode == -15:  # Terminated by SIGTERM (common on Windows for terminate)
                    self.log_output("Build aborted by user.")
                else:
                    self.log_output(f"Build failed with return code {self.current_process.returncode}")

            except FileNotFoundError:
                self.log_output(
                    f"Error: Command not found or executable issues. Ensure PyInstaller is installed for '{sys.executable}' and UPX (if used) is in system PATH.")
                self.log_output("Check PyInstaller and UPX availability using the buttons above.")
            except Exception as e:
                self.log_output(f"Error running PyInstaller: {str(e)}")
            finally:
                self.progress_bar.stop()
                # Re-enable controls and disable abort button after build finishes/aborts
                self.btn_abort_build.config(state="disabled")
                self._set_build_controls_state("normal")
                self.current_process = None  # Clear the process object

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

    def abort_build(self):
        """Aborts the currently running PyInstaller build process."""
        if self.current_process and self.current_process.poll() is None:  # Check if process is running
            self.log_output("Aborting build process...")
            try:
                self.current_process.terminate()  # or .kill() for a more forceful termination
                self.log_output("Build termination signal sent.")
            except Exception as e:
                self.log_output(f"Error trying to abort build: {e}")
        else:
            self.log_output("No active build process to abort.")
            self.btn_abort_build.config(state="disabled")  # Ensure button is disabled if no process

    def log_output(self, message):
        """Log output to text widget"""
        self.output_text.insert(tk.END, f"{message}\n")
        self.output_text.see(tk.END)
        self.root.update_idletasks()

    def save_config(self):
        """Save current configuration to file"""
        config = {
            'script_path': self.entry_path.get(),
            'hook_dir': self.entry_hook_dir.get(),
            'icon_file': self.entry_icon.get(),
            'show_paths': self.var_show_paths.get(),
            'recursive_scan': self.var_recursive_scan.get(),
            'debug': self.var_debug.get(),
            'console': self.var_console.get(),
            'onefile': self.var_onefile.get(),
            'windowed': self.var_windowed.get(),
            'upx': self.var_upx.get(),
            'strip': self.var_strip.get(),
            'noarchive': self.var_noarchive.get(),
            'optimize': self.var_optimize.get(),
            'additional_files': self.additional_files_list,
            'hidden_modules': self.hidden_modules_list,
            'upx_custom_path': self.upx_custom_path.get()
        }
        if platform.system() == "Windows":
            if hasattr(self, 'entry_version'):  # Check if these widgets were created
                config['version_file'] = self.entry_version.get()
            if hasattr(self, 'entry_manifest'):
                config['manifest'] = self.entry_manifest.get()
            if hasattr(self, 'var_uac_admin'):
                config['uac_admin'] = self.var_uac_admin.get()
            if hasattr(self, 'var_uac_uiaccess'):
                config['uac_uiaccess'] = self.var_uac_uiaccess.get()
        elif platform.system() == "Darwin":
            if hasattr(self, 'entry_bundle_identifier'):  # Check if these widgets were created
                config['bundle_identifier'] = self.entry_bundle_identifier.get()
                config['codesign_identity'] = self.entry_codesign_identity.get()
                config['entitlements_file'] = self.entry_entitlements_file.get()
                config['target_arch'] = self.var_target_arch.get()

        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            messagebox.showinfo("Success", f"Configuration saved to {self.config_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")

    def load_config(self):
        """Load configuration from file"""
        if not os.path.exists(self.config_file):
            return

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)

            self.entry_path.delete(0, tk.END)
            self.entry_path.insert(0, config.get('script_path', ''))

            self.entry_hook_dir.delete(0, tk.END)
            self.entry_hook_dir.insert(0, config.get('hook_dir', ''))

            self.entry_icon.delete(0, tk.END)
            self.entry_icon.insert(0, config.get('icon_file', ''))

            # Load platform-specific fields only if they exist
            if platform.system() == "Windows":
                # Check if widgets exist before trying to load data into them
                if hasattr(self, 'entry_version') and 'version_file' in config:
                    self.entry_version.delete(0, tk.END)
                    self.entry_version.insert(0, config['version_file'])
                if hasattr(self, 'entry_manifest') and 'manifest' in config:
                    self.entry_manifest.delete(0, tk.END)
                    self.entry_manifest.insert(0, config['manifest'])
                if hasattr(self, 'var_uac_admin') and 'uac_admin' in config:
                    self.var_uac_admin.set(config['uac_admin'])
                if hasattr(self, 'var_uac_uiaccess') and 'uac_uiaccess' in config:
                    self.var_uac_uiaccess.set(config['uac_uiaccess'])
            elif platform.system() == "Darwin":
                if hasattr(self, 'entry_bundle_identifier') and 'bundle_identifier' in config:
                    self.entry_bundle_identifier.delete(0, tk.END)
                    self.entry_bundle_identifier.insert(0, config['bundle_identifier'])
                    self.entry_codesign_identity.delete(0, tk.END)
                    self.entry_codesign_identity.insert(0, config['codesign_identity'])
                    self.entry_entitlements_file.delete(0, tk.END)
                    self.entry_entitlements_file.insert(0, config['entitlements_file'])
                    self.var_target_arch.set(config.get('target_arch', 'auto'))

            self.var_show_paths.set(config.get('show_paths', False))
            self.var_recursive_scan.set(config.get('recursive_scan', True))
            self.var_debug.set(config.get('debug', False))
            self.var_console.set(config.get('console', False))
            self.var_onefile.set(config.get('onefile', True))
            self.var_windowed.set(config.get('windowed', False))
            self.var_upx.set(config.get('upx', True))
            self.var_strip.set(config.get('strip', False))
            self.var_noarchive.set(config.get('noarchive', False))
            self.var_optimize.set(config.get('optimize', 0))

            self.additional_files_list = config.get('additional_files', [])
            self.hidden_modules_list = config.get('hidden_modules', [])
            self.upx_custom_path.set(config.get('upx_custom_path', ''))

            # If a script path was loaded, analyze it
            if self.entry_path.get():
                self.analyze_script()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load configuration: {str(e)}")

    def load_config_dialog(self):
        """Load configuration from selected file"""
        config_file = filedialog.askopenfilename(
            title="Load Configuration",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if config_file:
            self.config_file = config_file
            self.load_config()

    def select_file(self):
        """Select Python script file"""
        file_path = filedialog.askopenfilename(filetypes=[("Python Files", "*.py")])
        if file_path:
            self.entry_path.delete(0, tk.END)
            self.entry_path.insert(0, file_path)
            self.analyze_script()

    def analyze_script(self):
        """Analyze selected script for imports and files"""
        file_path = self.entry_path.get()
        if not file_path:
            return

        try:
            imports, files = self.extract_imports_and_files(
                file_path,
                self.var_recursive_scan.get()
            )

            # Clear previous data
            self.tree.delete(*self.tree.get_children())

            # Update the treeview
            self.imports_node = self.tree.insert("", "end", text="Imports", values=["Category", ""], tags=("header",))
            for imp in imports:
                status = "✓" if self.check_import_available(imp) else "✗"
                self.tree.insert(self.imports_node, "end", text=imp, values=["Import", status])

            self.files_node = self.tree.insert("", "end", text="Files", values=["Category", ""], tags=("header",))

            # Categorize files
            file_categories = {
                "Images": ['.png', '.gif', '.jpg', '.jpeg', '.bmp', '.ico', '.svg'],
                "Audio": ['.ogg', '.wav', '.mp3', '.m4a'],
                "Data": ['.json', '.xml', '.csv', '.xlsx', '.dat', '.bin'],
                "Fonts": ['.ttf', '.otf', '.woff'],
                "Text": ['.txt', '.story', '.md'],
                "Other": []
            }

            categorized_files = {cat: [] for cat in file_categories}

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                categorized = False
                for category, extensions in file_categories.items():
                    if ext in extensions:
                        categorized_files[category].append(file)
                        categorized = True
                        break
                if not categorized:
                    categorized_files["Other"].append(file)

            for category, file_list in categorized_files.items():
                if file_list:
                    category_node = self.tree.insert(self.files_node, "end", text=category, values=["Category", ""],
                                                     tags=("header",))
                    for file in file_list:
                        status = "✓" if self.check_file_exists(file, file_path) else "✗"
                        self.tree.insert(category_node, "end", text=file, values=["File", status])

            # Expand main nodes
            self.tree.item(self.imports_node, open=True)
            self.tree.item(self.files_node, open=True)

            self.refresh_tree()  # Call refresh_tree to populate additional files and hidden modules

        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze script: {str(e)}")

    def check_import_available(self, module_name):
        """Check if import is available"""
        try:
            # Attempt a direct import
            __import__(module_name)
            return True
        except ImportError:
            # Check if it's a sub-module and the parent exists
            parts = module_name.split('.')
            if len(parts) > 1:
                try:
                    __import__(parts[0])
                    # If the top-level module exists, assume the sub-module might be found at runtime
                    return True
                except ImportError:
                    pass
            return False
        except Exception:  # Catch other potential errors during import, e.g., syntax errors in module
            return False

    def check_file_exists(self, file_path, script_path):
        """Check if file exists relative to script or as an absolute path"""
        if os.path.isabs(file_path):
            return os.path.exists(file_path)
        else:
            script_dir = os.path.dirname(script_path)
            full_path = os.path.join(script_dir, file_path)
            return os.path.exists(full_path)

    def refresh_analysis(self):
        """Refresh analysis when settings change"""
        if self.entry_path.get():
            self.analyze_script()

    def add_additional_files(self):
        """Add additional files"""
        additional_files = filedialog.askopenfilenames(
            title="Select Additional Files",
            filetypes=[
                ("All Supported",
                 "*.json;*.png;*.gif;*.jpg;*.jpeg;*.dat;*.ttf;*.ogg;*.story;*.wav;*.txt;*.bin;*.xml;*.csv;*.xlsx;*.pdf;*.ico;*.bmp;*.svg"),
                ("All Files", "*.*")
            ]
        )
        if additional_files:
            for file in additional_files:
                if self.var_show_paths.get() or os.path.isabs(file):
                    file_to_add = file
                else:
                    # Make path relative to the script directory if script path is set
                    script_path = self.entry_path.get()
                    if script_path:
                        try:
                            file_to_add = os.path.relpath(file, os.path.dirname(script_path))
                        except ValueError:  # file on different drive than script
                            file_to_add = file
                    else:  # If no script selected, just add basename or full path
                        file_to_add = os.path.basename(file) if not self.var_show_paths.get() else file

                if file_to_add not in self.additional_files_list:
                    self.additional_files_list.append(file_to_add)

            self.refresh_tree()

    def add_hook_dir(self):
        """Add hook directory"""
        hook_dir = filedialog.askdirectory(title="Select Hook Directory")
        if hook_dir:
            self.entry_hook_dir.delete(0, tk.END)
            script_path = self.entry_path.get()
            if script_path and not self.var_show_paths.get():
                try:
                    relative_hook_dir = os.path.relpath(hook_dir, os.path.dirname(script_path))
                    self.entry_hook_dir.insert(0, relative_hook_dir)
                except ValueError:
                    self.entry_hook_dir.insert(0, hook_dir)  # Insert full path if cannot make relative
            else:
                self.entry_hook_dir.insert(0, hook_dir)

    def add_hidden_module(self):
        """Add hidden module"""
        module = self.entry_hidden_module.get().strip()
        if module and module not in self.hidden_modules_list:
            self.hidden_modules_list.append(module)
            self.refresh_tree()
            self.entry_hidden_module.delete(0, tk.END)

    def refresh_tree(self):
        """Refresh tree with additional files and modules"""
        # First, remove existing Additional/Hidden nodes to prevent duplicates
        if hasattr(self, 'imports_node') and self.imports_node:
            for child in list(self.tree.get_children(self.imports_node)):  # Iterate over a copy
                item_values = self.tree.item(child, "values")
                if item_values and item_values[0] == "Hidden Module":
                    self.tree.delete(child)

        if hasattr(self, 'files_node') and self.files_node:
            for child in list(self.tree.get_children(self.files_node)):  # Iterate over a copy
                item_values = self.tree.item(child, "values")
                if item_values and item_values[0] == "Category" and self.tree.item(child, "text") == "Additional":
                    self.tree.delete(child)

            # Now add them back
            if self.additional_files_list:
                additional_node = self.tree.insert(self.files_node, "end", text="Additional", values=["Category", ""],
                                                   tags=("header",))
                for file in self.additional_files_list:
                    script_path = self.entry_path.get()
                    status = "✓" if script_path and self.check_file_exists(file, script_path) else "✗"
                    self.tree.insert(additional_node, "end", text=file, values=["Additional File", status])
                self.tree.item(additional_node, open=True)  # Ensure this node is open

        # Add hidden modules to imports node
        if hasattr(self, 'imports_node') and self.imports_node:
            for module in self.hidden_modules_list:
                # Check if already exists by text content (less robust than iid check, but needed for dynamic adds)
                exists = False
                for child in self.tree.get_children(self.imports_node):
                    if self.tree.item(child, "text") == module:
                        exists = True
                        break
                if not exists:
                    status = "✓" if self.check_import_available(module) else "✗"
                    self.tree.insert(self.imports_node, "end", text=module, values=["Hidden Module", status])
            self.tree.item(self.imports_node, open=True)  # Ensure this node is open

    def generate_spec(self):
        """Generate spec file"""
        if not self.pyinstaller_available:
            messagebox.showwarning("PyInstaller Missing", "PyInstaller is not detected. Cannot generate spec file.")
            return

        file_path = self.entry_path.get()
        if not file_path:
            messagebox.showwarning("Warning", "Please select a Python script first.")
            return

        try:
            imports, files = self.extract_imports_and_files(file_path, self.var_recursive_scan.get())
            spec_path = self.generate_spec_file(file_path, imports, files)

            if spec_path:
                self.validate_spec_file(spec_path)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate spec file: {str(e)}")

    def validate_spec(self):
        """Validate existing spec file"""
        if not self.pyinstaller_available:
            messagebox.showwarning("PyInstaller Missing", "PyInstaller is not detected. Cannot validate spec file.")
            return

        spec_path = filedialog.askopenfilename(
            title="Select Spec File",
            filetypes=[("Spec Files", "*.spec")]
        )
        if spec_path:
            self.validate_spec_file(spec_path)

    def validate_spec_file(self, spec_path):
        """Validate spec file and check for missing files"""
        if not os.path.exists(spec_path):
            messagebox.showerror("Validation Error", "Spec file does not exist.")
            return

        try:
            with open(spec_path, 'r', encoding='utf-8') as file:
                content = file.read()

            # Extract datas section
            datas_match = re.search(r'datas\s*=\s*\[(.*?)\]', content, re.DOTALL)
            # Extract pathex section
            pathex_match = re.search(r'pathex\s*=\s*\[(.*?)\]', content, re.DOTALL)

            datas_str = datas_match.group(1) if datas_match else ""
            pathex_str = pathex_match.group(1) if pathex_match else ""

            file_tuples = re.findall(r'\(\s*[\'"]([^\'"]*)[\'"],\s*[\'"]([^\'"]*)[\'"]', datas_str)
            pathex_entries = [p.strip().strip("'\"") for p in pathex_str.split(',') if p.strip()]

            missing_files = []
            script_dir = os.path.dirname(spec_path)

            # Add pathex entries to search paths for validation
            search_paths = [script_dir] + [p for p in pathex_entries if os.path.isabs(p) and os.path.isdir(p)]

            for source, dest in file_tuples:
                if not source:  # Skip empty entries
                    continue

                found = False
                if os.path.isabs(source):
                    if os.path.exists(source):
                        found = True
                else:
                    # Check relative to script_dir and other pathex entries
                    for base_dir in search_paths:
                        full_path = os.path.normpath(os.path.join(base_dir, source))
                        if os.path.exists(full_path):
                            found = True
                            break

                if not found:
                    missing_files.append(source)  # Report the source path as in spec

            if missing_files:
                missing_list = '\n'.join(missing_files)
                messagebox.showerror("Validation Error", f"Missing files referenced in 'datas':\n\n{missing_list}")
                self.log_output(f"Validation failed: {len(missing_files)} missing files in 'datas' section.")
            else:
                messagebox.showinfo("Validation Success",
                                    "All files in the spec file 'datas' section are present or paths are valid.")
                self.log_output("Validation successful: All 'datas' files found.")

        except Exception as e:
            messagebox.showerror("Validation Error", f"Error validating spec file: {str(e)}")


def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = PyInstallerSpecGenerator(root)

    # Configure tree tags
    app.tree.tag_configure("header", background="#4a90e2", foreground="#ffffff")

    # Bind Enter key to hidden module entry
    root.bind('<Return>', lambda e: app.add_hidden_module() if root.focus_get() == app.entry_hidden_module else None)

    # Set minimum window size
    root.minsize(800, 600)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        root.quit()


if __name__ == "__main__":
    main()
