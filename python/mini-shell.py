"""
Windows Mini Shell - Professional OS Concepts Implementation
============================================================
A complete shell demonstrating core Operating System concepts:

OS CONCEPTS DEMONSTRATED:
1. Process Management - Creating, monitoring, and terminating processes
2. I/O Redirection - stdin, stdout, stderr handling
3. Inter-Process Communication - Pipes between processes
4. File System Operations - Directory navigation, file operations
5. Background/Foreground Execution - Process scheduling
6. Command Parsing - Tokenization and interpretation
7. System Calls - Interfacing with Windows OS
8. Memory Management - Process tracking and cleanup
9. Security - Encrypted logging with cryptography

Perfect for demonstrating to instructors!
"""

import tkinter as tk
from tkinter import scrolledtext
import subprocess
import os
import threading
import sys
from datetime import datetime
from cryptography.fernet import Fernet

# Auto-install dependencies
try:
    import psutil
except ImportError:
    print("Installing required package: psutil...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil

# ============================================================================
# ENCRYPTION MODULE - Security Concept
# ============================================================================

class EncryptedLogger:
    """
    OS CONCEPT: Security & Logging
    Implements AES encryption for secure command history storage
    """
    
    def __init__(self, log_file="shell_log.enc", key_file="shell.key"):
        self.log_file = log_file
        self.key_file = key_file
        self.cipher = self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Generate or load encryption key"""
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(self.key_file, 'wb') as f:
                    f.write(key)
            return Fernet(key)
        except Exception as e:
            print(f"Encryption error: {e}")
            return None
    
    def log_command(self, command, output="", error=""):
        """Encrypt and log command with timestamp"""
        if not self.cipher:
            return
        
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] CMD: {command}\n"
            if output:
                log_entry += f"OUT: {output[:300]}\n"
            if error:
                log_entry += f"ERR: {error[:300]}\n"
            log_entry += "-" * 40 + "\n"
            
            encrypted_data = self.cipher.encrypt(log_entry.encode())
            with open(self.log_file, 'ab') as f:
                f.write(encrypted_data + b'\n')
        except Exception as e:
            print(f"Logging error: {e}")
    
    def read_logs(self):
        """Decrypt and return command history"""
        if not self.cipher or not os.path.exists(self.log_file):
            return "No logs available."
        
        try:
            with open(self.log_file, 'rb') as f:
                encrypted_lines = f.readlines()
            
            decrypted_logs = []
            for line in encrypted_lines:
                if line.strip():
                    try:
                        decrypted = self.cipher.decrypt(line.strip()).decode()
                        decrypted_logs.append(decrypted)
                    except:
                        continue
            
            return ''.join(decrypted_logs) if decrypted_logs else "No logs found."
        except Exception as e:
            return f"Error reading logs: {e}"

# ============================================================================
# COMMAND PARSER - Lexical Analysis
# ============================================================================

class CommandParser:
    """
    OS CONCEPT: Command Interpretation
    Tokenizes and parses shell commands (like bash/cmd parser)
    """
    
    @staticmethod
    def parse_command(cmd_line):
        """
        Parse command line into executable components
        Handles: pipes (|), redirection (>, <), chaining (;), background (&)
        """
        result = {
            'chains': [],
            'background': False,
            'original': cmd_line
        }
        
        # Check for background execution (&)
        if cmd_line.strip().endswith('&'):
            result['background'] = True
            cmd_line = cmd_line.strip()[:-1].strip()
        
        # Split by semicolon for command chaining
        commands = [c.strip() for c in cmd_line.split(';') if c.strip()]
        
        for cmd in commands:
            parsed_cmd = CommandParser._parse_single_command(cmd)
            result['chains'].append(parsed_cmd)
        
        return result
    
    @staticmethod
    def _parse_single_command(cmd):
        """Parse single command for pipes and I/O redirection"""
        result = {
            'pipes': [],
            'input_file': None,
            'output_file': None,
            'append_file': None,
        }
        
        # Tokenize and handle redirection operators
        parts = cmd.split()
        clean_parts = []
        i = 0
        
        while i < len(parts):
            if parts[i] == '<' and i + 1 < len(parts):
                result['input_file'] = parts[i + 1]
                i += 2
            elif parts[i] == '>>' and i + 1 < len(parts):
                result['append_file'] = parts[i + 1]
                i += 2
            elif parts[i] == '>' and i + 1 < len(parts):
                result['output_file'] = parts[i + 1]
                i += 2
            elif parts[i].startswith('>>'):
                result['append_file'] = parts[i][2:]
                i += 1
            elif parts[i].startswith('>'):
                result['output_file'] = parts[i][1:]
                i += 1
            elif parts[i].startswith('<'):
                result['input_file'] = parts[i][1:]
                i += 1
            else:
                clean_parts.append(parts[i])
                i += 1
        
        # Handle pipes (|) for IPC
        clean_cmd = ' '.join(clean_parts)
        pipe_commands = [p.strip() for p in clean_cmd.split('|') if p.strip()]
        result['pipes'] = pipe_commands
        
        return result

# ============================================================================
# PROCESS MANAGER - Process Control Block (PCB) Management
# ============================================================================

class ProcessManager:
    """
    OS CONCEPT: Process Management
    Maintains Process Control Blocks (PCB) for background processes
    Demonstrates process scheduling and lifecycle management
    """
    
    def __init__(self):
        self.processes = {}  # Job ID -> Process Control Block
        self.next_job_id = 1
    
    def add_process(self, process, command):
        """
        Create PCB for new background process
        PCB contains: PID, command, start time, process object
        """
        job_id = self.next_job_id
        self.next_job_id += 1
        
        self.processes[job_id] = {
            'process': process,
            'command': command,
            'pid': process.pid,
            'start_time': datetime.now(),
            'status': 'Running'
        }
        return job_id
    
    def check_processes(self):
        """
        Poll all background processes for completion
        OS CONCEPT: Process state transitions (Running -> Terminated)
        """
        completed = []
        
        for job_id, pcb in list(self.processes.items()):
            return_code = pcb['process'].poll()
            if return_code is not None:
                pcb['status'] = 'Completed'
                pcb['exit_code'] = return_code
                completed.append((job_id, pcb, return_code))
                del self.processes[job_id]
        
        return completed
    
    def get_status(self):
        """Display process table (like 'ps' or 'jobs' command)"""
        if not self.processes:
            return "No background processes running.\n"
        
        status = "JOB ID | PID    | STATUS  | COMMAND\n"
        status += "-" * 50 + "\n"
        
        for job_id, pcb in self.processes.items():
            status += f"[{job_id:^4}] | {pcb['pid']:<6} | {pcb['status']:<7} | {pcb['command']}\n"
        
        return status
    
    def kill_all(self):
        """Terminate all background processes (cleanup)"""
        for pcb in self.processes.values():
            try:
                pcb['process'].terminate()
            except:
                pass
        self.processes.clear()

# ============================================================================
# COMMAND EXECUTOR - System Call Interface
# ============================================================================

class CommandExecutor:
    """
    OS CONCEPT: System Calls & I/O Management
    Interfaces with Windows OS to execute commands
    Handles stdin, stdout, stderr redirection
    """
    
    def __init__(self, output_callback, process_manager, logger):
        self.output_callback = output_callback
        self.process_manager = process_manager
        self.logger = logger
        self.current_dir = os.getcwd()
    
    def execute(self, cmd_line):
        """
        Main execution entry point
        OS CONCEPT: Command execution and process creation
        """
        if not cmd_line.strip():
            return
        
        # Parse command
        parsed = CommandParser.parse_command(cmd_line)
        
        # Check background processes (process monitoring)
        self._check_background_processes()
        
        # Execute command chains
        for chain in parsed['chains']:
            try:
                output, error = self._execute_chain(chain, parsed['background'])
                
                # Log command (security/audit trail)
                self.logger.log_command(cmd_line, output, error)
                
                # Display output
                if output:
                    self.output_callback(output, 'output')
                if error:
                    self.output_callback(error, 'error')
                    
            except Exception as e:
                error_msg = f"Execution error: {str(e)}"
                self.output_callback(error_msg, 'error')
                self.logger.log_command(cmd_line, "", error_msg)
    
    def _execute_chain(self, chain, background):
        """Execute command chain with built-in command handling"""
        pipes = chain['pipes']
        
        if not pipes:
            return "", ""
        
        first_cmd = pipes[0].strip().split()[0].lower()
        
        # Built-in commands (shell-level operations)
        if first_cmd == 'cd':
            return self._builtin_cd(pipes[0])
        elif first_cmd == 'help':
            return self._builtin_help()
        elif first_cmd == 'exit':
            return self._builtin_exit()
        elif first_cmd == 'jobs':
            return self.process_manager.get_status(), ""
        elif first_cmd == 'logs':
            return self.logger.read_logs(), ""
        elif first_cmd in ['clear', 'cls']:
            return "CLEAR_SCREEN", ""
        elif first_cmd == 'ps':
            return self._builtin_ps()
        elif first_cmd == 'pwd':
            return self.current_dir + "\n", ""
        
        # External commands (OS-level system calls)
        return self._execute_piped_commands(chain, background)
    
    def _execute_piped_commands(self, chain, background):
        """
        OS CONCEPT: Inter-Process Communication (IPC) using Pipes
        Creates pipeline of processes with stdin/stdout redirection
        """
        pipes = chain['pipes']
        
        try:
            processes = []
            stdin_source = None
            
            # Handle input redirection (<)
            if chain['input_file']:
                try:
                    stdin_source = open(chain['input_file'], 'r')
                except Exception as e:
                    return "", f"Cannot open input file: {e}"
            
            # Create process pipeline
            for i, cmd in enumerate(pipes):
                # Use cmd.exe for Windows built-in commands
                full_cmd = f'cmd.exe /c {cmd}'
                
                # Set up stdin from previous process or file
                if i == 0:
                    stdin = stdin_source if stdin_source else None
                else:
                    stdin = processes[-1].stdout
                
                stdout = subprocess.PIPE
                
                # Create process (OS system call: CreateProcess)
                process = subprocess.Popen(
                    full_cmd,
                    stdin=stdin,
                    stdout=stdout,
                    stderr=subprocess.PIPE,
                    cwd=self.current_dir,
                    text=True,
                    shell=True
                )
                processes.append(process)
                
                # Close previous stdout to allow SIGPIPE
                if i > 0 and processes[-2].stdout:
                    processes[-2].stdout.close()
            
            if stdin_source:
                stdin_source.close()
            
            # Background execution (process scheduling)
            if background:
                job_id = self.process_manager.add_process(processes[-1], chain['pipes'][0])
                return f"✓ Background job [{job_id}] started (PID: {processes[-1].pid})\n", ""
            
            # Wait for process completion (blocking)
            output, error = processes[-1].communicate()
            
            # Handle output redirection (>)
            if chain['output_file']:
                try:
                    with open(chain['output_file'], 'w') as f:
                        f.write(output)
                    return f"✓ Output redirected to: {chain['output_file']}\n", ""
                except Exception as e:
                    return output, f"Write error: {e}"
            
            # Handle append redirection (>>)
            if chain['append_file']:
                try:
                    with open(chain['append_file'], 'a') as f:
                        f.write(output)
                    return f"✓ Output appended to: {chain['append_file']}\n", ""
                except Exception as e:
                    return output, f"Append error: {e}"
            
            return output, error
            
        except FileNotFoundError:
            return "", f"Command not found: {pipes[0].split()[0]}"
        except Exception as e:
            return "", f"Execution error: {str(e)}"
    
    def _check_background_processes(self):
        """Monitor and report completed background processes"""
        completed = self.process_manager.check_processes()
        for job_id, pcb, return_code in completed:
            status = "✓" if return_code == 0 else "✗"
            elapsed = (datetime.now() - pcb['start_time']).total_seconds()
            msg = f"{status} Job [{job_id}] completed: {pcb['command']}\n"
            msg += f"   Exit code: {return_code} | Runtime: {elapsed:.2f}s\n"
            self.output_callback(msg, 'success' if return_code == 0 else 'info')
    
    # ========== Built-in Shell Commands ==========
    
    def _builtin_cd(self, cmd):
        """
        OS CONCEPT: File System Navigation
        Change current working directory
        """
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            return self.current_dir + "\n", ""
        
        target = parts[1].strip().strip('"')
        try:
            os.chdir(target)
            self.current_dir = os.getcwd()
            return f"✓ Changed directory to: {self.current_dir}\n", ""
        except Exception as e:
            return "", f"cd: {str(e)}\n"
    
    def _builtin_ps(self):
        """Display system processes (like Task Manager)"""
        try:
            output = "PID    | CPU%  | MEM%  | NAME\n"
            output += "-" * 50 + "\n"
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    if info['cpu_percent'] > 0:  # Only show active processes
                        output += f"{info['pid']:<6} | {info['cpu_percent']:>5.1f} | {info['memory_percent']:>5.1f} | {info['name']}\n"
                except:
                    continue
            
            return output, ""
        except Exception as e:
            return "", f"ps error: {e}"
    
    def _builtin_help(self):
        """Display comprehensive help with OS concepts"""
        help_text = """
╔══════════════════════════════════════════════════════════╗
║     MINI SHELL - Professional OS Implementation          ║
╚══════════════════════════════════════════════════════════╝

OS CONCEPTS DEMONSTRATED:
--------------------------
1. Process Management      - Creating, monitoring, terminating
2. I/O Redirection        - stdin, stdout, stderr handling
3. Inter-Process Comm.    - Pipes between processes
4. File System Ops        - Directory navigation
5. Background Execution   - Process scheduling
6. Command Parsing        - Tokenization & interpretation
7. System Calls           - Windows OS interface
8. Security               - AES encrypted logging

BUILT-IN COMMANDS:
------------------
  cd <path>         Change current directory (file system)
  pwd               Print working directory
  help              Show this help message
  exit              Exit shell (cleanup all processes)
  jobs              List background processes (PCB table)
  ps                Show running system processes
  logs              View encrypted command history
  clear / cls       Clear screen

COMMAND FEATURES:
-----------------
  command &         Run in background (async execution)
  cmd1 ; cmd2       Sequential execution (chaining)
  cmd1 | cmd2       Pipe output (IPC via pipes)
  cmd > file        Redirect stdout to file
  cmd >> file       Append stdout to file
  cmd < file        Redirect stdin from file

PRACTICAL EXAMPLES:
-------------------
File Operations:
  dir                           List directory
  cd C:\\Windows                Change to Windows folder
  type file.txt                 Display file contents
  echo Hello > test.txt         Create file with content
  copy file.txt backup.txt      Copy file

Process & System:
  ping google.com &             Background network test
  dir /s C:\\Windows &          Search entire folder tree
  jobs                          View background jobs
  ps                            View system processes

Pipes & Redirection:
  dir | findstr .py             Find Python files
  type file.txt | findstr "error" > errors.txt
  dir C:\\ | findstr "Program" > programs.txt
  ipconfig | findstr IPv4       Find IP address

Command Chaining:
  cd Desktop ; dir ; echo Done
  mkdir test ; cd test ; echo Created > readme.txt

KEYBOARD SHORTCUTS:
-------------------
  Enter             Execute command
  Up / Down         Navigate command history
  Escape            Cancel in dialogs

SYSTEM INFO:
------------
  Current Directory: {self.current_dir}
  Background Jobs:   {len(self.process_manager.processes)}
  Shell PID:         {os.getpid()}

"""
        return help_text, ""
    
    def _builtin_exit(self):
        """Signal shell exit"""
        return "EXIT_SHELL", ""

# ============================================================================
# PROFESSIONAL GUI - User Interface
# ============================================================================

class MiniShellGUI:
    """
    Professional GUI demonstrating OS shell interface
    Perfect for educational demonstrations
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("▶ Mini Shell - OS Concepts Implementation")
        self.root.geometry("1100x750")
        self.root.configure(bg='#1e1e1e')
        
        # Initialize OS components
        self.logger = EncryptedLogger()
        self.process_manager = ProcessManager()
        self.executor = CommandExecutor(
            self.display_output,
            self.process_manager,
            self.logger
        )
        
        self.command_history = []
        self.history_index = 0
        self.command_count = 0
        
        self._setup_gui()
        self.update_directory_display()
        self._start_system_monitor()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Display OS concepts on startup
        self._show_welcome()
    
    def _setup_gui(self):
        """Setup professional GUI layout"""
        # Configure grid
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # ===== HEADER =====
        header_frame = tk.Frame(self.root, bg='#0d1117', height=70)
        header_frame.grid(row=0, column=0, sticky='ew', padx=0, pady=0)
        header_frame.grid_propagate(False)
        
        # Logo and title
        title_frame = tk.Frame(header_frame, bg='#0d1117')
        title_frame.pack(side=tk.LEFT, padx=20, pady=10)
        
        tk.Label(
            title_frame,
            text="▶",
            font=('Segoe UI', 26, 'bold'),
            bg='#0d1117',
            fg='#58a6ff'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        title_container = tk.Frame(title_frame, bg='#0d1117')
        title_container.pack(side=tk.LEFT)
        
        tk.Label(
            title_container,
            text="MINI SHELL",
            font=('Segoe UI', 16, 'bold'),
            bg='#0d1117',
            fg='#c9d1d9'
        ).pack(anchor='w')
        
        tk.Label(
            title_container,
            text="OS Concepts Implementation",
            font=('Segoe UI', 9),
            bg='#0d1117',
            fg='#8b949e'
        ).pack(anchor='w')
        
        # Live stats
        stats_frame = tk.Frame(header_frame, bg='#0d1117')
        stats_frame.pack(side=tk.RIGHT, padx=20, pady=10)
        
        self.commands_label = tk.Label(
            stats_frame,
            text="📊 Commands: 0",
            font=('Consolas', 10),
            bg='#0d1117',
            fg='#58a6ff'
        )
        self.commands_label.pack(side=tk.LEFT, padx=10)
        
        self.jobs_label = tk.Label(
            stats_frame,
            text="⚙️ Jobs: 0",
            font=('Consolas', 10),
            bg='#0d1117',
            fg='#58a6ff'
        )
        self.jobs_label.pack(side=tk.LEFT, padx=10)
        
        # ===== DIRECTORY BAR =====
        dir_frame = tk.Frame(self.root, bg='#161b22', height=40)
        dir_frame.grid(row=1, column=0, sticky='ew', padx=0, pady=0)
        dir_frame.grid_propagate(False)
        
        tk.Label(
            dir_frame,
            text="📁",
            font=('Segoe UI', 13),
            bg='#161b22'
        ).pack(side=tk.LEFT, padx=(15, 5), pady=8)
        
        self.dir_label = tk.Label(
            dir_frame,
            text="",
            font=('Consolas', 10),
            bg='#161b22',
            fg='#58a6ff',
            anchor='w'
        )
        self.dir_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # ===== OUTPUT PANEL =====
        output_frame = tk.Frame(self.root, bg='#0d1117')
        output_frame.grid(row=2, column=0, sticky='nsew', padx=12, pady=12)
        output_frame.grid_rowconfigure(0, weight=1)
        output_frame.grid_columnconfigure(0, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            font=('Cascadia Code', 10),
            bg='#0d1117',
            fg='#c9d1d9',
            insertbackground='#58a6ff',
            state=tk.DISABLED,
            relief=tk.FLAT,
            padx=12,
            pady=12
        )
        self.output_text.grid(row=0, column=0, sticky='nsew')
        
        # Color tags for syntax highlighting
        self.output_text.tag_config('command', foreground='#a371f7', font=('Cascadia Code', 10, 'bold'))
        self.output_text.tag_config('output', foreground='#79c0ff')
        self.output_text.tag_config('error', foreground='#ff7b72', font=('Cascadia Code', 10, 'bold'))
        self.output_text.tag_config('info', foreground='#d29922')
        self.output_text.tag_config('success', foreground='#56d364')
        self.output_text.tag_config('header', foreground='#58a6ff', font=('Cascadia Code', 11, 'bold'))
        
        # ===== INPUT SECTION =====
        input_frame = tk.Frame(self.root, bg='#161b22')
        input_frame.grid(row=3, column=0, sticky='ew', padx=12, pady=(0, 12))
        input_frame.grid_columnconfigure(1, weight=1)
        
        tk.Label(
            input_frame,
            text="❯",
            font=('Cascadia Code', 16, 'bold'),
            bg='#161b22',
            fg='#56d364'
        ).grid(row=0, column=0, padx=(12, 5), pady=12)
        
        self.command_entry = tk.Entry(
            input_frame,
            font=('Cascadia Code', 11),
            bg='#0d1117',
            fg='#c9d1d9',
            insertbackground='#58a6ff',
            relief=tk.FLAT,
            bd=5
        )
        self.command_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=12)
        self.command_entry.bind('<Return>', lambda e: self.execute_command())
        self.command_entry.bind('<Up>', self.history_up)
        self.command_entry.bind('<Down>', self.history_down)
        self.command_entry.focus()
        
        # ===== BUTTON BAR =====
        button_frame = tk.Frame(self.root, bg='#161b22')
        button_frame.grid(row=4, column=0, sticky='ew', padx=12, pady=(0, 12))
        
        buttons = [
            ("🚀 Execute", self.execute_command, '#238636'),
            ("🗑️ Clear", self.clear_output, '#9e6a03'),
            ("📋 Jobs", self.show_jobs, '#1f6feb'),
            ("📜 Logs", self.show_logs, '#8957e5'),
            ("🚪 Exit", self.on_close, '#da3633'),
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(
                button_frame,
                text=text,
                command=command,
                bg=color,
                fg='white',
                font=('Segoe UI', 10, 'bold'),
                relief=tk.FLAT,
                padx=18,
                pady=10,
                cursor='hand2'
            )
            btn.pack(side=tk.LEFT, padx=5)
            
            # Hover effects
            btn.bind('<Enter>', lambda e, b=btn, c=color: b.config(bg=self._lighten_color(c)))
            btn.bind('<Leave>', lambda e, b=btn, c=color: b.config(bg=c))
        
        # ===== STATUS BAR =====
        status_frame = tk.Frame(self.root, bg='#0d1117', height=28)
        status_frame.grid(row=5, column=0, sticky='ew', padx=0, pady=0)
        status_frame.grid_propagate(False)
        
        self.status_label = tk.Label(
            status_frame,
            text="✓ Ready",
            font=('Consolas', 9),
            bg='#0d1117',
            fg='#56d364',
            anchor='w'
        )
        self.status_label.pack(side=tk.LEFT, padx=15)
        
        self.system_label = tk.Label(
            status_frame,
            text="💻 CPU: 0% | 🧠 RAM: 0% | Shell PID: " + str(os.getpid()),
            font=('Consolas', 9),
            bg='#0d1117',
            fg='#8b949e',
            anchor='e'
        )
        self.system_label.pack(side=tk.RIGHT, padx=15)
    
    def _show_welcome(self):
        """Display welcome message with OS concepts"""
        welcome = """
╔════════════════════════════════════════════════════════════════╗
║  🎓 MINI SHELL - Operating System Concepts Implementation  🎓  ║
╚════════════════════════════════════════════════════════════════╝

This shell demonstrates core OS concepts:
✓ Process Management & Scheduling
✓ Inter-Process Communication (Pipes)
✓ I/O Redirection & File System Operations
✓ Command Parsing & Interpretation
✓ System Calls & Process Control
✓ Security (AES Encryption)

Type 'help' for detailed command reference
All commands are logged with encryption for security

Ready to demonstrate OS concepts! 🚀
"""
        self.display_output(welcome, 'header')
    
    def _lighten_color(self, hex_color):
        """Lighten color for hover effect"""
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        lighter = tuple(min(255, int(c * 1.2)) for c in rgb)
        return f'#{lighter[0]:02x}{lighter[1]:02x}{lighter[2]:02x}'
    
    def execute_command(self):
        """Execute user command"""
        cmd = self.command_entry.get().strip()
        
        if not cmd:
            return
        
        # Add to history
        if not self.command_history or self.command_history[-1] != cmd:
            self.command_history.append(cmd)
        self.history_index = len(self.command_history)
        
        self.command_count += 1
        self.commands_label.config(text=f"📊 Commands: {self.command_count}")
        
        self.display_output(f"\n❯ {cmd}\n", 'command')
        self.command_entry.delete(0, tk.END)
        
        self.status_label.config(text="⚙️ Executing...", fg='#d29922')
        
        # Execute in separate thread
        thread = threading.Thread(target=self._execute_thread, args=(cmd,), daemon=True)
        thread.start()
    
    def _execute_thread(self, cmd):
        """Execute command in background thread"""
        # Check for exit command before execution
        if cmd.strip().lower() == 'exit':
            self.root.after(0, self.on_close)
            return
        
        self.executor.execute(cmd)
        
        # Update UI
        self.root.after(0, self.update_directory_display)
        self.root.after(0, self.update_jobs_count)
        self.root.after(0, lambda: self.status_label.config(text="✓ Ready", fg='#56d364'))
        
        # Check for special commands
        if "CLEAR_SCREEN" in cmd:
            self.root.after(0, self.clear_output)
    
    def display_output(self, text, tag='output'):
        """Display text in output panel"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text, tag)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def clear_output(self):
        """Clear output panel"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self._show_welcome()
    
    def show_jobs(self):
        """Display background process table"""
        status = self.process_manager.get_status()
        self.display_output(f"\n{'='*60}\n{status}{'='*60}\n", 'info')
    
    def show_logs(self):
        """Display encrypted command logs"""
        logs = self.logger.read_logs()
        self.display_output(f"\n{'='*60}\n📜 ENCRYPTED COMMAND HISTORY\n{'='*60}\n{logs}\n", 'info')
    
    def update_directory_display(self):
        """Update current directory display"""
        current = self.executor.current_dir
        if len(current) > 90:
            current = "..." + current[-87:]
        self.dir_label.config(text=current)
    
    def update_jobs_count(self):
        """Update background jobs counter"""
        count = len(self.process_manager.processes)
        self.jobs_label.config(text=f"⚙️ Jobs: {count}")
    
    def _start_system_monitor(self):
        """Start real-time system monitoring"""
        def update_system():
            try:
                cpu = psutil.cpu_percent(interval=1)
                ram = psutil.virtual_memory().percent
                self.system_label.config(
                    text=f"💻 CPU: {cpu:.1f}% | 🧠 RAM: {ram:.1f}% | Shell PID: {os.getpid()}"
                )
            except:
                pass
            self.root.after(2000, update_system)
        
        update_system()
    
    def history_up(self, event):
        """Navigate command history up"""
        if self.command_history and self.history_index > 0:
            self.history_index -= 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.history_index])
    
    def history_down(self, event):
        """Navigate command history down"""
        if self.command_history and self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.history_index])
        elif self.history_index == len(self.command_history) - 1:
            self.history_index += 1
            self.command_entry.delete(0, tk.END)
    
    def on_close(self):
        """
        Professional exit dialog
        Shows session statistics and cleanup information
        """
        # Kill all background processes
        job_count = len(self.process_manager.processes)
        
        # Simple confirmation if no background jobs
        if job_count == 0:
            if self._show_exit_dialog():
                self.process_manager.kill_all()
                self.root.quit()
                self.root.destroy()
        else:
            # Detailed dialog if background jobs exist
            if self._show_exit_dialog():
                self.process_manager.kill_all()
                self.root.quit()
                self.root.destroy()
    
    def _show_exit_dialog(self):
        """Show exit confirmation dialog and return True if user confirms"""
        # Create custom dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Exit Mini Shell")
        dialog.geometry("500x400")
        dialog.configure(bg='#0d1117')
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Variable to store user choice
        user_confirmed = [False]  # Using list to modify in nested function
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - 250
        y = (dialog.winfo_screenheight() // 2) - 200
        dialog.geometry(f"500x400+{x}+{y}")
        
        # Header
        header = tk.Frame(dialog, bg='#161b22', height=70)
        header.pack(fill=tk.X, padx=0, pady=0)
        header.pack_propagate(False)
        
        tk.Label(
            header,
            text="⚠️",
            font=('Segoe UI', 32),
            bg='#161b22',
            fg='#f85149'
        ).pack(side=tk.LEFT, padx=20)
        
        header_text = tk.Frame(header, bg='#161b22')
        header_text.pack(side=tk.LEFT, pady=15)
        
        tk.Label(
            header_text,
            text="Exit Mini Shell",
            font=('Segoe UI', 15, 'bold'),
            bg='#161b22',
            fg='#c9d1d9'
        ).pack(anchor='w')
        
        tk.Label(
            header_text,
            text="Confirm shell termination",
            font=('Segoe UI', 9),
            bg='#161b22',
            fg='#8b949e'
        ).pack(anchor='w')
        
        # Content
        content = tk.Frame(dialog, bg='#0d1117')
        content.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)
        
        tk.Label(
            content,
            text="Are you sure you want to exit?",
            font=('Segoe UI', 11, 'bold'),
            bg='#0d1117',
            fg='#c9d1d9'
        ).pack(anchor='w', pady=(0, 15))
        
        # Session statistics
        stats_frame = tk.Frame(content, bg='#161b22', relief=tk.FLAT)
        stats_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(
            stats_frame,
            text="📊 SESSION STATISTICS",
            font=('Segoe UI', 9, 'bold'),
            bg='#161b22',
            fg='#58a6ff'
        ).pack(anchor='w', padx=12, pady=(8, 5))
        
        stats = [
            ("Commands Executed:", str(self.command_count)),
            ("Background Jobs:", str(len(self.process_manager.processes))),
            ("Working Directory:", os.path.basename(self.executor.current_dir) or self.executor.current_dir),
            ("Session PID:", str(os.getpid()))
        ]
        
        for label, value in stats:
            row = tk.Frame(stats_frame, bg='#161b22')
            row.pack(fill=tk.X, padx=15, pady=3)
            
            tk.Label(
                row,
                text=label,
                font=('Consolas', 9),
                bg='#161b22',
                fg='#8b949e'
            ).pack(side=tk.LEFT)
            
            tk.Label(
                row,
                text=value,
                font=('Consolas', 9, 'bold'),
                bg='#161b22',
                fg='#79c0ff'
            ).pack(side=tk.RIGHT)
        
        # Warning for background jobs
        if len(self.process_manager.processes) > 0:
            warning_frame = tk.Frame(content, bg='#3d1b1b', relief=tk.FLAT)
            warning_frame.pack(fill=tk.X, pady=(15, 0))
            
            tk.Label(
                warning_frame,
                text="⚠️ WARNING",
                font=('Segoe UI', 9, 'bold'),
                bg='#3d1b1b',
                fg='#ff7b72'
            ).pack(anchor='w', padx=12, pady=(8, 5))
            
            tk.Label(
                warning_frame,
                text="All background processes will be terminated!",
                font=('Consolas', 9),
                bg='#3d1b1b',
                fg='#ffa198'
            ).pack(anchor='w', padx=12, pady=(0, 8))
        
        # Action info
        tk.Label(
            content,
            text="• All processes will be cleaned up\n• Command logs are saved (encrypted)\n• Session will terminate",
            font=('Consolas', 9),
            bg='#0d1117',
            fg='#8b949e',
            justify=tk.LEFT
        ).pack(anchor='w', pady=(15, 0))
        
        # Button frame
        button_frame = tk.Frame(dialog, bg='#0d1117')
        button_frame.pack(fill=tk.X, padx=25, pady=(0, 25))
        
        def confirm_exit():
            user_confirmed[0] = True
            dialog.destroy()
        
        def cancel_exit():
            user_confirmed[0] = False
            dialog.destroy()
        
        # Cancel button
        cancel_btn = tk.Button(
            button_frame,
            text="↩️ Cancel",
            command=cancel_exit,
            bg='#21262d',
            fg='#c9d1d9',
            font=('Segoe UI', 10, 'bold'),
            relief=tk.FLAT,
            padx=35,
            pady=12,
            cursor='hand2'
        )
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        
        # Exit button
        exit_btn = tk.Button(
            button_frame,
            text="✓ Exit Shell",
            command=confirm_exit,
            bg='#da3633',
            fg='white',
            font=('Segoe UI', 10, 'bold'),
            relief=tk.FLAT,
            padx=35,
            pady=12,
            cursor='hand2'
        )
        exit_btn.pack(side=tk.RIGHT, padx=5)
        
        # Hover effects
        def on_hover_exit(e):
            exit_btn.config(bg='#ff4444')
        def on_leave_exit(e):
            exit_btn.config(bg='#da3633')
        def on_hover_cancel(e):
            cancel_btn.config(bg='#30363d')
        def on_leave_cancel(e):
            cancel_btn.config(bg='#21262d')
        
        exit_btn.bind('<Enter>', on_hover_exit)
        exit_btn.bind('<Leave>', on_leave_exit)
        cancel_btn.bind('<Enter>', on_hover_cancel)
        cancel_btn.bind('<Leave>', on_leave_cancel)
        
        # Keyboard shortcuts
        dialog.bind('<Escape>', lambda e: cancel_exit())
        dialog.bind('<Return>', lambda e: confirm_exit())
        
        # Focus
        cancel_btn.focus()
        
        # Wait for dialog to close
        dialog.wait_window()
        
        return user_confirmed[0]

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """
    Launch Mini Shell
    Demonstrates OS concepts through practical implementation
    """
    root = tk.Tk()
    app = MiniShellGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()