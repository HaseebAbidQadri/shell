"""
Windows Mini Shell - Clean Command-Line Interface
=================================================
Minimal interface - commands only, no GUI buttons
Press Enter to execute commands
Press X to close terminal
Logs output to console/code editor

OS CONCEPTS: Process Management, IPC, I/O Redirection, Security
"""

import tkinter as tk
from tkinter import scrolledtext
import subprocess
import os
import threading
import sys
from datetime import datetime
from cryptography.fernet import Fernet

# Auto-install psutil
try:
    import psutil
except ImportError:
    print("[INSTALL] Installing psutil...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil

# ============================================================================
# CONSOLE LOGGING
# ============================================================================

def log(message, level="INFO"):
    """Log to console for debugging"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")
    sys.stdout.flush()

# ============================================================================
# ENCRYPTION MODULE
# ============================================================================

class EncryptedLogger:
    def __init__(self, log_file="shell_log.enc", key_file="shell.key"):
        self.log_file = log_file
        self.key_file = key_file
        self.cipher = self._initialize_encryption()
        log("Encryption initialized", "SYSTEM")
    
    def _initialize_encryption(self):
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
            log(f"Encryption error: {e}", "ERROR")
            return None
    
    def log_command(self, command, output="", error=""):
        if not self.cipher:
            return
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] {command}\n"
            if output:
                log_entry += f"OUT: {output[:200]}\n"
            if error:
                log_entry += f"ERR: {error[:200]}\n"
            log_entry += "-" * 40 + "\n"
            
            encrypted_data = self.cipher.encrypt(log_entry.encode())
            with open(self.log_file, 'ab') as f:
                f.write(encrypted_data + b'\n')
            log(f"Logged: {command[:50]}", "LOG")
        except Exception as e:
            log(f"Log error: {e}", "ERROR")
    
    def read_logs(self):
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
# COMMAND PARSER
# ============================================================================

class CommandParser:
    @staticmethod
    def parse_command(cmd_line):
        result = {'chains': [], 'background': False, 'original': cmd_line}
        
        if cmd_line.strip().endswith('&'):
            result['background'] = True
            cmd_line = cmd_line.strip()[:-1].strip()
        
        commands = [c.strip() for c in cmd_line.split(';') if c.strip()]
        for cmd in commands:
            result['chains'].append(CommandParser._parse_single_command(cmd))
        return result
    
    @staticmethod
    def _parse_single_command(cmd):
        result = {'pipes': [], 'input_file': None, 'output_file': None, 'append_file': None}
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
        
        clean_cmd = ' '.join(clean_parts)
        result['pipes'] = [p.strip() for p in clean_cmd.split('|') if p.strip()]
        return result

# ============================================================================
# PROCESS MANAGER
# ============================================================================

class ProcessManager:
    def __init__(self):
        self.processes = {}
        self.next_job_id = 1
        log("Process Manager initialized", "SYSTEM")
    
    def add_process(self, process, command):
        job_id = self.next_job_id
        self.next_job_id += 1
        self.processes[job_id] = {
            'process': process, 'command': command, 'pid': process.pid,
            'start_time': datetime.now(), 'status': 'Running'
        }
        log(f"Job [{job_id}] PID: {process.pid}", "PROCESS")
        return job_id
    
    def check_processes(self):
        completed = []
        for job_id, pcb in list(self.processes.items()):
            return_code = pcb['process'].poll()
            if return_code is not None:
                completed.append((job_id, pcb, return_code))
                log(f"Job [{job_id}] done: exit {return_code}", "PROCESS")
                del self.processes[job_id]
        return completed
    
    def get_status(self):
        if not self.processes:
            return "No background jobs.\n"
        status = "JOB | PID    | COMMAND\n" + "-" * 50 + "\n"
        for job_id, pcb in self.processes.items():
            status += f"[{job_id}]  {pcb['pid']:<6}  {pcb['command']}\n"
        return status
    
    def kill_all(self):
        count = len(self.processes)
        for pcb in self.processes.values():
            try:
                pcb['process'].terminate()
            except:
                pass
        self.processes.clear()
        log(f"Killed {count} process(es)", "CLEANUP")

# ============================================================================
# COMMAND EXECUTOR
# ============================================================================

class CommandExecutor:
    def __init__(self, output_callback, process_manager, logger):
        self.output_callback = output_callback
        self.process_manager = process_manager
        self.logger = logger
        self.current_dir = os.getcwd()
        log(f"Executor ready: {self.current_dir}", "SYSTEM")
    
    def execute(self, cmd_line):
        if not cmd_line.strip():
            return
        
        log(f"Execute: {cmd_line}", "CMD")
        parsed = CommandParser.parse_command(cmd_line)
        self._check_background_processes()
        
        for chain in parsed['chains']:
            try:
                output, error = self._execute_chain(chain, parsed['background'])
                self.logger.log_command(cmd_line, output, error)
                if output:
                    self.output_callback(output, 'output')
                if error:
                    self.output_callback(error, 'error')
            except Exception as e:
                error_msg = f"Error: {str(e)}"
                self.output_callback(error_msg, 'error')
                log(f"Exception: {e}", "ERROR")
    
    def _execute_chain(self, chain, background):
        pipes = chain['pipes']
        if not pipes:
            return "", ""
        
        first_cmd = pipes[0].strip().split()[0].lower()
        
        # Built-in commands
        if first_cmd == 'cd':
            return self._builtin_cd(pipes[0])
        elif first_cmd == 'help':
            return self._builtin_help()
        elif first_cmd == 'exit':
            log("Exit command", "CMD")
            return "EXIT_SHELL", ""
        elif first_cmd == 'jobs':
            return self.process_manager.get_status(), ""
        elif first_cmd == 'logs':
            return self.logger.read_logs(), ""
        elif first_cmd in ['clear', 'cls']:
            return "CLEAR_SCREEN", ""
        elif first_cmd == 'pwd':
            return self.current_dir + "\n", ""
        
        return self._execute_piped_commands(chain, background)
    
    def _execute_piped_commands(self, chain, background):
        pipes = chain['pipes']
        try:
            processes = []
            stdin_source = None
            
            if chain['input_file']:
                try:
                    stdin_source = open(chain['input_file'], 'r')
                except Exception as e:
                    return "", f"Cannot open: {e}"
            
            for i, cmd in enumerate(pipes):
                full_cmd = f'cmd.exe /c {cmd}'
                stdin = stdin_source if i == 0 and stdin_source else (processes[-1].stdout if i > 0 else None)
                
                process = subprocess.Popen(
                    full_cmd, stdin=stdin, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, cwd=self.current_dir,
                    text=True, shell=True
                )
                processes.append(process)
                if i > 0 and processes[-2].stdout:
                    processes[-2].stdout.close()
            
            if stdin_source:
                stdin_source.close()
            
            if background:
                job_id = self.process_manager.add_process(processes[-1], chain['pipes'][0])
                return f"✓ Job [{job_id}] started (PID: {processes[-1].pid})\n", ""
            
            output, error = processes[-1].communicate()
            
            if chain['output_file']:
                try:
                    with open(chain['output_file'], 'w') as f:
                        f.write(output)
                    return f"✓ Saved to: {chain['output_file']}\n", ""
                except Exception as e:
                    return output, f"Write error: {e}"
            
            if chain['append_file']:
                try:
                    with open(chain['append_file'], 'a') as f:
                        f.write(output)
                    return f"✓ Appended to: {chain['append_file']}\n", ""
                except Exception as e:
                    return output, f"Append error: {e}"
            
            return output, error
        except FileNotFoundError:
            return "", f"Command not found: {pipes[0].split()[0]}"
        except Exception as e:
            return "", f"Error: {str(e)}"
    
    def _check_background_processes(self):
        completed = self.process_manager.check_processes()
        for job_id, pcb, return_code in completed:
            status = "✓" if return_code == 0 else "✗"
            elapsed = (datetime.now() - pcb['start_time']).total_seconds()
            msg = f"{status} Job [{job_id}] done: {pcb['command']} (exit: {return_code}, time: {elapsed:.1f}s)\n"
            self.output_callback(msg, 'success' if return_code == 0 else 'info')
    
    def _builtin_cd(self, cmd):
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            return self.current_dir + "\n", ""
        target = parts[1].strip().strip('"')
        try:
            os.chdir(target)
            self.current_dir = os.getcwd()
            log(f"CD: {self.current_dir}", "CMD")
            return f"✓ {self.current_dir}\n", ""
        except Exception as e:
            return "", f"cd: {str(e)}\n"
    
    def _builtin_help(self):
        return """
╔══════════════════════════════════════════════════════════╗
║          MINI SHELL - Command Reference                  ║
╚══════════════════════════════════════════════════════════╝

COMMANDS:
  cd <path>      Change directory
  pwd            Print working directory
  help           Show this help
  exit           Exit shell
  jobs           List background jobs
  logs           View encrypted logs
  clear/cls      Clear screen

FEATURES:
  cmd &          Background execution
  cmd1 ; cmd2    Command chaining
  cmd1 | cmd2    Pipe output
  cmd > file     Redirect output
  cmd >> file    Append to file
  cmd < file     Input from file

EXAMPLES:
  dir
  cd C:\\Windows
  dir | findstr .txt > results.txt
  ping localhost &
  jobs
  cd Desktop ; dir ; echo Done

Press ENTER to execute commands
Press X button to close terminal
All commands logged with encryption

""", ""

# ============================================================================
# MINIMAL GUI
# ============================================================================

class MiniShellGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("▶ Mini Shell")
        self.root.geometry("1000x650")
        self.root.configure(bg='#0d1117')
        
        log("Starting Mini Shell", "SYSTEM")
        
        self.logger = EncryptedLogger()
        self.process_manager = ProcessManager()
        self.executor = CommandExecutor(self.display_output, self.process_manager, self.logger)
        
        self.command_history = []
        self.history_index = 0
        self.command_count = 0
        
        self._setup_gui()
        self.update_directory_display()
        self._start_monitor()
        
        # Direct close on X button
        self.root.protocol("WM_DELETE_WINDOW", self.close_immediately)
        
        self._show_welcome()
        log("Shell ready", "SYSTEM")
    
    def _setup_gui(self):
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Header
        header = tk.Frame(self.root, bg='#161b22', height=60)
        header.grid(row=0, column=0, sticky='ew')
        header.grid_propagate(False)
        
        tk.Label(header, text="▶ MINI SHELL", font=('Consolas', 16, 'bold'),
                bg='#161b22', fg='#58a6ff').pack(side=tk.LEFT, padx=20, pady=15)
        
        self.stats_label = tk.Label(header, text="Commands: 0 | Jobs: 0",
                                    font=('Consolas', 10), bg='#161b22', fg='#8b949e')
        self.stats_label.pack(side=tk.RIGHT, padx=20)
        
        # Directory bar
        dir_frame = tk.Frame(self.root, bg='#0d1117')
        dir_frame.grid(row=1, column=0, sticky='ew', padx=10, pady=5)
        
        tk.Label(dir_frame, text="📁", font=('Consolas', 12), bg='#0d1117').pack(side=tk.LEFT, padx=5)
        self.dir_label = tk.Label(dir_frame, text="", font=('Consolas', 10),
                                  bg='#0d1117', fg='#58a6ff', anchor='w')
        self.dir_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Output panel
        output_frame = tk.Frame(self.root, bg='#0d1117')
        output_frame.grid(row=2, column=0, sticky='nsew', padx=10, pady=5)
        output_frame.grid_rowconfigure(0, weight=1)
        output_frame.grid_columnconfigure(0, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, wrap=tk.WORD, font=('Cascadia Code', 10),
            bg='#0d1117', fg='#c9d1d9', insertbackground='#58a6ff',
            state=tk.DISABLED, relief=tk.FLAT, padx=10, pady=10
        )
        self.output_text.grid(row=0, column=0, sticky='nsew')
        
        # Color tags
        self.output_text.tag_config('command', foreground='#a371f7', font=('Cascadia Code', 10, 'bold'))
        self.output_text.tag_config('output', foreground='#79c0ff')
        self.output_text.tag_config('error', foreground='#ff7b72', font=('Cascadia Code', 10, 'bold'))
        self.output_text.tag_config('info', foreground='#d29922')
        self.output_text.tag_config('success', foreground='#56d364')
        self.output_text.tag_config('header', foreground='#58a6ff', font=('Cascadia Code', 11, 'bold'))
        
        # Input section
        input_frame = tk.Frame(self.root, bg='#161b22')
        input_frame.grid(row=3, column=0, sticky='ew', padx=10, pady=10)
        input_frame.grid_columnconfigure(1, weight=1)
        
        tk.Label(input_frame, text="❯", font=('Cascadia Code', 14, 'bold'),
                bg='#161b22', fg='#56d364').grid(row=0, column=0, padx=10, pady=10)
        
        self.command_entry = tk.Entry(
            input_frame, font=('Cascadia Code', 11), bg='#0d1117',
            fg='#c9d1d9', insertbackground='#58a6ff', relief=tk.FLAT, bd=5
        )
        self.command_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=10)
        self.command_entry.bind('<Return>', lambda e: self.execute_command())
        self.command_entry.bind('<Up>', self.history_up)
        self.command_entry.bind('<Down>', self.history_down)
        self.command_entry.focus()
        
        # Status bar
        status_frame = tk.Frame(self.root, bg='#0d1117', height=25)
        status_frame.grid(row=4, column=0, sticky='ew')
        status_frame.grid_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="✓ Ready", font=('Consolas', 9),
                                     bg='#0d1117', fg='#56d364', anchor='w')
        self.status_label.pack(side=tk.LEFT, padx=15)
        
        self.system_label = tk.Label(status_frame, text="CPU: 0% | RAM: 0%",
                                     font=('Consolas', 9), bg='#0d1117', fg='#8b949e', anchor='e')
        self.system_label.pack(side=tk.RIGHT, padx=15)
    
    def _show_welcome(self):
        welcome = """
╔══════════════════════════════════════════════════════════╗
║       🚀 MINI SHELL - OS Concepts Implementation 🚀      ║
╚══════════════════════════════════════════════════════════╝

Type commands and press ENTER to execute
Type 'help' for command reference
Type 'exit' to close (or press X button)
All commands are encrypted and logged

Ready for OS demonstrations! 🎓
"""
        self.display_output(welcome, 'header')
    
    def execute_command(self):
        cmd = self.command_entry.get().strip()
        if not cmd:
            return
        
        if not self.command_history or self.command_history[-1] != cmd:
            self.command_history.append(cmd)
        self.history_index = len(self.command_history)
        
        self.command_count += 1
        self.update_stats()
        
        self.display_output(f"\n❯ {cmd}\n", 'command')
        self.command_entry.delete(0, tk.END)
        self.status_label.config(text="⚙️ Executing...", fg='#d29922')
        
        threading.Thread(target=self._execute_thread, args=(cmd,), daemon=True).start()
    
    def _execute_thread(self, cmd):
        if cmd.strip().lower() == 'exit':
            log("Exit command received", "CMD")
            self.root.after(0, self.close_immediately)
            return
        
        self.executor.execute(cmd)
        self.root.after(0, self.update_directory_display)
        self.root.after(0, self.update_stats)
        self.root.after(0, lambda: self.status_label.config(text="✓ Ready", fg='#56d364'))
        
        if "CLEAR_SCREEN" in cmd:
            self.root.after(0, self.clear_output)
    
    def display_output(self, text, tag='output'):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text, tag)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self._show_welcome()
    
    def update_directory_display(self):
        current = self.executor.current_dir
        if len(current) > 80:
            current = "..." + current[-77:]
        self.dir_label.config(text=current)
    
    def update_stats(self):
        jobs = len(self.process_manager.processes)
        self.stats_label.config(text=f"Commands: {self.command_count} | Jobs: {jobs}")
    
    def _start_monitor(self):
        def update():
            try:
                cpu = psutil.cpu_percent(interval=1)
                ram = psutil.virtual_memory().percent
                self.system_label.config(text=f"CPU: {cpu:.0f}% | RAM: {ram:.0f}%")
            except:
                pass
            self.root.after(2000, update)
        update()
    
    def history_up(self, event):
        if self.command_history and self.history_index > 0:
            self.history_index -= 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.history_index])
    
    def history_down(self, event):
        if self.command_history and self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.history_index])
        elif self.history_index == len(self.command_history) - 1:
            self.history_index += 1
            self.command_entry.delete(0, tk.END)
    
    def close_immediately(self):
        """Close terminal immediately when X is pressed"""
        log(f"Closing shell - Executed {self.command_count} commands", "SYSTEM")
        self.process_manager.kill_all()
        self.root.quit()
        self.root.destroy()
        log("Shell terminated", "SYSTEM")

# ============================================================================
# MAIN
# ============================================================================

def main():
    log("="*60, "SYSTEM")
    log("MINI SHELL STARTING", "SYSTEM")
    log("="*60, "SYSTEM")
    root = tk.Tk()
    app = MiniShellGUI(root)
    root.mainloop()
    log("Shell closed", "SYSTEM")

if __name__ == "__main__":
    main()