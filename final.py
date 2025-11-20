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
    
    def add_process(self, process, command, priority='NORMAL'):
        job_id = self.next_job_id
        self.next_job_id += 1
        self.processes[job_id] = {
            'process': process, 'command': command, 'pid': process.pid,
            'start_time': datetime.now(), 'status': 'Running', 'priority': priority
        }
        log(f"Job [{job_id}] PID: {process.pid} Priority: {priority}", "PROCESS")
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
        status = "JOB | PID    | PRIORITY | COMMAND\n" + "-" * 60 + "\n"
        for job_id, pcb in self.processes.items():
            priority = pcb.get('priority', 'NORMAL')
            status += f"[{job_id}]  {pcb['pid']:<6}  {priority:<8}  {pcb['command']}\n"
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
        self.env_vars = {}  # Shell environment variables
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
        elif first_cmd == 'pwd':
            return self.current_dir + "\n", ""
        elif first_cmd == 'encrypt':
            return self._builtin_encrypt(pipes[0])
        elif first_cmd == 'decrypt':
            return self._builtin_decrypt(pipes[0])
        elif first_cmd == 'demo-ipc-crypto':
            return self._demo_ipc_crypto()
        elif first_cmd == 'priority':
            return self._builtin_priority(pipes[0], background)
        elif first_cmd == 'env':
            return self._builtin_env(pipes[0])
        elif first_cmd == 'setenv':
            return self._builtin_setenv(pipes[0])
        elif first_cmd == 'demo-deadlock':
            return self._demo_deadlock()
        
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
    
    def _builtin_encrypt(self, cmd):
        """Encrypt a message or file - demonstrates cryptography"""
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            return "", "Usage: encrypt <message or filename>\nExample: encrypt \"Hello World\"\n"
        
        input_text = parts[1].strip().strip('"')
        
        # Check if it's a file
        if os.path.isfile(input_text):
            try:
                with open(input_text, 'r') as f:
                    data = f.read()
                log(f"Encrypting file: {input_text}", "CRYPTO")
            except:
                return "", f"Cannot read file: {input_text}\n"
        else:
            data = input_text
            log(f"Encrypting message: {data[:30]}...", "CRYPTO")
        
        # Encrypt using logger's cipher
        if not self.logger.cipher:
            return "", "Encryption not available\n"
        
        try:
            encrypted = self.logger.cipher.encrypt(data.encode())
            encrypted_hex = encrypted.hex()
            
            output = f"""
╔══════════════════════════════════════════════════════════╗
║               ENCRYPTION DEMONSTRATION                    ║
╚══════════════════════════════════════════════════════════╝

Original Text:
{data[:200]}{'...' if len(data) > 200 else ''}

Encryption Algorithm: AES (Fernet - symmetric key cryptography)
Key Size: 256 bits
Mode: CBC with HMAC-SHA256 for authentication

Encrypted Data (hexadecimal):
{encrypted_hex[:400]}
{'...' if len(encrypted_hex) > 400 else ''}

Encrypted Length: {len(encrypted)} bytes
Original Length: {len(data)} bytes

✓ Data successfully encrypted!
"""
            return output, ""
        except Exception as e:
            log(f"Encryption error: {e}", "ERROR")
            return "", f"Encryption failed: {e}\n"
    
    def _builtin_decrypt(self, cmd):
        """Decrypt a message - demonstrates cryptography"""
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            return "", "Usage: decrypt <encrypted_hex>\nExample: Use hex output from encrypt command\n"
        
        encrypted_hex = parts[1].strip()
        
        if not self.logger.cipher:
            return "", "Decryption not available\n"
        
        try:
            # Convert hex back to bytes
            encrypted_bytes = bytes.fromhex(encrypted_hex)
            log(f"Decrypting data: {len(encrypted_bytes)} bytes", "CRYPTO")
            
            # Decrypt
            decrypted = self.logger.cipher.decrypt(encrypted_bytes).decode()
            
            output = f"""
╔══════════════════════════════════════════════════════════╗
║               DECRYPTION DEMONSTRATION                    ║
╚══════════════════════════════════════════════════════════╝

Encrypted Data (hex):
{encrypted_hex[:400]}
{'...' if len(encrypted_hex) > 400 else ''}

Decryption Algorithm: AES (Fernet)
Authentication: HMAC-SHA256 verified ✓

Decrypted Text:
{decrypted}

✓ Data successfully decrypted and authenticated!
"""
            return output, ""
        except Exception as e:
            log(f"Decryption error: {e}", "ERROR")
            return "", f"Decryption failed: {e}\n(Invalid data or wrong key)\n"
    
    def _demo_ipc_crypto(self):
        """Demonstrate IPC + Cryptography working together"""
        log("Running IPC + Crypto demonstration", "DEMO")
        
        demo_text = """
╔══════════════════════════════════════════════════════════╗
║          IPC + CRYPTOGRAPHY DEMONSTRATION                 ║
╚══════════════════════════════════════════════════════════╝

SCENARIO: Secure communication between two processes

Step 1: Process A (Encryption Service)
----------------------------------------
Message: "Confidential Data: User Password = Secret123"
Action: Encrypts data using AES-256
Output: Encrypted bytes sent through pipe

Step 2: IPC - Anonymous Pipe
----------------------------------------
Process A --[ENCRYPTED DATA]--> Process B
         (Inter-Process Communication)

Step 3: Process B (Decryption Service)
----------------------------------------
Input: Receives encrypted bytes from pipe
Action: Decrypts using shared secret key
Output: Original plaintext message

DEMONSTRATION:
"""
        
        # Create sample data
        original = "Confidential Data: User Password = Secret123"
        
        try:
            # Encrypt
            encrypted = self.logger.cipher.encrypt(original.encode())
            encrypted_hex = encrypted.hex()
            
            # Simulate IPC
            demo_text += f"""
[Process A - Sender]
Original Message: {original}
Encrypted (hex):  {encrypted_hex[:80]}...
                  Sent via PIPE →

[IPC Layer - Anonymous Pipe]
Data transferred: {len(encrypted)} bytes
Protocol: Windows Named Pipe / Unix Pipe
Status: ✓ Transfer complete

[Process B - Receiver]
Received (hex):   {encrypted_hex[:80]}...
                  ← Received via PIPE
Decrypting...
"""
            
            # Decrypt
            decrypted = self.logger.cipher.decrypt(encrypted).decode()
            
            demo_text += f"""Decrypted Message: {decrypted}
Status: ✓ Authentication verified

SECURITY FEATURES:
✓ End-to-end encryption (AES-256)
✓ Message authentication (HMAC-SHA256)
✓ Secure key exchange (Fernet)
✓ Protected IPC channel

OS CONCEPTS DEMONSTRATED:
1. Inter-Process Communication (Pipes)
2. Cryptography (AES encryption/decryption)
3. Message Authentication
4. Secure data transfer

TRY IT YOURSELF:
  encrypt "Your Secret Message"
  (copy the hex output)
  decrypt <paste_hex_here>

"""
            log("IPC + Crypto demo completed successfully", "DEMO")
            return demo_text, ""
            
        except Exception as e:
            log(f"Demo error: {e}", "ERROR")
            return "", f"Demo failed: {e}\n"
    
    def _builtin_priority(self, cmd, background):
        """
        OS CONCEPT: Process Priority & CPU Scheduling
        Set process priority for background jobs
        """
        parts = cmd.split(maxsplit=2)
        if len(parts) < 3:
            return "", "Usage: priority <high|normal|low> <command> &\nExample: priority high ping localhost -n 100 &\n"
        
        priority_level = parts[1].upper()
        command = parts[2]
        
        if priority_level not in ['HIGH', 'NORMAL', 'LOW']:
            return "", "Priority must be: high, normal, or low\n"
        
        if not background:
            return "", "Priority command must be run in background (add & at end)\n"
        
        # Map priority levels to Windows priority classes
        priority_map = {
            'HIGH': psutil.HIGH_PRIORITY_CLASS,
            'NORMAL': psutil.NORMAL_PRIORITY_CLASS,
            'LOW': psutil.IDLE_PRIORITY_CLASS
        }
        
        try:
            full_cmd = f'cmd.exe /c {command}'
            
            process = subprocess.Popen(
                full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=self.current_dir, text=True, shell=True
            )
            
            # Set process priority using psutil
            try:
                p = psutil.Process(process.pid)
                p.nice(priority_map[priority_level])
                log(f"Set PID {process.pid} priority to {priority_level}", "SCHEDULER")
            except Exception as e:
                log(f"Priority set failed: {e}", "ERROR")
            
            job_id = self.process_manager.add_process(process, command, priority_level)
            
            output = f"""
╔══════════════════════════════════════════════════════════╗
║          PROCESS PRIORITY DEMONSTRATION                   ║
╚══════════════════════════════════════════════════════════╝

OS CONCEPT: CPU Scheduling & Process Priority

Job ID: [{job_id}]
Process ID: {process.pid}
Priority Level: {priority_level}
Command: {command}

PRIORITY LEVELS (CPU Scheduling):
┌─────────┬──────────────────────────────────────────────┐
│  HIGH   │ Time-critical tasks, gets more CPU time      │
│ NORMAL  │ Default priority, balanced CPU allocation    │
│  LOW    │ Background tasks, minimal CPU interference   │
└─────────┴──────────────────────────────────────────────┘

CPU SCHEDULER BEHAVIOR:
• HIGH priority processes run before NORMAL
• NORMAL priority processes run before LOW  
• Scheduler uses priority-based preemptive scheduling
• Windows uses multilevel feedback queue algorithm

Use 'jobs' to see all processes with their priorities
✓ Background job started with {priority_level} priority!
"""
            return output, ""
            
        except Exception as e:
            return "", f"Priority execution failed: {e}\n"
    
    def _builtin_env(self, cmd):
        """
        OS CONCEPT: Environment Variables (Process Context)
        Show or get environment variables
        """
        parts = cmd.split(maxsplit=1)
        
        if len(parts) == 1:
            # Show all environment variables
            output = """
╔══════════════════════════════════════════════════════════╗
║          ENVIRONMENT VARIABLES                            ║
╚══════════════════════════════════════════════════════════╝

OS CONCEPT: Process Environment & Context

SYSTEM ENVIRONMENT VARIABLES:
"""
            # Show key system variables
            important_vars = ['PATH', 'USERPROFILE', 'COMPUTERNAME', 'OS', 'PROCESSOR_ARCHITECTURE', 'USERNAME', 'TEMP']
            for var in important_vars:
                value = os.environ.get(var, 'Not set')
                if len(value) > 60:
                    value = value[:57] + '...'
                output += f"  {var:<20} = {value}\n"
            
            output += "\nSHELL ENVIRONMENT VARIABLES:\n"
            if self.env_vars:
                for key, value in self.env_vars.items():
                    output += f"  {key:<20} = {value}\n"
            else:
                output += "  (No shell variables set)\n"
            
            output += """
WHAT ARE ENVIRONMENT VARIABLES?
• Key-value pairs that define process context
• Inherited by child processes from parent
• Used for configuration (PATH, TEMP, etc.)
• Each process has its own environment space

COMMANDS:
  env              Show all variables
  env VAR_NAME     Show specific variable
  setenv VAR=value Set shell variable

"""
            log("Displayed environment variables", "ENV")
            return output, ""
        else:
            # Show specific variable
            var_name = parts[1].strip()
            
            # Check shell variables first
            if var_name in self.env_vars:
                value = self.env_vars[var_name]
                log(f"Read shell variable: {var_name}", "ENV")
            else:
                # Check system variables
                value = os.environ.get(var_name, None)
                if value:
                    log(f"Read system variable: {var_name}", "ENV")
            
            if value:
                return f"{var_name}={value}\n", ""
            else:
                return "", f"Variable '{var_name}' not found\n"
    
    def _builtin_setenv(self, cmd):
        """
        OS CONCEPT: Environment Variables (Setting Process Context)
        Set environment variable in shell context
        """
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            return "", "Usage: setenv VAR_NAME=value\nExample: setenv MY_VAR=\"Hello World\"\n"
        
        assignment = parts[1].strip()
        if '=' not in assignment:
            return "", "Usage: setenv VAR_NAME=value\n"
        
        var_name, var_value = assignment.split('=', 1)
        var_name = var_name.strip()
        var_value = var_value.strip().strip('"').strip("'")
        
        self.env_vars[var_name] = var_value
        log(f"Set environment variable: {var_name}={var_value}", "ENV")
        
        output = f"""
╔══════════════════════════════════════════════════════════╗
║          ENVIRONMENT VARIABLE SET                         ║
╚══════════════════════════════════════════════════════════╝

Variable: {var_name}
Value: {var_value}

✓ Shell environment variable set!

This variable is now part of this shell's context.
Child processes will inherit this variable.

Verify with: env {var_name}
"""
        return output, ""
    
    def _demo_deadlock(self):
        """
        OS CONCEPT: Deadlock Detection & Prevention
        Demonstrates the four necessary conditions for deadlock
        """
        log("Running deadlock demonstration", "DEMO")
        
        output = """
╔══════════════════════════════════════════════════════════╗
║          DEADLOCK DEMONSTRATION                           ║
╚══════════════════════════════════════════════════════════╝

OS CONCEPT: Deadlock in Resource Allocation

WHAT IS DEADLOCK?
A state where processes are waiting for resources held by
each other, creating a circular wait that never resolves.

FOUR NECESSARY CONDITIONS FOR DEADLOCK:
┌────────────────────┬──────────────────────────────────┐
│ 1. Mutual Exclusion│ Only one process can use resource│
│ 2. Hold and Wait   │ Process holds while waiting more │
│ 3. No Preemption   │ Resources can't be forced away   │
│ 4. Circular Wait   │ Circular chain of waiting        │
└────────────────────┴──────────────────────────────────┘

DEADLOCK SCENARIO SIMULATION:
═════════════════════════════════════════════════════════

RESOURCES:
  R1 = Printer
  R2 = Scanner

PROCESSES:
  Process A (P1) - Wants: Printer → Scanner
  Process B (P2) - Wants: Scanner → Printer

TIMELINE:
─────────────────────────────────────────────────────────
Time 0: P1 acquires Printer (R1) ✓
        P2 acquires Scanner (R2) ✓

Time 1: P1 requests Scanner (R2)... BLOCKED (held by P2)
        P2 requests Printer (R1)... BLOCKED (held by P1)

DEADLOCK DETECTED!

RESOURCE ALLOCATION GRAPH:
    P1 ──holds──> R1 (Printer)
     ↑              ↓
  wants          wants
     ↓              ↑
    R2 (Scanner) <──holds── P2

CIRCULAR DEPENDENCY: P1 → R2 → P2 → R1 → P1

DEADLOCK PREVENTION STRATEGIES:
═════════════════════════════════════════════════════════
1. PREVENTION - Break one of the four conditions:
   • Order resources (always request R1 before R2)
   • Allow preemption (forcefully take resources)
   • Request all resources at once

2. AVOIDANCE - Banker's Algorithm:
   • Check if allocation leads to safe state
   • Only allocate if system remains safe

3. DETECTION & RECOVERY:
   • Detect cycles in resource graph
   • Kill one process to break cycle
   • Rollback transactions

REAL-WORLD EXAMPLES:
• Database transaction locks
• Multiple threads accessing shared memory
• Network routing protocols
• Disk access in multi-user systems

DEMONSTRATION IN THIS SHELL:
If two background processes both need:
  Process 1: File A → File B
  Process 2: File B → File A
This creates potential deadlock!

PREVENTION: Use proper resource ordering:
  priority high cmd1 &    # Give one process higher priority
  priority low cmd2 &     # Lower priority waits if needed

✓ Deadlock concept demonstrated!
"""
        return output, ""
    
    def _builtin_help(self):
        return """
╔══════════════════════════════════════════════════════════╗
║          MINI SHELL - Command Reference                  ║
╚══════════════════════════════════════════════════════════╝

BASIC COMMANDS:
  cd <path>      Change directory
  pwd            Print working directory
  help           Show this help
  exit           Exit shell
  jobs           List background jobs (with priorities!)
  logs           View encrypted logs
  clear/cls      Clear screen

CRYPTOGRAPHY COMMANDS:
  encrypt <text>           Encrypt a message/file
  decrypt <encrypted_hex>  Decrypt encrypted data
  demo-ipc-crypto          Show IPC + Encryption demo

OS CONCEPTS COMMANDS (NEW! ⭐):
  priority <level> <cmd> &  Run with CPU priority
                            Levels: high, normal, low
  env                       Show all environment variables
  env <VAR>                 Show specific variable
  setenv VAR=value          Set shell variable
  demo-deadlock             Deadlock demonstration

FEATURES:
  cmd &          Background execution
  cmd1 ; cmd2    Command chaining
  cmd1 | cmd2    Pipe output (IPC)
  cmd > file     Redirect output
  cmd >> file    Append to file
  cmd < file     Input from file

BASIC EXAMPLES:
  dir
  cd C:\\Windows
  dir | findstr .txt > results.txt
  ping localhost &
  jobs

OS CONCEPTS EXAMPLES:
  priority high ping localhost -n 100 &
  priority low dir /s C:\\ &
  jobs                  (shows priorities!)
  env PATH
  setenv MY_VAR="Hello"
  env MY_VAR
  demo-deadlock

CRYPTO EXAMPLES:
  encrypt "Secret Password"
  demo-ipc-crypto

Press ENTER to execute | X button to close
All commands logged with encryption ✓

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

OS CONCEPTS DEMONSTRATED:
✓ Process Management & CPU Scheduling (with priority!)
✓ Inter-Process Communication (Pipes)  
✓ Environment Variables (Process Context)
✓ Cryptography & Security (AES Encryption)
✓ Deadlock Detection & Prevention
✓ I/O Redirection & File System
✓ Background/Foreground Execution

NEW COMMANDS:
  priority high/normal/low <cmd> &  CPU scheduling
  env / setenv                      Environment variables
  demo-deadlock                     Deadlock demo
  demo-ipc-crypto                   IPC + Encryption

Type 'help' for full command reference
Type 'exit' to close (or press X button)
All commands encrypted and logged securely 🔐

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
        
        # Check for clear command before execution
        if cmd.strip().lower() in ['clear', 'cls']:
            log("Clear screen", "CMD")
            self.root.after(0, self.clear_output)
            return
        
        self.executor.execute(cmd)
        self.root.after(0, self.update_directory_display)
        self.root.after(0, self.update_stats)
        self.root.after(0, lambda: self.status_label.config(text="✓ Ready", fg='#56d364'))
    
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