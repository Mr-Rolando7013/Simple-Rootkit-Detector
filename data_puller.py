import psutil
import hashlib
import os
import json
from create_db import *
import json

# List of field names from /proc/[pid]/stat
stat_fields = [
    "pid", "comm", "state", "ppid", "pgrp", "session", "tty_nr", "tpgid", "flags",
    "minflt", "cminflt", "majflt", "cmajflt", "utime", "stime", "cutime", "cstime",
    "priority", "nice", "num_threads", "itrealvalue", "starttime", "vsize", "rss",
    "rsslim", "startcode", "endcode", "startstack", "kstkesp", "kstkeip", "signal",
    "blocked", "sigignore", "sigcatch", "wchan", "nswap", "cnswap", "exit_signal",
    "processor", "rt_priority", "policy", "delayacct_blkio_ticks", "guest_time",
    "cguest_time", "start_data", "end_data", "start_brk", "arg_start", "arg_end",
    "env_start", "env_end", "exit_code"
]

def read_proc_net():
    net_tcp_info = []
    net_tcp6_info = []
    net_udp_info = []
    net_udp6_info = []
    net_raw_info = []
    net_raw6_info = []
    net_unix_info = []
    net_dev_info = []
    net_arp_info = []
    net_route_info = []
    try:
        with open("/proc/net/tcp", "r") as f:
            next(f)  # Skip header line
            for line in f:
                net_tcp_info.append(line.strip().split())
        with open("/proc/net/tcp6", "r") as f:
            next(f)
            for line in f:
                net_tcp6_info.append(line.strip().split())
        with open("/proc/net/udp", "r") as f:
            next(f)
            for line in f:
                net_udp_info.append(line.strip().split())
        with open("/proc/net/udp6", "r") as f:
            next(f)
            for line in f:
                net_udp6_info.append(line.strip().split())
        with open("/proc/net/raw", "r") as f:
            next(f)
            for line in f:
                net_raw_info.append(line.strip().split())
        with open("/proc/net/raw6", "r") as f:
            next(f)
            for line in f:
                net_raw6_info.append(line.strip().split())
        with open("/proc/net/unix", "r") as f:
            next(f)
            for line in f:
                net_unix_info.append(line.strip().split())
        with open("/proc/net/dev", "r") as f:
            next(f)
            next(f)  # Skip two header lines
            for line in f:
                net_dev_info.append(line.strip().split())
        with open("/proc/net/arp", "r") as f:
            next(f)
            for line in f:
                net_arp_info.append(line.strip().split())
        with open("/proc/net/route", "r") as f:
            next(f)
            for line in f:
                net_route_info.append(line.strip().split())
    except FileNotFoundError:
        print("One of the /proc/net files does not exist.")
    except PermissionError:
        print("Permission denied when trying to read /proc/net files.")

def read_proc_meminfo():
    meminfo = {}
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                key, value = line.split(":", 1)
                meminfo[key.strip()] = value.strip()
        return json.dumps(meminfo, indent=4)
    except FileNotFoundError:
        print("The /proc/meminfo file does not exist.")
    except PermissionError:
        print("Permission denied when trying to read /proc/meminfo.")
    return None

def read_proc_uptime():
    try:
        with open("/proc/uptime", "r") as f:
            data = f.read().strip()
            uptime, idle_time = data.split()
            uptime_info = {
                "uptime_seconds": float(uptime),
                "idle_time_seconds": float(idle_time)
            }
            return json.dumps(uptime_info, indent=4)
    except FileNotFoundError:
        print("The /proc/uptime file does not exist.")
    except PermissionError:
        print("Permission denied when trying to read /proc/uptime.")
    return None


def read_proc_mounts():
    mounts = []
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    mount_info = {
                        "device": parts[0],
                        "mount_point": parts[1],
                        "fs_type": parts[2],
                        "options": parts[3],
                        "dump": int(parts[4]),
                        "pass": int(parts[5])
                    }
                    mounts.append(mount_info)
    except FileNotFoundError:
        print("The /proc/mounts file does not exist.")
    except PermissionError:
        print("Permission denied when trying to read /proc/mounts.")
    return json.dumps(mounts, indent=4)

def read_proc_modules():
    modules = []
    try:
        with open("/proc/modules", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    module_info = {
                        "name": parts[0],
                        "size": int(parts[1]),
                        "refcount": int(parts[2]),
                        "dependencies": parts[3].split(',') if parts[3] != '-' else [],
                        "state": parts[4],
                        "address": parts[5]
                    }
                    modules.append(module_info)
    except FileNotFoundError:
        print("The /proc/modules file does not exist.")
    except PermissionError:
        print("Permission denied when trying to read /proc/modules.")
    return json.dumps(modules, indent=4)

def read_stat_json(pid):
    with open(f"/proc/{pid}/stat", "r") as f:
        data = f.read()

    # comm (process name) is in parentheses and can have spaces
    first_paren = data.find('(')
    last_paren = data.rfind(')')
    comm = data[first_paren + 1:last_paren]

    # Split remaining fields
    pre = data[:first_paren].split()          # fields before comm
    post = data[last_paren + 1:].split()     # fields after comm

    all_values = pre + [comm] + post

    # Convert numeric fields to int where possible
    stat_dict = {}
    for i, field in enumerate(stat_fields):
        value = all_values[i]
        try:
            stat_dict[field] = int(value)
        except ValueError:
            stat_dict[field] = value  # comm (string)
    
    # Convert to JSON string
    return json.dumps(stat_dict, indent=4)


def read_fd_json(pid):
    # Im using version, but I pass a snpashot_id and that bs
    for file in os.listdir(f"/proc/{pid}/fd"):
        try:
            fd_dict = {}
            target = os.readlink(f"/proc/{pid}/fd/{file}")
            fd_dict[file] = {"target": target}
            print("Target:", target)
            with open(f"/proc/{pid}/fdinfo/{file}", "r") as f:
                info = f.read()
                print("FD Info:", info)
            fd_info = {}
            for line in info.strip().splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    fd_info[key.strip()] = value.strip()
            #Clasify inode (TO DO)

            # Merge parsed FD info into the dict
            fd_dict[file]["info"] = fd_info
        except (FileNotFoundError, PermissionError):
            continue
    return json.dumps(fd_dict, indent=4)

def decode_env_vars(data):
    """Decode NUL-separated environment variables into a dict."""
    env_vars = {}
    for pair in data.split(b'\0'):
        if b'=' in pair:
            key, val = pair.split(b'=', 1)
            env_vars[key.decode(errors='replace')] = val.decode(errors='replace')
    return env_vars
    

def add_proc_details():
    proc_directory = os.getcwd()  # Save current directory
    os.chdir('/proc')  # Change to /proc directory
    for pid in os.listdir('.'):
        status_info = {}
        if pid.isdigit():
            try:
                os.chdir(pid)
                try:
                    with open('cmdline', 'r') as f:
                        cmdline = f.read().replace('\x00', ' ').strip()
                        #print(f"PID: {pid}, CMDLINE: {cmdline}")

                except (FileNotFoundError, PermissionError):
                    notes = "Could not read cmdline"

                try:
                    with open('status', 'r') as f:
                        for line in f:
                            if ':' in line:
                                key, value = line.split(':', 1)
                                status_info[key.strip()] = value.strip()
                    #print(f"{pid} STATUS INFO: {status_info}")
                    name = status_info.get('Name', '')
                    uid = status_info.get('Uid', '')
                    gid = status_info.get('Gid', '')
                    state = status_info.get('State', '')
                    vmrss = status_info.get('VmRSS', '')
                    vmsize = status_info.get('VmSize', '')
                except (FileNotFoundError, PermissionError, json.JSONDecodeError):
                    notes = "Could not read status"
                    print("ERROR:", notes)

                try:
                    with open('environ', 'rb') as f:
                        data = f.read()
                        sha256 = hashlib.sha256(data).hexdigest()
                        env_vars = decode_env_vars(data)
                        #print(f"ENV HASH: {sha256}")
                        #print(f"ENVIRONMENT VARIABLES: {env_vars}")
                except (FileNotFoundError, PermissionError):
                    env_vars = None
                    sha256 = None

                try:
                    stat_info = read_stat_json(pid)
                    #print(f"STAT INFO: {stat_info}")
                except (FileNotFoundError, PermissionError):
                    pass

                try:
                    fd_info = read_fd_json(pid)
                    #print(f"FD INFO: {fd_info}")
                except (FileNotFoundError, PermissionError):
                    pass

                try:
                    with open('maps', 'r') as f:
                        maps_data = f.read()
                        #print(f"MAPS DATA: {maps_data}")
                except (FileNotFoundError, PermissionError):
                    pass
            except FileNotFoundError as e:
                print("Temp process:", e)

        else:
            continue
        os.chdir('/proc') 

    os.chdir(proc_directory)  # Restore original directory


def get_file_hash(file_path, chunk_size=8192):
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f :
            for chunk in iter(lambda: f.read(chunk_size), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None
    
def add_process_to_table():
    version = get_version_number()
    for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'create_time', 'cmdline', 'ppid', 'cwd', 'net_connections', 'status', 'memory_info']):
        print(proc.info)
        hashfile = get_file_hash(proc.info['exe']) if proc.info['exe'] else None
        print(f"Executable Hash: {hashfile}")
        proc.info['hashfile'] = hashfile
        temp = Process(
            pid=proc.info['pid'],
            name=proc.info['name'],
            username=proc.info['username'],
            exe=proc.info['exe'],
            create_time=str(proc.info['create_time']),
            cmdline=' '.join(proc.info['cmdline']) if proc.info['cmdline'] else None,
            ppid=proc.info['ppid'],
            cwd=proc.info['cwd'],
            net_connections=str(proc.info['net_connections']),
            status=proc.info['status'],
            memory_info=str(proc.info['memory_info']),
            hashfile=hashfile,
            version=version + 1
        )
        add_process(temp)

    #display_processes()
    return version + 1
    
def main():
    print("Do you want to create the database? (y/n): ")
    choice = input().strip().lower()
    if choice == 'y':
        create_db()
        add_process_to_table()
    print("Do you want to check the process security? (y/n): ")
    choice = input().strip().lower()
    if choice == 'y':
        version = add_process_to_table()
        check_process_baseline(version)

    print("Do you want to display proc details? (y/n): ")
    choice = input().strip().lower()
    if choice == 'y':
        add_proc_details()



if __name__ == "__main__":
    main()
