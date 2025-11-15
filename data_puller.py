import psutil
import hashlib
import os
import json
from create_db import *
import datetime
import time

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

def create_snapshot():
    timestamp = datetime.datetime.now().isoformat()
    hostname = os.uname().nodename
    temp = Snapshot(timestamp=timestamp, host=hostname)
    add_snapshot(temp)
    return temp.id

def read_and_add_proc_net(snap_id):
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
            next(f)
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
            next(f)
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

        temp = ProcNetInfo(
            snapshot_id=snap_id,
            net_tcp_info=json.dumps(net_tcp_info, indent=4),
            net_tcp6_info=json.dumps(net_tcp6_info, indent=4),
            net_udp_info=json.dumps(net_udp_info, indent=4),
            net_udp6_info=json.dumps(net_udp6_info, indent=4),
            net_raw_info=json.dumps(net_raw_info, indent=4),
            net_raw6_info=json.dumps(net_raw6_info, indent=4),
            net_unix_info=json.dumps(net_unix_info, indent=4),
            net_dev_info=json.dumps(net_dev_info, indent=4),
            net_arp_info=json.dumps(net_arp_info, indent=4),
            net_route_info=json.dumps(net_route_info, indent=4)
        )

        add_proc_net_info(temp)
    except FileNotFoundError:
        print("One of the /proc/net files does not exist.")
    except PermissionError:
        print("Permission denied when trying to read /proc/net files.")

# TO DO
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

# TO DO
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


def read_and_add_proc_mounts(snap_id):
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    temp = Mounts(
                        snapshot_id=snap_id,
                        device=parts[0],
                        mount_point=parts[1],
                        fs_type=parts[2],
                        options=parts[3],
                        parent_id=None
                    )
                    add_mount(temp)
    except FileNotFoundError:
        print("The /proc/mounts file does not exist.")
    except PermissionError:
        print("Permission denied when trying to read /proc/mounts.")

def read_and_add_proc_modules(snap_id):
    try:
        with open("/proc/modules", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    temp = Modules(
                        snapshot_id=snap_id,
                        name=parts[0],
                        size=int(parts[1]),
                        instances=int(parts[2]),
                        filename=parts[5],
                        state=parts[3]
                    )
                add_mount(temp)
    except FileNotFoundError:
        print("The /proc/modules file does not exist.")
    except PermissionError:
        print("Permission denied when trying to read /proc/modules.")

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


def read_and_add_fd_json(pid, snap_id):
    for file in os.listdir(f"/proc/{pid}/fd"):
        try:
            fd_dict = {}
            target = os.readlink(f"/proc/{pid}/fd/{file}")
            fd_dict[file] = {"target": target}
            #print("Target:", target)
            with open(f"/proc/{pid}/fdinfo/{file}", "r") as f:
                info = f.read()
                #print("FD Info:", info)
            fd_info = {}
            for line in info.strip().splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    fd_info[key.strip()] = value.strip()
            #Clasify inode (TO DO)

            # Merge parsed FD info into the dict
            fd_dict[file]["info"] = fd_info
            temp = Process_FDINFO(
                snapshot_id=snap_id,  # Placeholder
                pid=int(pid),
                fd=file,
                target=target,
                pos=fd_info.get("pos"),
                flags=fd_info.get("flags"),
                mnt_id=fd_info.get("mnt_id"),
                ino=fd_info.get("ino"),
                type=fd_info.get("type")
            )
            add_process_fdinfo(temp)
        except (FileNotFoundError, PermissionError):
            continue
    return json.dumps(fd_dict, indent=4)

def read_add_maps(pid, snapshot_id):
    try:
        # Open in binary mode ('rb') so we get bytes
        with open(f"/proc/{pid}/maps", 'rb') as f:
            for line in f:
                line = line.decode('utf-8').strip()
                parts = line.split(None, 5)  # Split into max 6 parts
                if len(parts) >= 5:
                    addr_range = parts[0]
                    permissions = parts[1]
                    offset = parts[2]
                    dev = parts[3]
                    inode = parts[4]
                    pathname = parts[5] if len(parts) == 6 else None

                    start_addr, end_addr = addr_range.split('-')

                    temp = Maps(
                        snapshot_id=snapshot_id,
                        pid=pid,
                        start_addr=start_addr,
                        end_addr=end_addr,
                        permissions=permissions,
                        offset=offset,
                        dev=dev,
                        inode=inode,
                        pathname=pathname
                        # raw_line=line  # If you want to store the raw line
                    )
                    add_maps(temp)

    except (FileNotFoundError, PermissionError) as e:
        print(f"Cannot read /proc/{pid}/maps: {e}")
        return
    
def add_proc_details(snap_id, pid, cwd, uid, gid, environ, fd_info, suspicious_flags, cmdline, notes, stat_info):
    temp = ProcDetails(
        snapshot_id=snap_id,
        pid=int(pid),
        cwd=cwd,
        uid=uid,
        gid=gid,
        env_vars=environ,
        fd_count=len(json.loads(fd_info)) if fd_info else 0,
        suspicious_flags=suspicious_flags,
        cmdline=cmdline,
        notes=notes,
        stat_json=stat_info
    )
    add_to_db_proc_details(temp)


def add_proc_info(snap_id):
    proc_directory = os.getcwd()  # Save current directory
    os.chdir('/proc')  # Change to /proc directory
    notes = ""
    
    # -------------------------------------
    # Read and process mounts and modules
    # This works
    read_and_add_proc_mounts(snap_id)
    #display_mounts()

    # This one works   
    # TO DO: State field is not being stored correctly: "-" instead of "Live"
    read_and_add_proc_modules(snap_id)
    #display_modules()

    # -------------------------------------
    # This works
    # Read network info
    read_and_add_proc_net(snap_id)
    #display_proc_net_info()

    for pid in os.listdir('.'):
        status_info = {}
        if pid.isdigit():
            # -------------------------------------
            # This works
            try:
                cwd_path = os.readlink(f"/proc/{pid}/cwd")
                #print(f"Process {pid} cwd: {cwd_path}")
            except FileNotFoundError:
                print("Process does not exist anymore.")
            except PermissionError:
                print("No permission to read cwd of this process.")
            
            # -------------------------------------
            # This works
            try:
                os.chdir(pid)
                try:
                    with open('cmdline', 'r') as f:
                        cmdline = f.read().replace('\x00', ' ').strip()
                        #print(f"PID: {pid}, CMDLINE: {cmdline}")

                except (FileNotFoundError, PermissionError):
                    notes = "Could not read cmdline"

                # -------------------------------------
                # This works
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
                
                # -------------------------------------
                # This works
                try:
                    with open('environ', 'rb') as f:
                        environ = f.read()

                except (FileNotFoundError, PermissionError):
                    print("Could not read environ")


                # -------------------------------------
                # Get stat info
                # This works
                stat_info = read_stat_json(pid)
                #print(f"STAT INFO: {stat_info}")
                

                #------------------------------------
                fd_info = read_and_add_fd_json(pid, snap_id)
                #print(f"FD INFO: {fd_info}")

                # This works
                read_add_maps(pid, snap_id)
                display_maps()

                add_proc_details(snap_id, pid, cwd_path, uid, gid, environ, fd_info, None, cmdline, notes, stat_info)
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
    
def add_process_to_table(snap_id):
    for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'create_time', 'cmdline', 'ppid', 'cwd', 'net_connections', 'status', 'memory_info']):
        #print(proc.info)
        hashfile = get_file_hash(proc.info['exe']) if proc.info['exe'] else None
        proc.info['hashfile'] = hashfile
        temp = Process(
            snapshot_id=snap_id,
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
        )
        add_process(temp)

    #display_processes()
    
def main():
    print("Do you want to create the database? (y/n): ")
    choice = input().strip().lower()
    if choice == 'y':
        create_db()
    print("Start checking the system... (y/n)")
    choice = input().strip().lower()
    counter = 0
    if choice == 'y':
        while counter <= 3:
            temp_snap_id = create_snapshot()
            add_process_to_table(temp_snap_id)
            add_proc_info(temp_snap_id)
            check_process_baseline(temp_snap_id)
            counter += 1
            print("Waiting for the next check...")
            time.sleep(60)



if __name__ == "__main__":
    main()
