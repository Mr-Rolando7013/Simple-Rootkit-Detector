from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

DABASE_URL = "sqlite:///info.db"

engine = create_engine(DABASE_URL, echo=True)

#create a base for models
Base = declarative_base()

class Snapshot(Base):
    __tablename__ = 'snapshots'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(String, nullable=False)
    host = Column(String, nullable=True)

    def __repr__(self):
        return f"<Snapshot(id={self.id}, timestamp='{self.timestamp}', description='{self.host}')>"

# Define process model

class Process(Base):
    __tablename__ = 'processes'
    
    id = Column(Integer, primary_key=True)
    pid = Column(Integer, nullable=False)
    name = Column(String, nullable=False)
    username = Column(String, nullable=False)
    exe = Column(String, nullable=True)
    create_time = Column(String, nullable=False)
    cmdline = Column(String, nullable=True)
    ppid = Column(Integer, nullable=False)
    cwd = Column(String, nullable=True)
    net_connections = Column(String, nullable=True)
    status = Column(String, nullable=False)
    memory_info = Column(String, nullable=True)
    hashfile = Column(String, nullable=True)
    version = Column(Integer, nullable=False)

    def __repr__(self):
        return f"<Process(id={self.id}, pid={self.pid}, name='{self.name}', username='{self.username}')>"
    
class Process_FDINFO(Base):
    __tablename__ = 'process_fdinfo'
    
    id = Column(Integer, primary_key=True)
    snapshot_id = Column(Integer, nullable=False)
    pid = Column(Integer, nullable=False)
    fd = Column(String, nullable=False)
    target = Column(String, nullable=True)
    pos = Column(String, nullable=True)
    flags = Column(String, nullable=True)
    mnt_id = Column(String, nullable=True)
    ino = Column(String, nullable=True)
    type = Column(String, nullable=True)

# To Do
class Sockets(Base):
    __tablename__ = 'sockets'
    id = Column(Integer, primary_key=True)
    snapshot_id = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)
    local_address = Column(String, nullable=True)
    remote_address = Column(String, nullable=True)
    inode = Column(String, nullable=True)
    state = Column(String, nullable=True)

class Mounts(Base):
    __tablename__ = 'mounts'
    id = Column(Integer, primary_key=True)
    snapshot_id = Column(Integer, nullable=False)
    device = Column(String, nullable=False)
    mount_point = Column(String, nullable=False)
    fs_type = Column(String, nullable=True)
    options = Column(String, nullable=True)
    parent_id = Column(Integer, nullable=True)

class Modules(Base):
    __tablename__ = 'modules'
    id = Column(Integer, primary_key=True)
    snapshot_id = Column(Integer, nullable=False)
    name = Column(String, nullable=False)
    size = Column(Integer, nullable=True)
    instances = Column(Integer, nullable=True)
    filename = Column(String, nullable=True)
    state = Column(String, nullable=True)

class ProcDetails(Base):
    __tablename__ = 'proc_details'
    id = Column(Integer, primary_key=True)
    snapshot_id = Column(Integer, nullable=False)
    pid = Column(Integer, nullable=False)
    cwd = Column(String, nullable=True)
    uid = Column(String, nullable=True)
    gid = Column(String, nullable=True)
    env_vars = Column(String, nullable=True)
    fd_count = Column(Integer, nullable=True)
    suspicious_flags = Column(String, nullable=True)
    cmdline = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    version = Column(Integer, nullable=False)
    stat_json = Column(String, nullable=True)

    def __repr__(self):
        return f"<ProcDetails(id={self.id}, pid={self.pid}, cwd='{self.cwd}')>"

class ProcNetInfo(Base):
    __tablename__ =  "proc_net_info"
    id = Column(Integer, primary_key=True)
    snapshot_id = Column(Integer, nullable=False)
    net_tcp_info = Column(String, nullable=True)
    net_tcp6_info = Column(String, nullable=True)
    net_udp_info = Column(String, nullable=True)
    net_udp6_info = Column(String, nullable=True)
    net_raw_info = Column(String, nullable=True)
    net_raw6_info = Column(String, nullable=True)
    net_unix_info = Column(String, nullable=True)
    net_dev_info = Column(String, nullable=True)
    net_arp_info = Column(String, nullable=True)
    net_route_info = Column(String, nullable=True)

    def __repr__(self):
        return f"<ProcNetInfo(id={self.id})>"

def create_db():
    # Create all tables
    Base.metadata.create_all(engine)

# Create a configured "Session"
Session = sessionmaker(bind=engine)
session = Session()

def add_snapshot(snapshot):
    session.add(snapshot)
    session.commit()

def add_process(process_info):
    session.add(process_info)
    session.commit()

def add_proc_details(proc_details):
    session.add(proc_details)
    session.commit()

def add_snapshot(snapshot):
    session.add(snapshot)
    session.commit()

def add_mount(mount):
    session.add(mount)
    session.commit()

def add_modules(module):
    session.add(module)
    session.commit()

def add_proc_net_info(proc_net_info):
    session.add(proc_net_info)
    session.commit()

def add_process_fdinfo(process_fdinfo):
    session.add(process_fdinfo)
    session.commit()

def get_version_number():
    latest_version = session.query(Process).order_by(Process.version.desc()).first()
    return latest_version.version if latest_version else 0

def display_processes():
    processes = session.query(Process).all()
    for process in processes:
        print(process)

def display_proc_details():
    proc_details = session.query(ProcDetails).all()
    for detail in proc_details:
        print(detail)

def display_mounts():
    mounts = session.query(Mounts).all()
    for mount in mounts:
        print(mount)

def display_modules():
    modules = session.query(Modules).all()
    for module in modules:
        print(module)

def display_proc_net_info():
    proc_net_infos = session.query(ProcNetInfo).all()
    for info in proc_net_infos:
        print(info)

def check_process_baseline(version):
    current_processes = session.query(Process).filter_by(version=version).all()
    for current_process in current_processes:
        differences = {}
        baseline_process = session.query(Process).filter_by(pid=current_process.pid).first()
        if baseline_process:
            # Compare attributes to detect anomalies
            for attr in ['pid', 'name', 'username', 'exe', 'create_time', 'cmdline', 'ppid', 'cwd', 'net_connections', 'status', 'memory_info', 'hashfile']:
                if getattr(baseline_process, attr) != getattr(current_process, attr):
                    print("ATTR: ", attr)
                    differences[attr] = (getattr(baseline_process, attr), getattr(current_process, attr))
                    print(f"Anomaly detected in {attr}: Baseline={getattr(baseline_process, attr)}, Current={getattr(current_process, attr)}")
            
    return differences
