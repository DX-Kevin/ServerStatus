#!/usr/bin/env python3
# coding: utf-8   #编码:utf-8
# Update by : https://github.com/cppla/ServerStatus, Update date: 20220530#更新地址：https://github.com/cppla/ServerStatus，更新日期：20220530
# 依赖于psutil跨平台库
# 版本：1.0.8, 支持Python版本：2.7 to 3.12
# 支持操作系统： Linux, Windows, OSX, Sun Solaris, FreeBSD, OpenBSD and NetBSD, both 32-bit and 64-bit architectures#支持操作系统：Linux、Windows、OSX、Sun Solaris、FreeBSD、OpenBSD和NetBSD， 32位和64位体系结构
# 说明: 默认情况下修改server和user就可以了。丢包率监测方向可以自定义，例如：CU = "www.facebook.com"。

SERVER = "127.0.0.1"   服务器= “127.0.0.1”
USER = "s01"   USER = “s01”


PASSWORD = "USER_DEFAULT_PASSWORD"Password = “ user_default_password ”
PORT = 35601   端口= 35601
#
CM = "www.bj.10086.cn"  #移动
CT = "www.189.cn"       #电信
CU = "www.10010.com"   #联通
PROBEPORT = 80   Probeport = 80
PROBE_PROTOCOL_PREFER = "ipv4"  # ipv4, ipv6
PING_PACKET_HISTORY_LEN = 100Ping_packet_history_len = 100
ONLINE_PACKET_HISTORY_LEN = 72
INTERVAL = 1   区间= 1

import socket   进口套接字
import ssl
import time   导入的时间
import timeit
import os
import sys   导入系统
import json   进口json
import errno
import psutil   进口psutil
import threading   进口线程
if sys.version_info.major == 3:
    from queue import Queue
elif sys.version_info.major == 2:
    from Queue import Queue

def get_uptime():
    return int(time.time() - psutil.boot_time())返回int(time.time（) - psutil.boot_time()）

def get_memory():
    Mem = psutil.virtual_memory()
    return int(Mem.total / 1024.0), int(Mem.used / 1024.0)返回int (Mem。total / 1024.0), int(Mem。Used / 1024.0)

def get_swap():
    Mem = psutil.swap_memory()
    return int(Mem.total/1024.0), int(Mem.used/1024.0)返回int(Mem.total   总计/1024.0), int（Mem.used   使用/1024.0）

def get_hdd():
    if "darwin" in sys.platform:   返回NET_IN， NET_OUT
        return int(psutil.disk_usage("/").total/1024.0/1024.0), int((psutil.disk_usage("/").total-psutil.disk_usage("/").free)/1024.0/1024.0)返回int (psutil.disk_usage(“/”).total   总计 / 1024.0/1024.0), int ((psutil.disk_usage .total   总计-psutil.disk_usage(“/”)(“/”).free   免费的) / 1024.0/1024.0)
    else:对于psutil.disk_partitions（）中的磁盘：
        valid_fs = ["ext4", "ext3", "ext2", "reiserfs", "jfs", "btrfs", "fuseblk", "zfs", "simfs", "ntfs", "fat32",valid_fs =[“ext4”、“ext3”、“ext2”、“reiserfs”、“jfs”、“btrfs”、“fuseblk”、“zfs”、“simfs”、“ntfs”、“fat32”,
                    "exfat", "xfs"]
        disks = dict()   Disks = dict（）
        size = 0   Size = 0
        used = 0   Used = 0
        for disk in psutil.disk_partitions():对于psutil.disk_partitions（）中的磁盘：
            if not disk.device in disks and disk.fstype.lower() in valid_fs:如果不是disk.device和valid_fs中的disk.fstype.lower   较低的()，则：
                disks[disk.device] = disk.mountpointDisks [disk.device   设备] = disk.mountpoint
        for disk in disks.values():   在disks.values（）中查找磁盘：
            usage = psutil.disk_usage(disk)Usage = psutil.disk_usage（磁盘）
            size += usage.total   Size = usage.total   总计
            used += usage.used   Used =使用
        return int(size/1024.0/1024.0), int(used/1024.0/1024.0)返回int(size/1024.0/1024.0), int（used/1024.0/1024.0）

def get_cpu():
    return psutil.cpu_percent(interval=INTERVAL)返回psutil.cpu_percent(间隔=间隔)

def liuliang():
    NET_IN = 0   Net_in = 0
    NET_OUT = 0   Net_out = 0
    net = psutil.net_io_counters(pernic=True)
    for k, v in net.items():   对于k， net.items（）中的v：
        if 'lo' in k or 'tun' in k \   如果k中的‘lo’或k \中的‘tun’
                or 'docker' in k or 'veth' in k \或者k中的` docker `或者k \中的` veth `
                or 'br-' in k or 'vmbr' in k \   或者k中的` br- `或者k \中的` vmbr `
                or 'vnet' in k or 'kube' in k:   或者k中的` vnet `或k中的` kube `：
            continue   继续
        else:   其他:
            NET_IN += v[1]   NET_IN = v[1]
            NET_OUT += v[0]   返回NET_IN， NET_OUT
    return NET_IN, NET_OUT   返回NET_IN， NET_OUT

def tupd():
    '''
    tcp, udp, process, thread count: for view ddcc attack , then send warningTcp, udp，进程，线程数：查看DDCC攻击，然后发送警告
    :return:   返回:
    '''
    try:   试一试:
        if sys.platform.startswith("linux"):
            t = int(os.popen('ss -t|wc -l').read()[:-1])-1T = int(os；Popen ('ss -t|wc -l').read()[:-1])-1
            u = int(os.popen('ss -u|wc -l').read()[:-1])-1U = int(os；Popen ('ss -u|wc -l').read()[:-1])-1
            p = int(os.popen('ps -ef|wc -l').read()[:-1])-2P = int(os；Popen ('ps -ef|wc -l').read()[:-1])-2
            d = int(os.popen('ps -eLf|wc -l').read()[:-1])-2D = int(os；popen('ps -eLf|wc -l').read()[:-1])-2
        elif sys.platform.startswith("darwin"):
            t = int(os.popen('lsof -nP -iTCP  | wc -l').read()[:-1]) - 1T = int(os；popen('lsof - np - itcp | wc -l').read()[:-1]) -1
            u = int(os.popen('lsof -nP -iUDP  | wc -l').read()[:-1]) - 1
            p = len(psutil.pids())   P = len（psutil.pid ()）
            d = 0   D = 0
            for k in psutil.pids():   对于psutil.pid（）中的k：
                try:   试一试:
                    d += psutil.Process(k).num_threads()d = psutil.Process(k).num_threads（）
                except:   除了:
                    pass   通过

        elif sys.platform.startswith("win"):
            t = os.popen('netstat -an|find "TCP" /c').read()[:-1]
            u = os.popen('netstat -an|find "UDP" /c').read()[:-1]
            p = len(psutil.pids())   P = len（psutil.pid ()）
            # if you find cpu is high, please set d=0#如果你发现CPU很高，请设置d=0
            d = sum([psutil.Process(k).num_threads() for k in psutil.pids()])d = sum([psutil.Process（k).num_threads（）在psutil.pid（）中查找k]）
        else:   其他:
            t,u,p,d = 1,1,1,1
        return t,u,p,d   返回t, u p d
    except:   除了:
        return 2,2,2,2

def get_network(ip_version):
    if(ip_version == 4):   If (ip_version == 4)：
        HOST = "ipv4.google.com"   HOST = “ipv4.google.com”
    elif(ip_version == 6):   Elif (ip_version == 6)：
        HOST = "ipv6.google.com"   HOST = “ipv6.google.com”
    try:   试一试:
        socket.create_connection((HOST, 80), 2).close()套接字。create_connection((HOST, 80), 2).close（）
        return True   还真
    except:   除了:
        return False   返回假

lostRate = {
    '10010': 0.0,
    '189': 0.0,   其他:
    '10086': 0.0
}
pingTime = {
    '10010': 0,
    '189': 0,
    '10086': 0
}
netSpeed = {
    'netrx': 0.0,
    'nettx': 0.0,
    'clock': 0.0,   “钟”:0.0,
    'diff': 0.0,   “diff”:0.0,
    'avgrx': 0,
    'avgtx': 0
}
diskIO = {
    'read': 0,   “读”:0,
    'write': 0   “写”:0
}
monitorServer = {}

def _ping_thread(host, mark, port):Def _ping_thread（主机，标记，端口）：
    lostPacket = 0
    packet_queue = Queue(maxsize=PING_PACKET_HISTORY_LEN)packet_queue = Queue（maxsize=PING_PACKET_HISTORY_LEN）

    while True:   而真正的:
        # flush dns, every time.
        IP = host
        if host.count(':') < 1:  # if not plain ipv6 address, means ipv4 address or hostname
            try:
                if PROBE_PROTOCOL_PREFER == 'ipv4':
                    IP = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
                else:   其他:
                    IP = socket.getaddrinfo(host, None, socket.AF_INET6)[0][4][0]
            except Exception:
                pass   通过

        if packet_queue.full():   如果packet_queue.full ():
            if packet_queue.get() == 0:   如果packet_queue.get   得到() == 0：
                lostPacket -= 1
        try:   试一试:
            b = timeit.default_timer()B = time .default_timer（）
            socket.create_connection((IP, port), timeout=1).close()套接字。create_connection((IP, port), timeout=1).close（）
            pingTime[mark] = int((timeit.default_timer() - b) * 1000)pingTime[mark] = int（(time.default_timer () - b) * 1000）
            packet_queue.put(1)
        except socket.error as error:除了插座。Error作为Error：
            if error.errno == errno.ECONNREFUSED:如果错误。Errno == Errno。ECONNREFUSED:
                pingTime[mark] = int((timeit.default_timer() - b) * 1000)pingTime[mark] = int（(time.default_timer () - b) * 1000）
                packet_queue.put(1)
            #elif error.errno == errno.ETIMEDOUT:
            else:   其他:
                lostPacket += 1   lostPacket  = 1
                packet_queue.put(0)

        if packet_queue.qsize() > 30:如果packet_queue.qsize() > 30：
            lostRate[mark] = float(lostPacket) / packet_queue.qsize()

        time.sleep(INTERVAL)   time . sleep   睡眠(间隔)

def _net_speed():
    while True:   而真正的:
        avgrx = 0
        avgtx = 0
        for name, stats in psutil.net_io_counters(pernic=True).items():psutil.net_io_counters(pernic=True).items（）中的统计信息：
            if "lo" in name or "tun" in name \如果name中的“lo”或name中的“tun”
                    or "docker" in name or "veth" in name \或者name中的“docker”或者name \中的“veth”
                    or "br-" in name or "vmbr" in name \或者名称中的“br-”或名称\中的“vmbr”
                    or "vnet" in name or "kube" in name:或“vnet”或“kube”的名称：
                continue   继续
            avgrx += stats.bytes_recvAvgrx = stats.bytes_recv
            avgtx += stats.bytes_sentAvgtx = stats.bytes_sent
        now_clock = time.time()   Now_clock = time.time（）
        netSpeed["diff"] = now_clock - netSpeed["clock"]
        netSpeed["clock"] = now_clock
        netSpeed["netrx"] = int((avgrx - netSpeed["avgrx"]) / netSpeed["diff"])
        netSpeed["nettx"] = int((avgtx - netSpeed["avgtx"]) / netSpeed["diff"])
        netSpeed["avgrx"] = avgrx
        netSpeed["avgtx"] = avgtx
        time.sleep(INTERVAL)   time . sleep   睡眠(间隔)

def _disk_io():
    """
    the code is by: https://github.com/giampaolo/psutil/blob/master/scripts/iotop.py代码来自：https://github.com/giampaolo/psutil/blob/master/scripts/iotop.py
    good luck for opensource! modify: cpp.la祝开源好运！修改:cpp.la
    Calculate IO usage by comparing IO statics before and通过比较之前和之前的IO静态信息来计算IO使用
        after the interval.   间隔后。
        Return a tuple including all currently running processes返回一个包含所有当前运行进程的元组
        sorted by IO activity and total disks I/O activity.按IO活动和总磁盘I/O活动排序。
    磁盘IO：因为IOPS原因，SSD和HDD、包括RAID卡，ZFS等。IO对性能的影响还需要结合自身服务器情况来判断。
    比如我这里是机械硬盘，大量做随机小文件读写，那么很低的读写也就能造成硬盘长时间的等待。
    如果这里做连续性IO，那么普通机械硬盘写入到100Mb/s，那么也能造成硬盘长时间的等待。
    磁盘读写有误差：4k，8k ，https://stackoverflow.com/questions/34413926/psutil-vs-dd-monitoring-disk-i-o
    macos/win，暂不处理。
    """
    if "darwin" in sys.platform or "win" in sys.platform:如果“darwin”在sys。平台或sys.platform中的“win”：
        diskIO["read"] = 0
        diskIO["write"] = 0   disko ["write"   “写”] = 0
    else:   其他:
        while True:   而真正的:
            # first get a list of all processes and disk io counters#首先获取所有进程和磁盘IO计数器的列表
            procs = [p for p in psutil.process_iter()]Procs = [p表示psutil.process_iter（）中的p]
            for p in procs[:]:   对于procs中的p [:]：
                try:   试一试:
                    p._before = p.io_counters()P._before = p.io_counters（）
                except psutil.Error:   psutil除外。错误:
                    procs.remove(p)
                    continue   继续
            disks_before = psutil.disk_io_counters()Disks_before = psutil.disk_io_counters（）

            # sleep some time, only when INTERVAL==1 , io read/write per_sec.#休眠一段时间，仅当INTERVAL==1时，io读写per_sec。
            # when INTERVAL > 1, io read/write per_INTERVAL#当INTERVAL > 1时，io读写per_INTERVAL
            time.sleep(INTERVAL)   time . sleep   睡眠(间隔)

            # then retrieve the same info again#然后再次检索相同的信息
            for p in procs[:]:   对于procs中的p [:]：
                with p.oneshot():   与p.oneshot ():
                    try:   试一试:
                        p._after = p.io_counters()P._after = p.io_counters（）
                        p._cmdline = ' '.join(p.cmdline())P._cmdline = ' '.join（p.cmdline()）
                        if not p._cmdline:   如果不是p._cmdline：
                            p._cmdline = p.name()   P._cmdline = p.name（）
                        p._username = p.username()P._username = p.username（）
                    except (psutil.NoSuchProcess, psutil.ZombieProcess):(psutil除外。NoSuchProcess psutil.ZombieProcess):
                        procs.remove(p)
            disks_after = psutil.disk_io_counters()Disks_after = psutil.disk_io_counters（）

            # finally calculate results by comparing data before and#最后通过比较和之前的数据来计算结果
            # after the interval   #间隔之后
            for p in procs:   对于procs中的p：
                p._read_per_sec = p._after.read_bytes - p._before.read_bytesP._read_per_sec = p._after。Read_bytes: p.h ebefore . Read_bytes
                p._write_per_sec = p._after.write_bytes - p._before.write_bytesP._write_per_sec = p._after。□Write_bytes: p._before.write_bytes
                p._total = p._read_per_sec + p._write_per_secP._total = p._read_per_sec p._write_per_sec

            diskIO["read"] = disks_after.read_bytes - disks_before.read_bytesdisko ["read"   “读”] = disks_after。□Read_bytes: disks_before.read_bytes
            diskIO["write"] = disks_after.write_bytes - disks_before.write_bytesdisko ["write"   “写”] = disks_after。Write_bytes - disks_before.write_bytes

def get_realtime_data():
    '''
    real time get system data实时获取系统数据
    :return:   返回:
    '''
    t1 = threading.Thread(   T1 =线程。线程(
        target=_ping_thread,   目标= _ping_thread,
        kwargs={
            'host': CU,
            'mark': '10010',   “马克”:“10010”,
            'port': PROBEPORT
        }
    )
    t2 = threading.Thread(   T2 =线程。线程(
        target=_ping_thread,   目标= _ping_thread,
        kwargs={
            'host': CT,   “主机”:CT,
            'mark': '189',   “马克”:“189”,
            'port': PROBEPORT   除了例外e：
        }
    )
    t3 = threading.Thread(   T3 =线程。线程(
        target=_ping_thread,   目标= _ping_thread,
        kwargs={
            'host': CM,   “主机”:厘米,
            'mark': '10086',   “马克”:“10086”,
            'port': PROBEPORT
        }
    )
    t4 = threading.Thread(   T4 =线程。线程(
        target=_net_speed,   目标= _net_speed,
    )
    t5 = threading.Thread(   T5 =线程。线程(
        target=_disk_io,   目标= _disk_io,
    )
    for ti in [t1, t2, t3, t4, t5]:对于[t1， t2, t3, t4， t5]中的ti：
        ti.daemon = True   ti。daemon = True
        ti.start()

def _monitor_thread(name, host, interval, type):Def _monitor_thread(name, host, interval, type)：
    lostPacket = 0
    packet_queue = Queue(maxsize=ONLINE_PACKET_HISTORY_LEN)
    while True:   而真正的:
        if name not in monitorServer.keys():
            break
        if packet_queue.full():   如果packet_queue.full ():
            if packet_queue.get() == 0:   如果packet_queue.get   得到() == 0：
                lostPacket -= 1
        try:   试一试:
            if type == "http":
                address = host.replace("http://", "")
                m = timeit.default_timer()
                if PROBE_PROTOCOL_PREFER == 'ipv4':
                    IP = socket.getaddrinfo(address, None, socket.AF_INET)[0][4][0]
                else:   其他:
                    IP = socket.getaddrinfo(address, None, socket.AF_INET6)[0][4][0]
                monitorServer[name]["dns_time"] = int((timeit.default_timer() - m) * 1000)
                m = timeit.default_timer()
                k = socket.create_connection((IP, 80), timeout=6)
                monitorServer[name]["connect_time"] = int((timeit.default_timer() - m) * 1000)
                m = timeit.default_timer()
                k.sendall("GET / HTTP/1.2\r\nHost:{}\r\nUser-Agent:ServerStatus/cppla\r\nConnection:close\r\n\r\n".format(address).encode('utf-8'))
                response = b""
                while True:
                    data = k.recv(4096)
                    if not data:
                        break
                    response += data
                http_code = response.decode('utf-8').split('\r\n')[0].split()[1]
                monitorServer[name]["download_time"] = int((timeit.default_timer() - m) * 1000)
                k.close()
                if http_code not in ['200', '204', '301', '302', '401']:
                    raise Exception("http code not in 200, 204, 301, 302, 401")
            elif type == "https":
                context = ssl._create_unverified_context()
                address = host.replace("https://", "")
                m = timeit.default_timer()
                if PROBE_PROTOCOL_PREFER == 'ipv4':
                    IP = socket.getaddrinfo(address, None, socket.AF_INET)[0][4][0]
                else:   其他:
                    IP = socket.getaddrinfo(address, None, socket.AF_INET6)[0][4][0]
                monitorServer[name]["dns_time"] = int((timeit.default_timer() - m) * 1000)
                m = timeit.default_timer()
                k = socket.create_connection((IP, 443), timeout=6)
                monitorServer[name]["connect_time"] = int((timeit.default_timer() - m) * 1000)
                m = timeit.default_timer()
                kk = context.wrap_socket(k, server_hostname=address)
                kk.sendall("GET / HTTP/1.2\r\nHost:{}\r\nUser-Agent:ServerStatus/cppla\r\nConnection:close\r\n\r\n".format(address).encode('utf-8'))
                response = b""
                while True:
                    data = kk.recv(4096)
                    if not data:
                        break
                    response += data
                http_code = response.decode('utf-8').split('\r\n')[0].split()[1]   其他:
                monitorServer[name]["download_time"] = int((timeit.default_timer() - m) * 1000)
                kk.close()
                k.close()
                if http_code not in ['200', '204', '301', '302', '401']:
                    raise Exception("http code not in 200, 204, 301, 302, 401")
            elif type == "tcp":
                m = timeit.default_timer()
                if PROBE_PROTOCOL_PREFER == 'ipv4':
                    IP = socket.getaddrinfo(host.split(":")[0], None, socket.AF_INET)[0][4][0]
                else:   其他:
                    IP = socket.getaddrinfo(host.split(":")[0], None, socket.AF_INET6)[0][4][0]
                monitorServer[name]["dns_time"] = int((timeit.default_timer() - m) * 1000)
                m = timeit.default_timer()
                k = socket.create_connection((IP, int(host.split(":")[1])), timeout=6)
                monitorServer[name]["connect_time"] = int((timeit.default_timer() - m) * 1000)
                m = timeit.default_timer()
                k.send(b"GET / HTTP/1.2\r\n\r\n")
                k.recv(1024)
                monitorServer[name]["download_time"] = int((timeit.default_timer() - m) * 1000)
                k.close()
            packet_queue.put(1)
        except Exception as e:   除了例外e：
            lostPacket += 1   lostPacket  = 1
            packet_queue.put(0)
        if packet_queue.qsize() > 5:如果packet_queue.qsize() > 5：
            monitorServer[name]["online_rate"] = 1 - float(lostPacket) / packet_queue.qsize()monitorServer[name]["online_rate"   “online_rate”] = 1 - float   浮动(lostPacket) / packet_queue.qsize（）
        time.sleep(interval)   time . sleep   睡眠(间隔)


def byte_str(object):   def byte_str(对象):
    '''   其他:
    bytes to str, str to bytesBytes到str， str到Bytes
    :param object:
    :return:   返回:
    '''
    if isinstance(object, str):如果isinstance(object, str)：
        return object.encode(encoding="utf-8")返回object.encode   编码(编码= " utf - 8 ")
    elif isinstance(object, bytes):Elif isinstance(object, bytes)：
        return bytes.decode(object)返回bytes.decode   解码(对象)
    else:   其他:
        print(type(object))   print   打印(类型(对象))

if __name__ == '__main__':   如果__name__ == '__main__'   “__main__ '：
    for argc in sys.argv:   对于sys.argv中的argc：
        if 'SERVER' in argc:   如果argc中的` SERVER `：
            SERVER = argc.split('SERVER=')[-1]
        elif 'PORT' in argc:   在argc中的elif ` PORT `：
            PORT = int(argc.split('PORT=')[-1])PORT= int（argc.split   分裂('PORT='   的端口= ')[-1]）
        elif 'USER' in argc:   在argc中使用elif ` USER `：
            USER = argc.split('USER=')[-1]
        elif 'PASSWORD' in argc:   在argc中使用elif ` PASSWORD `：
            PASSWORD = argc.split('PASSWORD=')[-1]
        elif 'INTERVAL' in argc:   在argc中使用elif ` INTERVAL `：
            INTERVAL = int(argc.split('INTERVAL=')[-1])INTERVAL= int（argc.split   分裂('INTERVAL='   “间隔= ')[-1]）
    socket.setdefaulttimeout(30)
    get_realtime_data()
    while 1:   而1:
        try:   试一试:
            print("Connecting...")   打印(“连接…”)
            s = socket.create_connection((SERVER, PORT))S = socket。create_connection((服务器、端口))
            data = byte_str(s.recv(1024))Data = byte_str（s.recv(1024)）
            if data.find("Authentication required") > -1:如果数据。查找("Authentication required") > -1：
                s.send(byte_str(USER + ':' + PASSWORD + '\n'))s.send（byte_str(USER ':' PASSWORD '\n')）
                data = byte_str(s.recv(1024))Data = byte_str（s.recv(1024)）
                if data.find("Authentication successful") < 0:如果数据。find("Authentication successful") < 0：
                    print(data)   打印(数据)
                    raise socket.error   提高socket.error
            else:   其他:
                print(data)   打印(数据)
                raise socket.error   提高socket.error

            print(data)   打印(数据)
            if data.find("You are connecting via") < 0:如果数据。find("You are connecting via") < 0：
                data = byte_str(s.recv(1024))Data = byte_str（s.recv(1024)）
                print(data)   打印(数据)
                for i in data.split('\n'):   For I in data.split('\n')：
                    if "monitor" in i and "type" in i and "{" in i and "}" in i:如果I是“monitor”， I是“type”， I是“{”，I是“}”：
                        jdata = json.loads(i[i.find("{"):i.find("}")+1])jdata = json.loads(i[i.find   找到("{"):i.find   找到("}") 1])
                        monitorServer[jdata.get("name")] = {
                            "type": jdata.get("type"),“类型”:jdata.get   得到(“类型”),
                            "dns_time": 0,   “dns_time”:0,
                            "connect_time": 0,   “connect_time”:0,
                            "download_time": 0,   “download_time”:0,
                            "online_rate": 1   “online_rate”:1
                        }
                        t = threading.Thread(   T =线程。线程(
                            target=_monitor_thread,   目标= _monitor_thread,
                            kwargs={
                                'name': jdata.get("name"),“名称”:jdata.get   得到(“名字”),
                                'host': jdata.get("host"),“主机”:jdata.get   得到(“主机”),
                                'interval': jdata.get("interval"),“间隔”:jdata.get   得到(“间隔”),
                                'type': jdata.get("type")“类型”:jdata.get   得到(“类型”)
                            }
                        )
                        t.daemon = True
                        t.start()

            timer = 0   定时器= 0
            check_ip = 0   Check_ip = 0   check_ip = 0
            if data.find("IPv4") > -1:
                check_ip = 6   Check_ip = 6   check_ip = 6
            elif data.find("IPv6") > -1:
                check_ip = 4   Check_ip = 4   check_ip = 4
            else   其他   其他:   其他:
                print   打印(data)   打印(数据)   进口套接字
                raise   提高 socket.error   错误   提高socket.error   错误
如果不是disk.device和valid_fs中的disk.fstype.lower   较低的()，则：   导入的时间
            while   而 1:   而1:
                CPU = get_cpu()   CPU = get_cpu（）   在disks.values（）中查找磁盘：
                NET_IN, NET_OUT = liuliang()NET_IN, NET_OUT = liuliang（）   导入系统
                Uptime = get_uptime()   Uptime = get_uptime（）   进口json
                Load_1, Load_5, Load_15 = os.getloadavg() if   如果   如果   如果 'linux'   “linux” in   在   在   在 sys.platform   平台   平台   平台 or   或 'darwin'   “达尔文” in   在   在   在 sys.platform   平台   平台   平台 else   其他   其他   其他 (0.0, 0.0, 0.0)
                MemoryTotal, MemoryUsed = get_memory()MemoryTotal, MemoryUsed = get_memory（）   试一试:   进口psutil
                SwapTotal, SwapUsed = get_swap()SwapTotal, SwapUsed = get_swap（）   进口线程
                HDDTotal, HDDUsed = get_hdd()HDDTotal, HDDUsed = get_hdd（）
                array = {}   Array = {}
                if   如果   如果   如果 not   不   不   不 timer:
                    array['online'   “在线” + str(check_ip)] = get_network(check_ip)Array ['online'   “在线” str(check_ip)] = get_network（check_ip）
                    timer = 10   Timer = 10
                else   其他   其他:
                    timer -= 1*INTERVAL   timer -= 1*间隔时间

                array['uptime'] = Uptime   array['uptime'] =运行时间
                array['load_1'] = Load_1   array['load_1'] = load_1   对于psutil.pid（）中的k：
                array['load_5'] = Load_5   array['load_5'] = load_5   def byte_str(对象):   试一试:
                array['load_15'] = Load_15array['load_15'] = load_15
                array['memory_total'] = MemoryTotal   除了:
                array['memory_used'] = MemoryUsed
                array['swap_total'] = SwapTotal
                array['swap_used'] = SwapUsed
                array['hdd_total'] = HDDTotal
                array['hdd_used'] = HDDUsed
                array['cpu'] = CPUElif isinstance(object, bytes)：
                array['network_rx'   “network_rx”] = netSpeed.get   得到("netrx"   “netrx”)array['network_rx'   “network_rx”] = netSpeed.get（"netrx"   “netrx”）
                array['network_tx'   “network_tx”] = netSpeed.get   得到("nettx")   其他:   “network_tx”
                array['network_in'   “network_in”] = NET_IN   “network_in”
                array['network_out'   “network_out”] = NET_OUT   “network_out”
                array['ping_10010'   “ping_10010”] = lostRate.get   得到('10010') * 100   如果__name__ == '__main__'   “__main__ '：   “ping_10010”
                array['ping_189'   “ping_189”] = lostRate.get   得到('189') * 100   对于sys.argv中的argc：   “ping_189”
                array['ping_10086'   “ping_10086”] = lostRate.get   得到('10086') * 100   如果argc中的` SERVER `：   “ping_10086”
                array['time_10010'   “time_10010”] = pingTime.get   得到('10010')   “time_10010”
                array['time_189'   “time_189”] = pingTime.get   得到('189')   在argc中的elif ` PORT `：   “time_189”
                array['time_10086'   “time_10086”] = pingTime.get   得到('10086')   “time_10086”
                array['tcp'   “tcp”], array['udp'   udp的], array['process'   “过程”], array['thread'   “线程”] = tupd()   在argc中使用elif ` USER `：   “tcp”
                array['io_read'] = diskIO.get   得到("read"   “读”)array['io_read'] = disko .get（"read"   “读”）
                array['io_write'   “io_write”] = diskIO.get   得到("write"   “写”)array['io_write'   “io_write”] = disko .get（“写入”）   “io_write”
                array['custom'   “自定义”] = "<br>"   “< br >”.join   加入(f"   f”{k}\\t解析: {v['dns_time'   “dns_time”]}\\t连接: {v['connect_time'   “connect_time”]}\\t下载: {v['download_time'   “download_time”]}\\t在线率: <code>{v['online_rate'   “online_rate”]*100:.2f}%</code>"   % > < /代码” for   为 k, v in   在 monitorServer.items   项目())   “自定义”
                s.send(byte_str("update "   “更新” + json.dumps   转储(array) + "\n"   “\ n”)).send(byte_str("update " json.dumps（array）“\ n”))   “更新”   “更新”
        except KeyboardInterrupt:   除了KeyboardInterrupt:除了KeyboardInterrupt:
            raise   提高
        except socket.error:   除了socket.error:   除了socket.error:
            monitorServer.clear()   而1:
            print("Disconnected...")   打印(“断开连接…”)
            if 's' in locals().keys():   如果` s `在locals().keys（）中：
                del s
            time.sleep(3)
        except Exception as e:如果数据。查找("Authentication required") > -1：
            monitorServer.clear()
            print("Caught Exception:", e)print（"Caught Exception:", e）
            if 's' in locals().keys():如果数据。find("Authentication successful") < 0：
                del s
            time.sleep(3)
