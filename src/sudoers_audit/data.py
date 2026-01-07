# Comprehensive list of binaries known to facilitate privilege escalation via sudo.
# Source: https://gtfobins.github.io/#+sudo (Snapshot)

RISKY_BINARIES = {
    # Shells & Interpreters
    "ash", "bash", "csh", "dash", "elvish", "fish", "ksh", "lua", "make", "php", 
    "perl", "python", "python2", "python3", "ruby", "rview", "rvim", "sash", 
    "sh", "tclsh", "zsh", "wish", "expect", "jjs", "jrunscript", "gtester", 
    "julia", "node", "npm", "ol", "scrot", "slsh", "soelim", "yash",

    # Editors & Pagers (Can spawn shells)
    "vi", "vim", "vimdiff", "view", "nano", "pico", "ed", "emacs", "joe", 
    "less", "more", "man", "pg", "pic", "red", "ul", "pager", "most",

    # Network Tools
    "aria2c", "arp", "curl", "wget", "fetch", "ftp", "lftp", "nc", "netcat", 
    "nmap", "openssl", "socat", "ssh", "telnet", "tftp", "whois", "ip", 
    "if top", "tcpdump", "tshark",

    # File System & Archives (Read/Write/Exec)
    "cp", "mv", "chmod", "chown", "chroot", "tar", "zip", "unzip", "gzip", 
    "bzip2", "7z", "ar", "cpio", "dd", "find", "grep", "awk", "gawk", "mawk", 
    "nawk", "sed", "jq", "cat", "base64", "base32", "diff", "fmt", "head", 
    "tail", "hexdump", "od", "nl", "paste", "sort", "tee", "uniq", "xxd", 
    "xz", "zsoelim",

    # System Utilities
    "apt", "apt-get", "yum", "dnf", "dpkg", "rpm", "pkexec", "service", 
    "systemctl", "journalctl", "dmesg", "snap", "task", "nice", "ionice", 
    "strace", "ltrace", "gdb", "perf", "time", "timeout", "watch", "env", 
    "busctl", "capsh", "choom", "column", "comm", "crash", "crontab", 
    "dmsetup", "flock", "genisoimage", "git", "iconv", "install", "ksshell", 
    "ld.so", "ldconfig", "logsave", "look", "mount", "msgfilt", "msgmerge", 
    "msguniq", "multitime", "namei", "nfsstat", "nsenter", "pandoc", 
    "pidstat", "pr", "ptx", "puppet", "readelf", "restic", "rlwrap", 
    "rsync", "run-parts", "scanmem", "setarch", "shuf", "softlimit", 
    "split", "sqlite3", "ss", "ssh-agent", "ssh-keygen", "ssh-keyscan", 
    "start-stop-daemon", "stdbuf", "sysctl", "systemd-resolve", "tac", 
    "taskset", "uudecode", "uuencode", "valgrind", "vigr", "vipw", 
    "virsh", "volatility", "wall", "xargs", "xdotool", "xmodmap", 
    "xmore", "xpad", "zipp", "zypper", "docker", "kubectl"
}
