// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

#![allow(dead_code)]
//! Runtime platform capability detection for ClawTower.
//!
//! Probes the running system empirically — attempts the actual syscall or operation
//! and checks the result. No hardcoded assumptions about any platform.
//!
//! Used by all four defense layers to select the strongest available implementation
//! and gracefully degrade when features are unavailable.

use std::fs;
use std::io;
use std::path::Path;

/// CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
    Armv7,
    Riscv64,
    Other,
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::X86_64 => write!(f, "x86_64"),
            Arch::Aarch64 => write!(f, "aarch64"),
            Arch::Armv7 => write!(f, "armv7l"),
            Arch::Riscv64 => write!(f, "riscv64"),
            Arch::Other => write!(f, "unknown"),
        }
    }
}

/// All capabilities discovered at runtime. Every field is probed, not assumed.
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    // ── Kernel features ──
    pub seccomp_filter: bool,
    pub ebpf_syscall: bool,
    pub ebpf_jit: bool,
    pub bpf_lsm: bool,
    pub kprobes: bool,
    pub ftrace_syscalls: bool,
    pub userfaultfd: bool,
    pub fanotify: bool,
    pub fanotify_access_perms: bool,
    pub inotify: bool,

    // ── Memory features ──
    pub cross_memory_attach: bool,
    pub proc_mem: bool,
    pub proc_pagemap: bool,
    pub memfd_create: bool,

    // ── Hardware debug ──
    pub hw_breakpoints: bool,
    pub hw_watchpoint_count: u8,
    pub hw_breakpoint_count: u8,

    // ── Architecture ──
    pub arch: Arch,
    pub page_size: usize,
    pub cpu_cores: usize,
    pub arm_mte: bool,
    pub intel_mpk: bool,

    // ── Containment ──
    pub cgroup_v2: bool,
    pub cgroup_freeze: bool,
    pub network_namespaces: bool,
    pub pid_namespaces: bool,

    // ── Environment ──
    pub in_container: bool,
    pub kernel_version: String,
}

impl PlatformCapabilities {
    /// Probe the running system. Every field is tested empirically.
    /// Failed probes set the capability to false — no panics, no hard failures.
    pub fn probe() -> Self {
        let arch = detect_arch();
        PlatformCapabilities {
            seccomp_filter: probe_seccomp(),
            ebpf_syscall: probe_ebpf_syscall(),
            ebpf_jit: probe_ebpf_jit(),
            bpf_lsm: probe_bpf_lsm(),
            kprobes: probe_kprobes(),
            ftrace_syscalls: probe_ftrace_syscalls(),
            userfaultfd: probe_userfaultfd(),
            fanotify: probe_fanotify(),
            fanotify_access_perms: probe_fanotify_access_perms(),
            inotify: probe_inotify(),

            cross_memory_attach: probe_cross_memory_attach(),
            proc_mem: probe_proc_mem(),
            proc_pagemap: probe_proc_pagemap(),
            memfd_create: probe_memfd_create(),

            hw_breakpoints: false,  // set below
            hw_watchpoint_count: 0, // set below
            hw_breakpoint_count: 0, // set below

            arch,
            page_size: probe_page_size(),
            cpu_cores: probe_cpu_cores(),
            arm_mte: probe_arm_mte(arch),
            intel_mpk: probe_intel_mpk(arch),

            cgroup_v2: probe_cgroup_v2(),
            cgroup_freeze: probe_cgroup_freeze(),
            network_namespaces: probe_network_namespaces(),
            pid_namespaces: probe_pid_namespaces(),

            in_container: detect_container(),
            kernel_version: detect_kernel_version(),
        }
        .with_hw_breakpoints_probed()
    }

    /// Probe hardware breakpoints (requires setting struct fields after initial construction).
    fn with_hw_breakpoints_probed(mut self) -> Self {
        let (wp, bp) = probe_hw_breakpoints(self.arch);
        self.hw_watchpoint_count = wp;
        self.hw_breakpoint_count = bp;
        self.hw_breakpoints = wp > 0 || bp > 0;
        self
    }

    /// Security score: 0-100 based on available depth.
    pub fn security_score(&self) -> u8 {
        let mut score: u16 = 0;
        let mut max: u16 = 0;

        // Layer 1: LD_PRELOAD (always available) — 20 points baseline
        score += 20;
        max += 20;

        // Layer 1 enhancements
        max += 5;
        if self.userfaultfd {
            score += 5;
        }
        max += 3;
        if self.fanotify_access_perms {
            score += 3;
        }

        // Layer 2: Kernel enforcement
        max += 20;
        if self.seccomp_filter {
            score += 20;
        }
        max += 10;
        if self.ebpf_syscall {
            score += 10;
        }
        max += 8;
        if self.bpf_lsm {
            score += 8;
        }
        max += 5;
        if self.kprobes {
            score += 5;
        }
        max += 2;
        if self.ebpf_jit {
            score += 2;
        }

        // Layer 3: Memory
        max += 10;
        if self.hw_breakpoints {
            score += 10;
        }
        max += 5;
        if self.proc_mem {
            score += 5;
        }
        max += 5;
        if self.cross_memory_attach {
            score += 5;
        }
        max += 5;
        if self.arm_mte || self.intel_mpk {
            score += 5;
        }

        // Layer 4: Containment
        max += 5;
        if self.cgroup_v2 && self.cgroup_freeze {
            score += 5;
        }
        max += 2;
        if self.network_namespaces {
            score += 2;
        }

        if max == 0 {
            return 0;
        }
        ((score as f64 / max as f64) * 100.0) as u8
    }

    /// Check minimum viable security. Returns Err with reason if below threshold.
    pub fn check_minimum_viable(&self) -> Result<(), String> {
        if !self.seccomp_filter && !self.ebpf_syscall {
            return Err(
                "Neither seccomp-BPF nor eBPF available. \
                 ClawTower cannot provide kernel-level enforcement. \
                 LD_PRELOAD alone is insufficient — a static binary bypasses it entirely."
                    .into(),
            );
        }

        if !self.cross_memory_attach && !self.proc_mem {
            return Err(
                "Cannot read target process memory. \
                 Neither process_vm_readv nor /proc/[pid]/mem accessible."
                    .into(),
            );
        }

        Ok(())
    }

    /// Human-readable capability report.
    pub fn report(&self) -> String {
        let score = self.security_score();
        let mut r = String::with_capacity(2048);

        r.push_str("╔══════════════════════════════════════════════════════════╗\n");
        r.push_str("║            ClawTower Capability Report                  ║\n");
        r.push_str("╠══════════════════════════════════════════════════════════╣\n");
        r.push_str(&format!(
            "║ Platform: Linux {} {} ({} cores, {}K pages){}\n",
            self.kernel_version,
            self.arch,
            self.cpu_cores,
            self.page_size / 1024,
            if self.in_container { " [container]" } else { "" }
        ));
        r.push_str(&format!("║ Security Score: {}/100\n", score));
        r.push_str("╠══════════════════════════════════════════════════════════╣\n");

        // Layer 1
        r.push_str("║ LAYER 1: LD_PRELOAD\n");
        r.push_str("║   ✅ Ring buffer + threat scoring\n");
        r.push_str("║   ✅ Behavioral pattern matching\n");
        if self.userfaultfd {
            r.push_str("║   ✅ Page interception: userfaultfd\n");
        } else {
            r.push_str("║   ⚠️  Page interception: mprotect fallback\n");
        }
        if self.fanotify_access_perms {
            r.push_str("║   ✅ File blocking: fanotify access permissions\n");
        } else {
            r.push_str("║   ⚠️  File blocking: LD_PRELOAD only\n");
        }
        r.push_str("╠══════════════════════════════════════════════════════════╣\n");

        // Layer 2
        r.push_str("║ LAYER 2: Kernel Enforcement\n");
        if self.seccomp_filter {
            r.push_str("║   ✅ seccomp-BPF with TRACE → sentinel\n");
        } else {
            r.push_str("║   ❌ seccomp-BPF NOT available\n");
        }
        if self.ebpf_syscall {
            r.push_str(&format!(
                "║   ✅ eBPF programs{}\n",
                if self.ebpf_jit { " (JIT enabled)" } else { "" }
            ));
        } else {
            r.push_str("║   ❌ eBPF NOT available\n");
        }
        if self.bpf_lsm {
            r.push_str("║   ✅ BPF LSM hooks (optimal)\n");
        } else if self.ebpf_syscall {
            r.push_str("║   ⚠️  LSM hooks: tracepoint/kprobe fallback\n");
        }
        r.push_str("╠══════════════════════════════════════════════════════════╣\n");

        // Layer 3
        r.push_str("║ LAYER 3: Memory Sentinel\n");
        if self.hw_breakpoints {
            r.push_str(&format!(
                "║   ✅ Hardware watchpoints: {} slots\n",
                self.hw_watchpoint_count
            ));
        } else {
            r.push_str("║   ⚠️  No hardware watchpoints (polling fallback)\n");
        }
        if self.cross_memory_attach {
            r.push_str("║   ✅ Memory access via process_vm_readv/writev\n");
        } else if self.proc_mem {
            r.push_str("║   ⚠️  Memory access via /proc/[pid]/mem (slower)\n");
        } else {
            r.push_str("║   ❌ No memory access method available\n");
        }
        if self.arm_mte {
            r.push_str("║   ✅ ARM Memory Tagging Extension\n");
        } else if self.intel_mpk {
            r.push_str("║   ✅ Intel Memory Protection Keys\n");
        }
        r.push_str("╠══════════════════════════════════════════════════════════╣\n");

        // Layer 4
        r.push_str("║ LAYER 4: Process Cage\n");
        if self.cgroup_v2 && self.cgroup_freeze {
            r.push_str("║   ✅ cgroup v2 freeze\n");
        } else if self.cgroup_v2 {
            r.push_str("║   ⚠️  cgroup v2 (no freeze support)\n");
        } else {
            r.push_str("║   ⚠️  cgroup v1 or unavailable\n");
        }
        if self.network_namespaces {
            r.push_str("║   ✅ Network namespace isolation\n");
        } else {
            r.push_str("║   ⚠️  Network isolation: iptables/nftables fallback\n");
        }
        r.push_str("╚══════════════════════════════════════════════════════════╝\n");

        // Recommendations
        let mut recs = Vec::new();
        if !self.userfaultfd {
            recs.push("Enable CONFIG_USERFAULTFD in kernel");
        }
        if !self.bpf_lsm {
            recs.push("Enable CONFIG_BPF_LSM + add \"bpf\" to LSM list");
        }
        if !self.fanotify_access_perms {
            recs.push("Enable CONFIG_FANOTIFY_ACCESS_PERMISSIONS in kernel");
        }
        if !recs.is_empty() {
            r.push_str(&format!(
                "\n⚠️  {} feature(s) using fallback. For maximum security:\n",
                recs.len()
            ));
            for rec in &recs {
                r.push_str(&format!("  • {}\n", rec));
            }
        }

        r
    }
}

// ── Probe macro ─────────────────────────────────────────────────────────────

/// Probe a capability by attempting a syscall that returns a file descriptor.
///
/// On success (fd >= 0): closes the fd and returns `true`.
/// On failure: if `eperm_is_ok` is true, returns `true` when the error is EPERM
/// (meaning the kernel supports the feature but the process lacks privileges).
/// Otherwise returns `false`.
///
/// Handles both `i32` (direct libc calls) and `i64` (`libc::syscall`) return types.
macro_rules! probe_fd_syscall {
    // Variant: EPERM counts as success (capability exists but restricted)
    (eperm_ok, $syscall:expr) => {{
        let ret = unsafe { $syscall };
        if ret >= 0 {
            unsafe { libc::close(ret as i32) };
            true
        } else {
            let e = io::Error::last_os_error();
            e.raw_os_error() == Some(libc::EPERM)
        }
    }};
    // Variant: failure always means unsupported
    ($syscall:expr) => {{
        let ret = unsafe { $syscall };
        if ret >= 0 {
            unsafe { libc::close(ret as i32) };
            true
        } else {
            false
        }
    }};
}

// ── Probe implementations ──────────────────────────────────────────────────

fn detect_arch() -> Arch {
    #[cfg(target_arch = "x86_64")]
    {
        Arch::X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        Arch::Aarch64
    }
    #[cfg(target_arch = "arm")]
    {
        Arch::Armv7
    }
    #[cfg(target_arch = "riscv64")]
    {
        Arch::Riscv64
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64"
    )))]
    {
        Arch::Other
    }
}

fn probe_seccomp() -> bool {
    // prctl(PR_GET_SECCOMP) returns 0 if seccomp is available but not active,
    // or the current mode if active. Returns -1/EINVAL if not compiled in.
    let ret = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
    ret >= 0
}

fn probe_ebpf_syscall() -> bool {
    // Try BPF_PROG_LOAD with a minimal socket filter program.
    // Success or EPERM both mean the kernel supports it (EPERM = need CAP_BPF).
    // ENOSYS means not compiled in.
    #[repr(C)]
    struct BpfInsn {
        code: u8,
        regs: u8,
        off: i16,
        imm: i32,
    }

    // Minimal program: return 0
    let insns = [
        BpfInsn {
            code: 0xb7,
            regs: 0,
            off: 0,
            imm: 0,
        }, // mov r0, 0
        BpfInsn {
            code: 0x95,
            regs: 0,
            off: 0,
            imm: 0,
        }, // exit
    ];

    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct bpf_attr_prog {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
    }

    let license = b"GPL\0";
    let attr = bpf_attr_prog {
        prog_type: 1, // BPF_PROG_TYPE_SOCKET_FILTER
        insn_cnt: 2,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
        kern_version: 0,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            5i32, // BPF_PROG_LOAD
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<bpf_attr_prog>() as u32,
        )
    };

    if ret >= 0 {
        // Successfully loaded — close the fd
        unsafe { libc::close(ret as i32) };
        true
    } else {
        let e = io::Error::last_os_error();
        // EPERM means kernel supports it but we lack privileges
        e.raw_os_error() == Some(libc::EPERM)
    }
}

fn probe_ebpf_jit() -> bool {
    fs::read_to_string("/proc/sys/net/core/bpf_jit_enable")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|v| v > 0)
        .unwrap_or(false)
}

fn probe_bpf_lsm() -> bool {
    fs::read_to_string("/sys/kernel/security/lsm")
        .ok()
        .map(|s| s.contains("bpf"))
        .unwrap_or(false)
}

fn probe_kprobes() -> bool {
    // Check if kprobes are enabled
    fs::read_to_string("/sys/kernel/debug/kprobes/enabled")
        .or_else(|_| fs::read_to_string("/proc/sys/debug/kprobes/enabled"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|v| v == 1)
        // If we can't read the file (no debugfs mounted), check for the events dir
        .unwrap_or_else(|| Path::new("/sys/kernel/tracing/kprobe_events").exists()
            || Path::new("/sys/kernel/debug/tracing/kprobe_events").exists())
}

fn probe_ftrace_syscalls() -> bool {
    Path::new("/sys/kernel/tracing/events/syscalls").exists()
        || Path::new("/sys/kernel/debug/tracing/events/syscalls").exists()
}

fn probe_userfaultfd() -> bool {
    // EPERM = exists but restricted; ENOSYS = not compiled in
    probe_fd_syscall!(eperm_ok, libc::syscall(libc::SYS_userfaultfd, 0i32))
}

fn probe_fanotify() -> bool {
    // FAN_CLOEXEC = 0x00000001, FAN_CLASS_NOTIF = 0x00000000
    probe_fd_syscall!(eperm_ok, libc::fanotify_init(0x01, libc::O_RDONLY as u32))
}

fn probe_fanotify_access_perms() -> bool {
    // FAN_CLASS_CONTENT = 0x00000004, FAN_CLOEXEC = 0x00000001
    // EPERM = supported but need CAP_SYS_ADMIN
    // EINVAL = not compiled in (FAN_CLASS_CONTENT not recognized)
    probe_fd_syscall!(eperm_ok, libc::fanotify_init(0x04 | 0x01, libc::O_RDONLY as u32))
}

fn probe_inotify() -> bool {
    probe_fd_syscall!(libc::inotify_init1(libc::IN_CLOEXEC))
}

fn probe_cross_memory_attach() -> bool {
    // Try to read 1 byte from ourselves
    let buf: u8 = 42;
    let local_iov = libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    };
    let remote_iov = libc::iovec {
        iov_base: &buf as *const u8 as *mut libc::c_void,
        iov_len: 0,
    };
    let ret = unsafe {
        libc::process_vm_readv(
            libc::getpid(),
            &local_iov,
            1,
            &remote_iov,
            1,
            0,
        )
    };
    // Returns 0 for 0-length read (success) or -1/ENOSYS
    if ret >= 0 {
        true
    } else {
        let e = io::Error::last_os_error();
        // EPERM = exists but restricted (e.g., Yama ptrace_scope)
        e.raw_os_error() == Some(libc::EPERM)
    }
}

fn probe_proc_mem() -> bool {
    Path::new("/proc/self/mem").exists()
}

fn probe_proc_pagemap() -> bool {
    // Try to open — may fail with EPERM even if it exists
    match fs::File::open("/proc/self/pagemap") {
        Ok(_) => true,
        Err(e) => e.kind() == io::ErrorKind::PermissionDenied, // exists but need root
    }
}

fn probe_memfd_create() -> bool {
    let name = b"clawtower_probe\0";
    probe_fd_syscall!(libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0u32))
}

fn probe_hw_breakpoints(_arch: Arch) -> (u8, u8) {
    // Hardware breakpoint probing via perf_event_open.
    // We try to open watchpoints on a dummy address until we get ENOSPC.
    //
    // This is the most reliable cross-platform method — works on x86, ARM, RISC-V.
    // If perf_event_open returns ENOENT or EOPNOTSUPP, HW breakpoints aren't available.

    let dummy_addr: u64 = 0x1000; // doesn't matter, we're just probing slot count
    let mut watchpoints: u8 = 0;
    let mut breakpoints: u8 = 0;
    let mut wp_fds = Vec::new();
    let mut bp_fds = Vec::new();

    // Probe watchpoints (data breakpoints)
    for i in 0u8..16 {
        let addr = dummy_addr + (i as u64) * 8;
        match try_perf_breakpoint(addr, 1, false) {
            Ok(fd) => {
                wp_fds.push(fd);
                watchpoints = i + 1;
            }
            Err(_) => break,
        }
    }

    // Probe execute breakpoints
    for i in 0u8..16 {
        let addr = dummy_addr + 0x10000 + (i as u64) * 8;
        match try_perf_breakpoint(addr, 1, true) {
            Ok(fd) => {
                bp_fds.push(fd);
                breakpoints = i + 1;
            }
            Err(_) => break,
        }
    }

    // Clean up
    for fd in wp_fds.into_iter().chain(bp_fds.into_iter()) {
        unsafe { libc::close(fd) };
    }

    (watchpoints, breakpoints)
}

/// Try to create a hardware breakpoint via perf_event_open.
fn try_perf_breakpoint(addr: u64, len: u64, execute: bool) -> Result<i32, ()> {
    // perf_event_attr structure — we only fill the fields we need.
    // The struct is large (136 bytes); zero-init handles the rest.
    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct perf_event_attr {
        type_: u32,
        size: u32,
        config: u64,
        sample_period_or_freq: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        wakeup_events_or_watermark: u32,
        bp_type: u32,
        bp_addr_or_config1: u64,
        bp_len_or_config2: u64,
        // ... remaining fields are zero
        _pad: [u8; 136 - 80], // pad to full struct size
    }

    const PERF_TYPE_BREAKPOINT: u32 = 5;
    const HW_BREAKPOINT_W: u32 = 2;
    const HW_BREAKPOINT_X: u32 = 4;

    let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
    attr.type_ = PERF_TYPE_BREAKPOINT;
    attr.size = 136; // PERF_ATTR_SIZE_VER8
    attr.bp_type = if execute { HW_BREAKPOINT_X } else { HW_BREAKPOINT_W };
    attr.bp_addr_or_config1 = addr;
    attr.bp_len_or_config2 = len;
    attr.sample_period_or_freq = 1;
    attr.flags = 0x02 | 0x04; // disabled + exclude_kernel

    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const _ as *const libc::c_void,
            0i32,  // current process
            -1i32, // any CPU
            -1i32, // no group
            0u64,  // no flags
        )
    };

    if fd < 0 {
        Err(())
    } else {
        Ok(fd as i32)
    }
}

fn probe_page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

fn probe_cpu_cores() -> usize {
    unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as usize }
}

fn probe_arm_mte(arch: Arch) -> bool {
    if arch != Arch::Aarch64 {
        return false;
    }
    // Check HWCAP2 for MTE support via /proc/self/auxv or AT_HWCAP2
    // HWCAP2_MTE = (1 << 18)
    #[cfg(target_arch = "aarch64")]
    {
        let hwcap2 = unsafe { libc::getauxval(libc::AT_HWCAP2) };
        hwcap2 & (1 << 18) != 0
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

fn probe_intel_mpk(arch: Arch) -> bool {
    if arch != Arch::X86_64 {
        return false;
    }
    // Check CPUID leaf 7, ECX bit 3 (OSPKE) and bit 4 (PKU)
    #[cfg(target_arch = "x86_64")]
    {
        // Use cpuid instruction via inline asm.
        // rbx is reserved by LLVM, so we save/restore it manually.
        let ecx: u32;
        unsafe {
            std::arch::asm!(
                "push rbx",
                "mov eax, 7",
                "xor ecx, ecx",
                "cpuid",
                "pop rbx",
                out("ecx") ecx,
                out("eax") _,
                out("edx") _,
                options(nostack),
            );
        }
        ecx & (1 << 3) != 0 // OSPKE
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

fn probe_cgroup_v2() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

fn probe_cgroup_freeze() -> bool {
    // Check if "freeze" is available in the cgroup controllers,
    // or if cgroup.freeze file exists in any cgroup
    // cgroup v2 freeze is always available if cgroup v2 is present (kernel 5.2+),
    // but it's not listed in controllers. Check for the freeze file instead.
    // Check our own cgroup
    if let Ok(cgroup_path) = fs::read_to_string("/proc/self/cgroup") {
        for line in cgroup_path.lines() {
            // cgroup v2 lines start with "0::"
            if let Some(path) = line.strip_prefix("0::") {
                let freeze_path = format!("/sys/fs/cgroup{}/cgroup.freeze", path);
                if Path::new(&freeze_path).exists() {
                    return true;
                }
            }
        }
    }
    false
}

fn probe_network_namespaces() -> bool {
    Path::new("/proc/self/ns/net").exists()
}

fn probe_pid_namespaces() -> bool {
    Path::new("/proc/self/ns/pid").exists()
}

fn detect_container() -> bool {
    // Multiple signals for container detection
    Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || fs::read_to_string("/proc/1/cgroup")
            .ok()
            .map(|s| s.contains("docker") || s.contains("kubepods") || s.contains("lxc"))
            .unwrap_or(false)
        || fs::read_to_string("/proc/self/mountinfo")
            .ok()
            .map(|s| s.contains("docker") || s.contains("overlay"))
            .unwrap_or(false)
}

fn detect_kernel_version() -> String {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } == 0 {
        let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
        release.to_string_lossy().into_owned()
    } else {
        "unknown".to_string()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_runs_without_panic() {
        let caps = PlatformCapabilities::probe();
        // Basic sanity — these should always be true on any Linux system
        assert!(caps.page_size > 0);
        assert!(caps.cpu_cores > 0);
        assert!(!caps.kernel_version.is_empty());
        assert_ne!(caps.kernel_version, "unknown");
    }

    #[test]
    fn test_arch_detection() {
        let arch = detect_arch();
        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, Arch::Aarch64);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, Arch::X86_64);
    }

    #[test]
    fn test_security_score_range() {
        let caps = PlatformCapabilities::probe();
        let score = caps.security_score();
        assert!(score <= 100, "Score {} exceeds 100", score);
        // On any real Linux system we should have at least LD_PRELOAD baseline
        assert!(score >= 19, "Score {} too low — LD_PRELOAD baseline is 20", score);
    }

    #[test]
    fn test_security_score_minimum_is_ld_preload_baseline() {
        // A system with nothing available still gets 20/105 ≈ 19
        let mut caps = PlatformCapabilities::probe();
        caps.seccomp_filter = false;
        caps.ebpf_syscall = false;
        caps.ebpf_jit = false;
        caps.bpf_lsm = false;
        caps.kprobes = false;
        caps.userfaultfd = false;
        caps.fanotify_access_perms = false;
        caps.hw_breakpoints = false;
        caps.proc_mem = false;
        caps.cross_memory_attach = false;
        caps.arm_mte = false;
        caps.intel_mpk = false;
        caps.cgroup_v2 = false;
        caps.cgroup_freeze = false;
        caps.network_namespaces = false;
        let score = caps.security_score();
        assert_eq!(score, 19); // 20/105 = 19
    }

    #[test]
    fn test_security_score_full() {
        let mut caps = PlatformCapabilities::probe();
        caps.seccomp_filter = true;
        caps.ebpf_syscall = true;
        caps.ebpf_jit = true;
        caps.bpf_lsm = true;
        caps.kprobes = true;
        caps.userfaultfd = true;
        caps.fanotify_access_perms = true;
        caps.hw_breakpoints = true;
        caps.proc_mem = true;
        caps.cross_memory_attach = true;
        caps.arm_mte = true;
        caps.cgroup_v2 = true;
        caps.cgroup_freeze = true;
        caps.network_namespaces = true;
        let score = caps.security_score();
        assert_eq!(score, 100);
    }

    #[test]
    fn test_minimum_viable_passes_with_seccomp() {
        let mut caps = PlatformCapabilities::probe();
        caps.seccomp_filter = true;
        caps.proc_mem = true;
        assert!(caps.check_minimum_viable().is_ok());
    }

    #[test]
    fn test_minimum_viable_passes_with_ebpf() {
        let mut caps = PlatformCapabilities::probe();
        caps.seccomp_filter = false;
        caps.ebpf_syscall = true;
        caps.proc_mem = true;
        assert!(caps.check_minimum_viable().is_ok());
    }

    #[test]
    fn test_minimum_viable_fails_without_kernel_enforcement() {
        let mut caps = PlatformCapabilities::probe();
        caps.seccomp_filter = false;
        caps.ebpf_syscall = false;
        assert!(caps.check_minimum_viable().is_err());
    }

    #[test]
    fn test_minimum_viable_fails_without_memory_access() {
        let mut caps = PlatformCapabilities::probe();
        caps.seccomp_filter = true;
        caps.cross_memory_attach = false;
        caps.proc_mem = false;
        assert!(caps.check_minimum_viable().is_err());
    }

    #[test]
    fn test_report_not_empty() {
        let caps = PlatformCapabilities::probe();
        let report = caps.report();
        assert!(report.contains("ClawTower Capability Report"));
        assert!(report.contains("Security Score:"));
        assert!(report.contains("LAYER 1"));
        assert!(report.contains("LAYER 2"));
        assert!(report.contains("LAYER 3"));
        assert!(report.contains("LAYER 4"));
    }

    #[test]
    fn test_container_detection() {
        let in_container = detect_container();
        // Just ensure it doesn't panic — result depends on environment
        let _ = in_container;
    }

    #[test]
    fn test_inotify_available() {
        // inotify should be available on all modern Linux
        assert!(probe_inotify());
    }

    #[test]
    fn test_proc_mem_available() {
        assert!(probe_proc_mem());
    }

    #[test]
    fn test_print_report() {
        let caps = PlatformCapabilities::probe();
        eprintln!("\n{}", caps.report());
        eprintln!("Detailed probe results:");
        eprintln!("  seccomp_filter: {}", caps.seccomp_filter);
        eprintln!("  ebpf_syscall: {}", caps.ebpf_syscall);
        eprintln!("  ebpf_jit: {}", caps.ebpf_jit);
        eprintln!("  bpf_lsm: {}", caps.bpf_lsm);
        eprintln!("  kprobes: {}", caps.kprobes);
        eprintln!("  ftrace_syscalls: {}", caps.ftrace_syscalls);
        eprintln!("  userfaultfd: {}", caps.userfaultfd);
        eprintln!("  fanotify: {}", caps.fanotify);
        eprintln!("  fanotify_access_perms: {}", caps.fanotify_access_perms);
        eprintln!("  inotify: {}", caps.inotify);
        eprintln!("  cross_memory_attach: {}", caps.cross_memory_attach);
        eprintln!("  proc_mem: {}", caps.proc_mem);
        eprintln!("  proc_pagemap: {}", caps.proc_pagemap);
        eprintln!("  memfd_create: {}", caps.memfd_create);
        eprintln!("  hw_breakpoints: {} (wp={}, bp={})", caps.hw_breakpoints, caps.hw_watchpoint_count, caps.hw_breakpoint_count);
        eprintln!("  arm_mte: {}", caps.arm_mte);
        eprintln!("  intel_mpk: {}", caps.intel_mpk);
        eprintln!("  cgroup_v2: {}", caps.cgroup_v2);
        eprintln!("  cgroup_freeze: {}", caps.cgroup_freeze);
        eprintln!("  network_namespaces: {}", caps.network_namespaces);
        eprintln!("  pid_namespaces: {}", caps.pid_namespaces);
        eprintln!("  in_container: {}", caps.in_container);
        eprintln!("  kernel: {}", caps.kernel_version);
        eprintln!("  arch: {}", caps.arch);
        eprintln!("  min viable: {:?}", caps.check_minimum_viable());
    }

    #[test]
    fn test_arch_display() {
        assert_eq!(format!("{}", Arch::X86_64), "x86_64");
        assert_eq!(format!("{}", Arch::Aarch64), "aarch64");
        assert_eq!(format!("{}", Arch::Armv7), "armv7l");
        assert_eq!(format!("{}", Arch::Riscv64), "riscv64");
        assert_eq!(format!("{}", Arch::Other), "unknown");
    }
}
