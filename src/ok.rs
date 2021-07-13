// SPDX-License-Identifier: Apache-2.0

use super::*;
use colorful::*;
use std::arch::x86_64;
use std::fs;
use std::mem::transmute;
use std::str::from_utf8;

#[derive(StructOpt)]
pub enum SevGeneration {
    #[structopt(about = "Secure Encrypted Virtualization")]
    Sev,

    #[structopt(about = "SEV + Encrypted State")]
    Es,
}

const SYS_TEST_LEVEL: u32 = 5;

type SystemTest = (Box<dyn Fn() -> (bool, String)>, String);

struct CpuId {
    pub name: &'static str,
    pub leaf: u32,
    pub func: fn(x86_64::CpuidResult) -> (bool, Option<String>),
    pub level: u32,
}

impl CpuId {
    pub fn execute(&self) -> (bool, String) {
        let (success, msg) = (self.func)(unsafe { x86_64::__cpuid(self.leaf) });

        let msg = match msg {
            Some(m) => format!("{}: {}", self.name, m),
            None => self.name.to_string(),
        };

        (success, msg)
    }
}

const CORE_CPUID: &[CpuId] = &[CpuId {
    name: "AMD CPU",
    leaf: 0x00000000,
    func: |res| {
        let name: [u8; 12] = unsafe { transmute([res.ebx, res.edx, res.ecx]) };
        let name = from_utf8(&name[..]).unwrap();

        (name == "AuthenticAMD", None)
    },
    level: 1,
}];

const AMD_CPU_DEPENDENT_CPUIDS: &[CpuId] = &[CpuId {
    name: "Microcode support",
    leaf: 0x80000002,
    func: |_| {
        let cpu_name = {
            let mut bytestr = Vec::with_capacity(48);
            for cpuid in 0x8000_0002_u32..=0x8000_0004_u32 {
                let cpuid = unsafe { x86_64::__cpuid(cpuid) };
                let mut bytes: Vec<u8> = [cpuid.eax, cpuid.ebx, cpuid.ecx, cpuid.edx]
                    .iter()
                    .flat_map(|r| r.to_le_bytes().to_vec())
                    .collect();
                bytestr.append(&mut bytes);
            }
            String::from_utf8(bytestr)
                .unwrap_or_else(|_| "ERROR_FOUND".to_string())
                .trim()
                .to_string()
        };

        (cpu_name.to_uppercase().contains("EPYC"), None)
    },
    level: 2,
}];
const MICROCODE_DEPENDENT_CPUIDS: &[CpuId] = &[
    CpuId {
        name: "AMD SEV",
        leaf: 0x8000001f,
        func: |res| (res.eax & (0x1 << 1) != 0, None),
        level: 3,
    },
    CpuId {
        name: "AMD SME",
        leaf: 0x8000001f,
        func: |res| (res.eax & 0x1 != 0, None),
        level: 3,
    },
];
const SEV_SME_DEPENDENT_CPUIDS: &[CpuId] = &[
    CpuId {
        name: "Page flush MSR",
        leaf: 0x8000001f,
        func: |res| (res.eax & (0x1 << 2) != 0, None),
        level: 4,
    },
    CpuId {
        name: "Physical address bit reduction",
        leaf: 0x8000001f,
        func: |res| {
            let field = res.ebx & 0b1111_1100_0000 >> 6;
            (true, Some(format!("{}", field)))
        },
        level: 4,
    },
    CpuId {
        name: "C-bit location in page table entry",
        leaf: 0x8000001f,
        func: |res| {
            let field = res.ebx & 0b01_1111;
            (true, Some(format!("{}", field)))
        },
        level: 4,
    },
    CpuId {
        name: "Number of encrypted guests supported simultaneously",
        leaf: 0x8000001f,
        func: |res| (true, Some(format!("{}", res.ecx))),
        level: 4,
    },
    CpuId {
        name: "Minimum ASID value for SEV-enabled, SEV-ES disabled guest",
        leaf: 0x8000001f,
        func: |res| (true, Some(format!("{}", res.edx))),
        level: 4,
    },
];

// SEV-ES specific CPUIDs.
const SEV_ES_CPUIDS: &[CpuId] = &[CpuId {
    name: "AMD SEV-ES",
    leaf: 0x8000001f,
    func: |res| (res.eax & (0x1 << 3) != 0, None),
    level: 4,
}];

pub fn cmd(gen: Option<SevGeneration>, quiet: bool) -> Result<()> {
    let mut passed = true;

    // Collect all tests.
    let cpuid_vec = match gen {
        Some(g) => collect_cpuids(g),
        None => collect_cpuids(SevGeneration::Es),
    };
    let sys_tests: Vec<SystemTest> = vec![
        (Box::new(dev_sev_r), "/dev/sev readable".to_string()),
        (Box::new(dev_sev_w), "/dev/sev writable".to_string()),
    ];

    // Iterate through and test CPUIDs.
    for list in cpuid_vec {
        if passed {
            for cpuid in list {
                let (success, msg) = cpuid.execute();
                if !success {
                    passed = false;
                }
                if !quiet {
                    emit_result(success, &msg, cpuid.level);
                }
            }
        } else {
            for cpuid in list {
                if !quiet {
                    emit_skip(cpuid.name, cpuid.level);
                }
            }
        }
    }

    // Complete the rest of the system tests
    if passed {
        for (func, _func_name) in sys_tests {
            let (success, msg) = func();
            if !quiet {
                emit_result(success, &msg, SYS_TEST_LEVEL);
            }
            if !success {
                passed = false;
            }
        }
    } else {
        for (_func, func_name) in sys_tests {
            if !quiet {
                emit_skip(&func_name, SYS_TEST_LEVEL);
            }
        }
    }

    if passed {
        Ok(())
    } else {
        Err(error::Context::new(
            "One or more tests in sevctl-ok reported a failure",
            Box::<Error>::new(ErrorKind::InvalidData.into()),
        ))
    }
}

fn emit_result(success: bool, msg: &str, level: u32) {
    let res_v = if success {
        format!("[ {} ]", "OK".green())
    } else {
        format!("[ {} ]", "FAIL".red())
    };

    let align_level = get_align_level(level);

    println!("{}", format!("{}{}{}", res_v, align_level, msg))
}

fn emit_skip(msg: &str, level: u32) {
    let res_v = format!("[ {} ]", "SKIP".yellow());

    let align_level = get_align_level(level);

    println!("{}", format!("{}{}{}", res_v, align_level, msg))
}

fn get_align_level(level: u32) -> &'static str {
    match level {
        1 => " ",
        2 => " - ",
        3 => "   - ",
        4 => "     - ",
        _ => "       - ",
    }
}

fn collect_cpuids(gen: SevGeneration) -> Vec<&'static [CpuId]> {
    let mut c_vec = vec![
        CORE_CPUID,
        AMD_CPU_DEPENDENT_CPUIDS,
        MICROCODE_DEPENDENT_CPUIDS,
        SEV_SME_DEPENDENT_CPUIDS,
    ];
    if let SevGeneration::Es = gen {
        c_vec.push(SEV_ES_CPUIDS);
    }

    c_vec
}

fn dev_sev_r() -> (bool, String) {
    let (success, msg) = dev_sev_rw(fs::OpenOptions::new().read(true));

    if success {
        (success, "/dev/sev readable".to_string())
    } else {
        (success, format!("/dev/sev not readable: {}", msg))
    }
}

fn dev_sev_w() -> (bool, String) {
    let (success, msg) = dev_sev_rw(fs::OpenOptions::new().write(true));

    if success {
        (success, "/dev/sev writable".to_string())
    } else {
        (success, format!("/dev/sev not writable: {}", msg))
    }
}

fn dev_sev_rw(file: &mut fs::OpenOptions) -> (bool, String) {
    let path = "/dev/sev";
    let mut success = true;

    let msg = match file.open(path) {
        Ok(_) => "Readable".to_string(),
        Err(e) => {
            success = false;
            format!("Error ({})", e)
        }
    };

    (success, msg)
}
