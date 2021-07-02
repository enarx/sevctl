// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::arch::x86_64;
use std::mem::transmute;
use std::str::from_utf8;

#[derive(StructOpt)]
pub enum SevGeneration {
    #[structopt(about = "Secure Encrypted Virtualization")]
    Sev,

    #[structopt(about = "SEV + Encrypted State")]
    Es,
}

struct CpuId {
    pub name: &'static str,
    pub leaf: u32,
    pub func: fn(x86_64::CpuidResult) -> (bool, Option<String>),
    pub level: u32,
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

    if passed {
        Ok(())
    } else {
        Err(error::Context::new(
            "One or more tests in sevctl-ok reported a failure",
            Box::<Error>::new(ErrorKind::InvalidData.into()),
        ))
    }
}
