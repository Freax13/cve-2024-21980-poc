use std::{
    fs::OpenOptions,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::prelude::OpenOptionsExt,
    },
};

use anyhow::{ensure, Context, Result};
use bitflags::bitflags;
use nix::{ioctl_readwrite, ioctl_write_int_bad, libc::O_SYNC, request_code_none};
use tracing::debug;

use crate::snp_types::guest_policy::GuestPolicy;

const KVMIO: u8 = 0xAE;

pub struct KvmHandle {
    fd: OwnedFd,
}

impl KvmHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_SYNC)
            .open("/dev/kvm")
            .context("failed to open /dev/kvm")?;
        let fd = OwnedFd::from(file);

        ioctl_write_int_bad!(kvm_get_api_version, request_code_none!(KVMIO, 0x00));
        let res = unsafe { kvm_get_api_version(fd.as_raw_fd(), 0) };
        let version = res.context("failed to execute get_api_version")?;
        debug!(version, "determined kvm version");
        ensure!(version >= 12, "unsupported kvm api version ({version})");

        Ok(Self { fd })
    }

    pub fn create_snp_vm(&self) -> Result<VmHandle> {
        debug!("creating vm");

        ioctl_write_int_bad!(kvm_create_vm, request_code_none!(KVMIO, 0x01));
        let res = unsafe { kvm_create_vm(self.fd.as_raw_fd(), 3) };
        let raw_fd = res.context("failed to create vm")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok(VmHandle { fd })
    }
}

pub struct VmHandle {
    fd: OwnedFd,
}

impl VmHandle {
    unsafe fn memory_encrypt_op<'a>(
        &self,
        payload: KvmSevCmdPayload<'a>,
        sev_handle: Option<&SevHandle>,
    ) -> Result<KvmSevCmdPayload<'a>> {
        debug!("executing memory encryption operation");

        let mut cmd = KvmSevCmd {
            payload,
            error: 0,
            sev_fd: sev_handle.map(|sev_handle| sev_handle.fd.as_fd()),
        };

        ioctl_readwrite!(kvm_memory_encrypt_op, KVMIO, 0xba, u64);
        let res =
            kvm_memory_encrypt_op(self.fd.as_raw_fd(), &mut cmd as *mut KvmSevCmd as *mut u64);
        ensure!(cmd.error == 0);
        res.context("failed to execute memory encryption operation")?;

        Ok(cmd.payload)
    }

    pub fn sev_snp_init(&self) -> Result<()> {
        let mut data = KvmSnpInit {
            flags: KvmSnpInitFlags::empty(),
        };
        let payload = KvmSevCmdPayload::KvmSevSnpInit { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to initialize sev snp")?;
        Ok(())
    }

    pub fn sev_snp_launch_start(&self, policy: GuestPolicy, sev_handle: &SevHandle) -> Result<()> {
        debug!("starting snp launch");
        let mut data = KvmSevSnpLaunchStart {
            policy,
            ma_uaddr: 0,
            ma_en: 0,
            imi_en: 0,
            gosvw: [0; 16],
            _pad: [0; 6],
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchStart { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to start sev snp launch")?;
        Ok(())
    }

    pub fn sev_snp_dbg_decrypt(&self, gfn: u64) -> Result<[u8; 4096]> {
        debug!("debug decrypting");

        let mut page = [0xcc; 4096];

        let mut data = KvmSevSnpDbg {
            src_gfn: gfn,
            dst_uaddr: &mut page as *const [u8; 4096] as u64,
        };
        let payload = KvmSevCmdPayload::KvmSevSnpDbgDecrypt { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to debug decrypt")?;
        Ok(page)
    }
}

pub struct SevHandle {
    fd: OwnedFd,
}

impl SevHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_SYNC)
            .open("/dev/sev")
            .context("failed to open /dev/sev")?;
        let fd = OwnedFd::from(file);
        Ok(Self { fd })
    }
}

#[repr(C)]
struct KvmSevCmd<'a, 'b> {
    pub payload: KvmSevCmdPayload<'a>,
    pub error: u32,
    pub sev_fd: Option<BorrowedFd<'b>>,
}

#[allow(clippy::enum_variant_names)]
#[repr(C, u32)]
// FIXME: Figure out which ones need `&mut T` and which ones need `&T`
pub enum KvmSevCmdPayload<'a> {
    KvmSevSnpInit { data: &'a mut KvmSnpInit } = 22,
    KvmSevSnpLaunchStart { data: &'a mut KvmSevSnpLaunchStart } = 23,
    KvmSevSnpDbgDecrypt { data: &'a mut KvmSevSnpDbg } = 28,
}

#[repr(C)]
pub struct KvmSnpInit {
    pub flags: KvmSnpInitFlags,
}

bitflags! {
    #[repr(transparent)]
    pub struct KvmSnpInitFlags: u64 {}
}

#[repr(C)]
pub struct KvmSevSnpLaunchStart {
    /// Guest policy to use.
    pub policy: GuestPolicy,
    /// userspace address of migration agent
    pub ma_uaddr: u64,
    /// 1 if the migtation agent is enabled
    pub ma_en: u8,
    /// set IMI to 1.
    pub imi_en: u8,
    /// guest OS visible workarounds
    pub gosvw: [u8; 16],
    pub _pad: [u8; 6],
}

#[repr(C)]
pub struct KvmSevSnpDbg {
    src_gfn: u64,
    dst_uaddr: u64,
}

bitflags! {
    #[repr(transparent)]
    pub struct KvmGuestMemFdFlags: u64 {
        const HUGE_PMD = 1 << 0;
    }
}
