/// Generates a test UFVK from a random seed.
/// Run: cargo run --bin gen_ufvk
///
/// The spending key is printed once and must be saved securely offline.
/// The UFVK is what you deploy to the payment server.
use anyhow::Result;

fn main() -> Result<()> {
    // This is a placeholder - actual key generation requires:
    // 1. Generate 32 random bytes as seed
    // 2. Derive UnifiedSpendingKey from seed for account 0
    // 3. Derive UnifiedFullViewingKey from USK
    // 4. Encode UFVK as string
    //
    // For testnet, use Zingo CLI instead:
    //   ./zingo-cli --chain testnet
    //   > export_ufvk
    //
    // Or use zcash-cli:
    //   zcash-cli z_exportviewingkey <your_address>
    //
    // The UFVK string looks like: uviewtest1...
    // Set it as: export UFVK="uviewtest1..."

    eprintln!("=== UFVK Generator ===");
    eprintln!();
    eprintln!("For testnet, the easiest path is Zingo CLI:");
    eprintln!("  1. Run: ./zingo-cli --chain testnet");
    eprintln!("  2. Inside Zingo: exportufvk");
    eprintln!("  3. Copy the uviewtest1... string");
    eprintln!("  4. Set: export UFVK=\"uviewtest1...\"");
    eprintln!();
    eprintln!("For the existing testnet address in your .env:");
    eprintln!("  The miner address is a Unified Address, not a UFVK.");
    eprintln!("  You need to export the UFVK from the wallet that");
    eprintln!("  generated that address (Zingo CLI).");
    eprintln!();
    eprintln!("The UFVK contains the Full Viewing Key (can see payments)");
    eprintln!("but NOT the Spending Key (cannot move funds).");

    Ok(())
}
