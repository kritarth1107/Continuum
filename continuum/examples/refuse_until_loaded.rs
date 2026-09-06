//! Example: RuntimeGuard refuses tool access until a verified HandoffPacket is loaded.
//!
//! Run with: `cargo run --example refuse_until_loaded`

use continuum::{ContinuitySeal, HandoffPacket, Kernel, KeyPair, RuntimeGuard, TrustLevel};

fn main() {
    println!("=== Continuum: Refuse-Until-Loaded Example ===\n");

    // Create a RuntimeGuard - it starts with no loaded kernel
    let mut guard = RuntimeGuard::new();

    // Attempt to access tools before loading a kernel
    println!("1. Attempting tool access before loading kernel...");
    match guard.check_access("file_write") {
        Ok(_) => println!("   file_write: ALLOWED (unexpected!)"),
        Err(e) => println!("   file_write: BLOCKED - {}", e),
    }
    match guard.check_access("shell_exec") {
        Ok(_) => println!("   shell_exec: ALLOWED (unexpected!)"),
        Err(e) => println!("   shell_exec: BLOCKED - {}", e),
    }

    // Create a kernel with specific tool trust settings
    println!("\n2. Creating and sealing a kernel...");
    let mut kernel = Kernel::new("demo-agent");
    kernel.description = Some("Demo kernel for refuse-until-loaded example".to_string());
    kernel.spend_ceiling_usd = 50.0;
    kernel
        .tool_trust
        .insert("file_write".to_string(), TrustLevel::Standard);
    kernel
        .tool_trust
        .insert("shell_exec".to_string(), TrustLevel::Restricted);
    kernel
        .tool_trust
        .insert("dangerous_op".to_string(), TrustLevel::Blocked);

    // Generate a keypair and seal the kernel
    let keypair = KeyPair::generate();
    let seal = ContinuitySeal::create(&kernel, &keypair).expect("seal creation failed");
    let packet = HandoffPacket::new(kernel, seal);

    println!("   Kernel ID: {}", packet.kernel_id);
    println!("   Created:   {}", packet.created_at);

    // Load the verified packet into the guard
    println!("\n3. Loading verified handoff packet...");
    guard.load_packet(packet).expect("packet verification failed");
    println!("   Packet loaded and verified!");

    // Now tool access works (subject to trust levels)
    println!("\n4. Attempting tool access after loading kernel...");

    match guard.check_access("file_write") {
        Ok(trust) => println!("   file_write:   ALLOWED (trust: {:?})", trust),
        Err(e) => println!("   file_write:   BLOCKED - {}", e),
    }

    match guard.check_access("shell_exec") {
        Ok(trust) => println!("   shell_exec:   ALLOWED (trust: {:?})", trust),
        Err(e) => println!("   shell_exec:   BLOCKED - {}", e),
    }

    match guard.check_access("dangerous_op") {
        Ok(trust) => println!("   dangerous_op: ALLOWED (trust: {:?})", trust),
        Err(e) => println!("   dangerous_op: BLOCKED - {}", e),
    }

    match guard.check_access("unknown_tool") {
        Ok(trust) => println!("   unknown_tool: ALLOWED (trust: {:?}, default)", trust),
        Err(e) => println!("   unknown_tool: BLOCKED - {}", e),
    }

    // Unload and show tools are blocked again
    println!("\n5. Unloading kernel...");
    guard.unload();
    match guard.check_access("file_write") {
        Ok(_) => println!("   file_write: ALLOWED (unexpected!)"),
        Err(e) => println!("   file_write: BLOCKED - {}", e),
    }

    println!("\n=== Demo complete ===");
}
