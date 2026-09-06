use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use continuum::{ContinuitySeal, DiffReceipt, HandoffPacket, Kernel, KeyPair};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "continuum")]
#[command(about = "Portable judgment kernel + continuity seal for agent identity")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 signing key pair
    Keygen {
        /// Output path for the secret key
        #[arg(short, long, default_value = "continuum.key")]
        output: PathBuf,
    },

    /// Seal a kernel configuration
    Seal {
        /// Path to kernel JSON file
        #[arg(short = 'i', long)]
        kernel: PathBuf,

        /// Path to secret key file
        #[arg(short = 'k', long)]
        key: PathBuf,

        /// Output path for the handoff packet
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify a handoff packet
    Verify {
        /// Path to handoff packet JSON file
        #[arg(short, long)]
        packet: PathBuf,

        /// Show detailed output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Compute diff between two kernel versions
    Diff {
        /// Path to old handoff packet
        #[arg(long)]
        old: PathBuf,

        /// Path to new handoff packet
        #[arg(long)]
        new: PathBuf,

        /// Path to secret key file (for signing the diff receipt)
        #[arg(short = 'k', long)]
        key: PathBuf,

        /// Output path for the diff receipt
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a diff receipt
    VerifyDiff {
        /// Path to diff receipt JSON file
        #[arg(short, long)]
        receipt: PathBuf,
    },

    /// Show kernel hash (for debugging)
    Hash {
        /// Path to kernel JSON file
        #[arg(short, long)]
        kernel: PathBuf,
    },

    /// Initialize a new kernel from a template
    Init {
        /// Template name: conservative_ops, aggressive_research, customer_support
        #[arg(short, long)]
        template: String,

        /// Output path for the kernel JSON
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Display a kernel or packet in human-readable format
    Show {
        /// Path to kernel or packet JSON file
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output } => cmd_keygen(output),
        Commands::Seal {
            kernel,
            key,
            output,
        } => cmd_seal(kernel, key, output),
        Commands::Verify { packet, verbose } => cmd_verify(packet, verbose),
        Commands::Diff {
            old,
            new,
            key,
            output,
        } => cmd_diff(old, new, key, output),
        Commands::VerifyDiff { receipt } => cmd_verify_diff(receipt),
        Commands::Hash { kernel } => cmd_hash(kernel),
        Commands::Init { template, output } => cmd_init(template, output),
        Commands::Show { path } => cmd_show(path),
    }
}

fn cmd_keygen(output: PathBuf) -> Result<()> {
    let keypair = KeyPair::generate();
    let secret_hex = hex::encode(keypair.to_bytes());
    let public_hex = keypair.public_key_hex();

    fs::write(&output, &secret_hex).context("Failed to write secret key")?;

    let public_path = output.with_extension("pub");
    fs::write(&public_path, &public_hex).context("Failed to write public key")?;

    println!("Generated key pair:");
    println!("  Secret: {}", output.display());
    println!("  Public: {}", public_path.display());
    println!("  Public key: {}", public_hex);

    Ok(())
}

fn cmd_seal(kernel_path: PathBuf, key_path: PathBuf, output: PathBuf) -> Result<()> {
    let kernel_json = fs::read_to_string(&kernel_path).context("Failed to read kernel file")?;
    let kernel = Kernel::from_json(&kernel_json).context("Failed to parse kernel")?;

    let key_hex = fs::read_to_string(&key_path).context("Failed to read key file")?;
    let key_bytes: [u8; 32] = hex::decode(key_hex.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
    let keypair = KeyPair::from_bytes(&key_bytes);

    let seal = ContinuitySeal::create(&kernel, &keypair).context("Failed to create seal")?;
    let packet = HandoffPacket::new(kernel, seal);

    let packet_json = packet.to_json().context("Failed to serialize packet")?;
    fs::write(&output, &packet_json).context("Failed to write packet")?;

    println!("Created handoff packet: {}", output.display());
    println!("  Kernel ID: {}", packet.kernel_id);
    println!("  Version: {}", packet.version);
    println!("  Hash: {}", packet.seal.kernel_hash);

    Ok(())
}

fn cmd_verify(packet_path: PathBuf, verbose: bool) -> Result<()> {
    let packet_json = fs::read_to_string(&packet_path).context("Failed to read packet file")?;
    let packet = HandoffPacket::from_json(&packet_json).context("Failed to parse packet")?;

    match packet.verify() {
        Ok(true) => {
            println!("✓ Packet verified successfully");
            if verbose {
                println!("  Kernel ID: {}", packet.kernel_id);
                println!("  Version: {}", packet.version);
                println!("  Created: {}", packet.created_at);
                println!("  Name: {}", packet.kernel.name);
                println!("  Hash: {}", packet.seal.kernel_hash);
                println!("  Public key: {}", packet.seal.public_key);
            }
            Ok(())
        }
        Ok(false) => {
            eprintln!("✗ Packet verification failed");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("✗ Packet verification failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_diff(
    old_path: PathBuf,
    new_path: PathBuf,
    key_path: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let old_json = fs::read_to_string(&old_path).context("Failed to read old packet")?;
    let old_packet = HandoffPacket::from_json(&old_json).context("Failed to parse old packet")?;

    let new_json = fs::read_to_string(&new_path).context("Failed to read new packet")?;
    let new_packet = HandoffPacket::from_json(&new_json).context("Failed to parse new packet")?;

    let key_hex = fs::read_to_string(&key_path).context("Failed to read key file")?;
    let key_bytes: [u8; 32] = hex::decode(key_hex.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
    let keypair = KeyPair::from_bytes(&key_bytes);

    let receipt = DiffReceipt::create(
        &old_packet.kernel_id,
        old_packet.version,
        &old_packet.kernel,
        &old_packet.seal,
        &new_packet.kernel,
        &new_packet.seal,
        &keypair,
    )
    .context("Failed to create diff receipt")?;

    if let Some(output_path) = output {
        let receipt_json = receipt.to_json().context("Failed to serialize receipt")?;
        fs::write(&output_path, &receipt_json).context("Failed to write receipt")?;
        println!("Created diff receipt: {}", output_path.display());
    }

    println!("{}", receipt.to_human_readable());

    Ok(())
}

fn cmd_verify_diff(receipt_path: PathBuf) -> Result<()> {
    let receipt_json = fs::read_to_string(&receipt_path).context("Failed to read receipt file")?;
    let receipt = DiffReceipt::from_json(&receipt_json).context("Failed to parse receipt")?;

    match receipt.verify() {
        Ok(true) => {
            println!("✓ Diff receipt verified successfully");
            println!("{}", receipt.to_human_readable());
            Ok(())
        }
        Ok(false) => {
            eprintln!("✗ Diff receipt verification failed");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("✗ Diff receipt verification failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_hash(kernel_path: PathBuf) -> Result<()> {
    let kernel_json = fs::read_to_string(&kernel_path).context("Failed to read kernel file")?;
    let kernel = Kernel::from_json(&kernel_json).context("Failed to parse kernel")?;

    let canonical = kernel
        .to_canonical_json()
        .context("Failed to canonicalize")?;
    let hash = continuum::seal::compute_sha256(canonical.as_bytes());

    println!("Kernel: {}", kernel.name);
    println!("Hash: {}", hex::encode(hash));

    Ok(())
}

fn cmd_init(template: String, output: PathBuf) -> Result<()> {
    let kernel = match template.as_str() {
        "conservative_ops" => golden_kernels::conservative_ops(),
        "aggressive_research" => golden_kernels::aggressive_research(),
        "customer_support" => golden_kernels::customer_support(),
        _ => {
            anyhow::bail!(
                "Unknown template: {}. Available: conservative_ops, aggressive_research, customer_support",
                template
            );
        }
    };

    let json = serde_json::to_string_pretty(&kernel)?;
    fs::write(&output, &json).context("Failed to write kernel")?;

    println!(
        "Created kernel from template '{}': {}",
        template,
        output.display()
    );

    Ok(())
}

fn cmd_show(path: PathBuf) -> Result<()> {
    let json = fs::read_to_string(&path).context("Failed to read file")?;

    if let Ok(packet) = HandoffPacket::from_json(&json) {
        println!("Handoff Packet");
        println!("==============");
        println!("Kernel ID: {}", packet.kernel_id);
        println!("Version: {}", packet.version);
        println!("Created: {}", packet.created_at);
        println!();
        show_kernel(&packet.kernel);
        println!();
        println!("Seal");
        println!("----");
        println!("Hash: {}", packet.seal.kernel_hash);
        println!("Public key: {}", packet.seal.public_key);
        return Ok(());
    }

    if let Ok(kernel) = Kernel::from_json(&json) {
        show_kernel(&kernel);
        return Ok(());
    }

    if let Ok(receipt) = DiffReceipt::from_json(&json) {
        println!("{}", receipt.to_human_readable());
        return Ok(());
    }

    anyhow::bail!("Could not parse file as kernel, packet, or diff receipt");
}

fn show_kernel(kernel: &Kernel) {
    println!("Kernel: {}", kernel.name);
    if let Some(desc) = &kernel.description {
        println!("Description: {}", desc);
    }
    println!("Schema version: {}", kernel.schema_version);
    println!();
    println!("Parameters");
    println!("----------");
    println!("Risk appetite: {:?}", kernel.risk_appetite);
    println!("Spend ceiling: ${:.2} USD", kernel.spend_ceiling_usd);
    println!(
        "Confidence threshold: {:.0}%",
        kernel.confidence_threshold * 100.0
    );
    println!("Citation bar: {:?}", kernel.citation_bar);
    println!();
    println!("Refusal classes: {:?}", kernel.refusal_classes);
    println!();
    println!("Escalation rules:");
    for rule in &kernel.escalation_rules {
        println!("  - {}: {:?} → {:?}", rule.name, rule.trigger, rule.action);
    }
    println!();
    println!("Tool trust:");
    for (tool, trust) in &kernel.tool_trust {
        println!("  - {}: {:?}", tool, trust);
    }
}

mod golden_kernels {
    use continuum::kernel::*;
    use std::collections::HashMap;

    pub fn conservative_ops() -> Kernel {
        let mut kernel = Kernel::new("conservative_ops");
        kernel.description = Some(
            "Conservative operations kernel for production environments with strict safety guardrails"
                .to_string(),
        );
        kernel.risk_appetite = RiskAppetite::Conservative;
        kernel.spend_ceiling_usd = 10.0;
        kernel.confidence_threshold = 0.9;
        kernel.citation_bar = CitationBar::AllFacts;

        kernel.refusal_classes = vec![
            RefusalClass::HarmfulContent,
            RefusalClass::SafetyOverride,
            RefusalClass::UnauthorizedFinancial,
            RefusalClass::OutOfScopeAccess,
            RefusalClass::Impersonation,
            RefusalClass::SystemDisclosure,
            RefusalClass::IrreversibleWithoutApproval,
        ];

        kernel.escalation_rules = vec![
            EscalationRule {
                name: "cost_limit".to_string(),
                trigger: EscalationTrigger::CostExceeds { usd: 5.0 },
                action: EscalationAction::RequireApproval,
            },
            EscalationRule {
                name: "low_confidence".to_string(),
                trigger: EscalationTrigger::ConfidenceBelow { threshold: 0.85 },
                action: EscalationAction::RequireApproval,
            },
            EscalationRule {
                name: "irreversible".to_string(),
                trigger: EscalationTrigger::IrreversibleAction,
                action: EscalationAction::RequireApproval,
            },
        ];

        kernel.tool_trust = HashMap::from([
            ("file_read".to_string(), TrustLevel::Standard),
            ("file_write".to_string(), TrustLevel::Restricted),
            ("file_delete".to_string(), TrustLevel::RequiresApproval),
            ("shell_exec".to_string(), TrustLevel::RequiresApproval),
            ("http_request".to_string(), TrustLevel::Restricted),
            ("database_write".to_string(), TrustLevel::RequiresApproval),
        ]);

        kernel
    }

    pub fn aggressive_research() -> Kernel {
        let mut kernel = Kernel::new("aggressive_research");
        kernel.description = Some(
            "Aggressive research kernel for exploratory work with higher autonomy".to_string(),
        );
        kernel.risk_appetite = RiskAppetite::Aggressive;
        kernel.spend_ceiling_usd = 500.0;
        kernel.confidence_threshold = 0.6;
        kernel.citation_bar = CitationBar::Disputed;

        kernel.refusal_classes = vec![
            RefusalClass::HarmfulContent,
            RefusalClass::SafetyOverride,
            RefusalClass::Impersonation,
        ];

        kernel.escalation_rules = vec![
            EscalationRule {
                name: "high_cost".to_string(),
                trigger: EscalationTrigger::CostExceeds { usd: 100.0 },
                action: EscalationAction::NotifyAndContinue,
            },
            EscalationRule {
                name: "very_low_confidence".to_string(),
                trigger: EscalationTrigger::ConfidenceBelow { threshold: 0.4 },
                action: EscalationAction::ReduceScope { max_iterations: 3 },
            },
        ];

        kernel.tool_trust = HashMap::from([
            ("file_read".to_string(), TrustLevel::Trusted),
            ("file_write".to_string(), TrustLevel::Trusted),
            ("file_delete".to_string(), TrustLevel::Standard),
            ("shell_exec".to_string(), TrustLevel::Standard),
            ("http_request".to_string(), TrustLevel::Trusted),
            ("database_write".to_string(), TrustLevel::Restricted),
        ]);

        kernel
    }

    pub fn customer_support() -> Kernel {
        let mut kernel = Kernel::new("customer_support");
        kernel.description =
            Some("Customer support kernel optimized for helpful, safe interactions".to_string());
        kernel.risk_appetite = RiskAppetite::Moderate;
        kernel.spend_ceiling_usd = 0.0;
        kernel.confidence_threshold = 0.75;
        kernel.citation_bar = CitationBar::Disputed;

        kernel.refusal_classes = vec![
            RefusalClass::HarmfulContent,
            RefusalClass::SafetyOverride,
            RefusalClass::UnauthorizedFinancial,
            RefusalClass::Impersonation,
            RefusalClass::SystemDisclosure,
            RefusalClass::Custom("competitor_discussion".to_string()),
        ];

        kernel.escalation_rules = vec![
            EscalationRule {
                name: "refund_request".to_string(),
                trigger: EscalationTrigger::DomainMatch {
                    domains: vec!["refund".to_string(), "billing".to_string()],
                },
                action: EscalationAction::RequireApproval,
            },
            EscalationRule {
                name: "account_changes".to_string(),
                trigger: EscalationTrigger::DomainMatch {
                    domains: vec!["account_delete".to_string(), "password_reset".to_string()],
                },
                action: EscalationAction::RequireApproval,
            },
            EscalationRule {
                name: "low_confidence".to_string(),
                trigger: EscalationTrigger::ConfidenceBelow { threshold: 0.6 },
                action: EscalationAction::NotifyAndContinue,
            },
        ];

        kernel.tool_trust = HashMap::from([
            ("knowledge_base".to_string(), TrustLevel::Trusted),
            ("ticket_create".to_string(), TrustLevel::Standard),
            ("ticket_update".to_string(), TrustLevel::Standard),
            ("customer_lookup".to_string(), TrustLevel::Restricted),
            ("refund_process".to_string(), TrustLevel::RequiresApproval),
            ("account_modify".to_string(), TrustLevel::Blocked),
        ]);

        kernel
    }
}
