//! Razorpay Payment Rail & 24-Hour Diurnal Traffic Simulation Engine
//!
//! Replicates realistic payment distributions (70% UPI, 20% Cards, 5% NetBanking,
//! 3% Refunds/Reversals, 2% Mandates) across diurnal volume curves for black-box
//! certification, boundary limit testing, and regulatory compliance validation.

use crate::iso8583::Iso8583Message;
use rand::Rng;

/// Supported payment rails mimicking Razorpay's production distribution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RazorpayPaymentRail {
    /// 70% volume: Instant micro-payments, QR, P2M / P2P
    Upi,
    /// 20% volume: RuPay, Visa, Mastercard tokenized 3DS & POS
    Cards,
    /// 5% volume: High-ticket IMPS / NEFT corporate & merchant settlements
    NetBanking,
    /// 3% volume: Merchant refunds and switch timeout reversals
    RefundsReversals,
    /// 2% volume: Scheduled recurring subscription e-mandates
    SubscriptionsMandates,
}

/// Diurnal 24-hour traffic phases representing real payment switch volume waves
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiurnalPhase {
    /// 02:00 - 06:00: Low traffic (5% peak volume, subscription renewals)
    NightLull,
    /// 08:00 - 11:00: Morning commute (65% peak volume, cabs, coffee, retail)
    MorningCommute,
    /// 12:00 - 14:00: Lunch rush (85% peak volume, high-velocity UPI food/dining)
    LunchRush,
    /// 14:00 - 18:00: Afternoon business (60% peak volume, B2B vendor payouts)
    AfternoonSteady,
    /// 19:00 - 22:00: Evening prime & flash sale peak (100% maximum capacity)
    EveningPrime,
    /// 22:00 - 02:00: Late night decline (30% peak volume, entertainment, cabs)
    LateNightDecline,
}

impl DiurnalPhase {
    /// Returns the simulated hour of the day (0..23) for temporal feature evaluation
    pub fn simulated_hour(&self) -> u32 {
        match self {
            DiurnalPhase::NightLull => 3,
            DiurnalPhase::MorningCommute => 9,
            DiurnalPhase::LunchRush => 13,
            DiurnalPhase::AfternoonSteady => 16,
            DiurnalPhase::EveningPrime => 20,
            DiurnalPhase::LateNightDecline => 23,
        }
    }

    /// Relative traffic density multiplier (0.05 to 1.00)
    pub fn relative_weight(&self) -> f64 {
        match self {
            DiurnalPhase::NightLull => 0.05,
            DiurnalPhase::MorningCommute => 0.65,
            DiurnalPhase::LunchRush => 0.85,
            DiurnalPhase::AfternoonSteady => 0.60,
            DiurnalPhase::EveningPrime => 1.00,
            DiurnalPhase::LateNightDecline => 0.30,
        }
    }
}

pub struct RazorpayTrafficGenerator;

impl RazorpayTrafficGenerator {
    /// Samples a payment rail according to Razorpay's empirical daily distribution
    pub fn sample_rail(rng: &mut impl Rng) -> RazorpayPaymentRail {
        let p: f64 = rng.gen_range(0.0..100.0);
        if p < 70.0 {
            RazorpayPaymentRail::Upi
        } else if p < 90.0 {
            RazorpayPaymentRail::Cards
        } else if p < 95.0 {
            RazorpayPaymentRail::NetBanking
        } else if p < 98.0 {
            RazorpayPaymentRail::RefundsReversals
        } else {
            RazorpayPaymentRail::SubscriptionsMandates
        }
    }

    /// Generates a valid ISO 8583 payment message conforming to the selected rail and diurnal phase
    pub fn generate_iso_transaction(
        rng: &mut impl Rng,
        rail: RazorpayPaymentRail,
        stan: u32,
        phase: DiurnalPhase,
    ) -> Iso8583Message {
        let mti = match rail {
            RazorpayPaymentRail::RefundsReversals => {
                if rng.gen_bool(0.4) {
                    *b"0420" // Reversal
                } else {
                    *b"0200" // Refund
                }
            }
            _ => *b"0200", // Standard Financial Transaction
        };

        let mut msg = Iso8583Message::new(mti);

        // Field 3: Processing Code (6 chars)
        let proc_code = match rail {
            RazorpayPaymentRail::RefundsReversals if mti == *b"0200" => b"200000".to_vec(),
            _ => b"000000".to_vec(),
        };
        msg.set_field(3, proc_code);

        // Field 4: Transaction Amount (12 chars zero-padded in paise)
        let amount_paise: u64 = match rail {
            RazorpayPaymentRail::Upi => rng.gen_range(5000..250_000), // INR 50 to INR 2,500
            RazorpayPaymentRail::Cards => rng.gen_range(49_900..1_500_000), // INR 499 to INR 15,000
            RazorpayPaymentRail::NetBanking => rng.gen_range(500_000..50_000_000), // INR 5,000 to INR 5,00,000
            RazorpayPaymentRail::RefundsReversals => rng.gen_range(10_000..300_000),
            RazorpayPaymentRail::SubscriptionsMandates => rng.gen_range(19_900..149_900), // INR 199 to INR 1,499
        };
        msg.set_field(4, format!("{:012}", amount_paise).into_bytes());

        // Field 7: Transmission Date & Time (10 chars MMDDhhmmss)
        let hour = phase.simulated_hour();
        let minute: u32 = rng.gen_range(0..60);
        let second: u32 = rng.gen_range(0..60);
        let f7 = format!("0903{:02}{:02}{:02}", hour, minute, second);
        msg.set_field(7, f7.into_bytes());

        // Field 11: Systems Trace Audit Number / STAN (6 chars zero-padded)
        let f11 = format!("{:06}", stan % 1_000_000);
        msg.set_field(11, f11.into_bytes());

        // Field 12 & 13: Local Time & Date
        msg.set_field(12, format!("{:02}{:02}{:02}", hour, minute, second).into_bytes());
        msg.set_field(13, b"0903".to_vec());

        // Rail-specific fields
        match rail {
            RazorpayPaymentRail::Cards => {
                // Field 2: Card Number / Token (16 digits)
                let pan = format!("411111{:010}", rng.gen_range(100_000_0000u64..999_999_9999u64));
                msg.set_field(2, pan.into_bytes());
                // Field 14: Card Expiration Date (YYMM)
                msg.set_field(14, b"2812".to_vec());
                // Field 18: MCC (Department Store)
                msg.set_field(18, b"5311".to_vec());
                // Field 22: POS Entry Mode (051 = EMV Chip / 3DS)
                msg.set_field(22, b"051".to_vec());
            }
            RazorpayPaymentRail::Upi => {
                // Field 18: MCC (Fast Food / Grocery)
                msg.set_field(18, b"5411".to_vec());
                // Field 22: POS Entry Mode (071 = E-commerce QR)
                msg.set_field(22, b"071".to_vec());
                // Field 63: UPI Reference & Virtual Payment Address Handle
                let vpa = format!("cust_{}@okhdfcbank", rng.gen_range(1000..9999));
                msg.set_field(63, vpa.into_bytes());
            }
            RazorpayPaymentRail::NetBanking => {
                // Field 18: MCC (Financial Institutions)
                msg.set_field(18, b"6012".to_vec());
                // Field 22: POS Entry Mode (012 = Internet Banking)
                msg.set_field(22, b"012".to_vec());
                // Field 60: Beneficiary IFSC & Account Prefix
                msg.set_field(60, b"HDFC0000001".to_vec());
            }
            RazorpayPaymentRail::RefundsReversals => {
                msg.set_field(18, b"5311".to_vec());
                msg.set_field(22, b"071".to_vec());
                // Field 37: Original Retrieval Reference Number (RRN)
                msg.set_field(37, format!("{:012}", rng.gen::<u64>() % 1_000_000_000_000).into_bytes());
            }
            RazorpayPaymentRail::SubscriptionsMandates => {
                msg.set_field(18, b"4899".to_vec()); // Streaming / Utilities
                msg.set_field(22, b"071".to_vec());
                // Field 48: E-Mandate URN identifier
                msg.set_field(48, b"MNDT_RECURRING_AUTH_OK".to_vec());
            }
        }

        // Common payment terminal & routing identifiers
        msg.set_field(41, b"RZRPOS01".to_vec()); // Terminal ID
        msg.set_field(42, b"RAZORPAYMCH0001".to_vec()); // Merchant ID
        msg.set_field(49, b"356".to_vec()); // Currency: Indian Rupee (INR)

        msg
    }

    /// Constructs an adversarial high-risk transaction designed to trigger Edge AI anomaly detection:
    /// - Foreign Currency (USD 840)
    /// - High Ticket Amount (INR 99,99,999)
    /// - High-Risk MCC: Gambling/Betting (7995)
    /// - Risky POS Entry: Manual Keyed without CVV/3DS (011)
    /// - Suspicious Time: 03:30 AM
    pub fn generate_anomalous_fraud_burst(stan: u32) -> Iso8583Message {
        let mut msg = Iso8583Message::new(*b"0200");
        msg.set_field(3, b"000000".to_vec());
        msg.set_field(4, b"000999999900".to_vec()); // ~ INR 1 Crore
        msg.set_field(7, b"0903033000".to_vec()); // 03:30:00 AM
        msg.set_field(11, format!("{:06}", stan % 1_000_000).into_bytes());
        msg.set_field(18, b"7995".to_vec()); // Casino / Online Betting
        msg.set_field(22, b"011".to_vec()); // Manual PAN Entry (Highest Fraud Risk)
        msg.set_field(41, b"SHADY001".to_vec());
        msg.set_field(42, b"CASINO_EXPLOIT".to_vec());
        msg.set_field(49, b"840".to_vec()); // US Dollar (Foreign cross-border)
        msg
    }

    /// Injects a deliberate single-bit flip mutation into a serialized wire frame
    /// to test the Verify-Before-Release (VBR) and AEAD authentication barriers
    pub fn generate_adversarial_bitflip(mut wire_bytes: Vec<u8>) -> Vec<u8> {
        if wire_bytes.len() > 10 {
            // Flip a bit in the middle of the payload
            let mid = wire_bytes.len() / 2;
            wire_bytes[mid] ^= 0x01;
        }
        wire_bytes
    }

    /// Injects a malformed buffer overflow attack frame: claims a 65,535-byte length
    /// but truncates prematurely to probe socket memory leak and buffer bloat handling
    pub fn generate_malformed_overflow_probe() -> Vec<u8> {
        let mut malformed = vec![0xFF, 0xFF]; // 65,535 bytes in Big Endian
        malformed.extend_from_slice(b"MALFORMED_PROBE_TRUNCATED");
        malformed
    }
}
