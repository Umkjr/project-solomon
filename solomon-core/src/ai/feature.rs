// solomon-core/src/ai/feature.rs
use crate::ai::linalg::Vector;
use crate::iso8583::Iso8583Message;

/// Extracts a normalized 8-dimensional feature vector from an ISO 8583 message payload.
pub fn extract_features(payload: &[u8], timestamp: i64) -> Vector {
    let mut features = Vector::new(8);
    
    // Parse actual ISO 8583 fields
    let msg = match Iso8583Message::parse(payload) {
        Ok(m) => m,
        Err(_) => return features, // Return zeros if malformed
    };

    // x0: Normalized Amount (Field 4)
    let mut amount: f32 = 0.0;
    if let Some(f4) = msg.get_field(4) {
        if let Ok(s) = std::str::from_utf8(f4) {
            amount = s.parse().unwrap_or(0.0);
        }
    }
    features.data[0] = (amount + 1.0).log10() / 6.0; // Normalized to ~[0, 1]

    // x1: Processing Code risk (Field 3)
    // First two digits represent transaction type (e.g. 00=Purchase, 01=Withdrawal, 20=Refund)
    let mut pc_risk = 0.1; // Default
    if let Some(f3) = msg.get_field(3) {
        if f3.len() >= 2 {
            pc_risk = match &f3[0..2] {
                b"00" => 0.1, // Purchase
                b"01" => 0.5, // Withdrawal
                b"20" => 0.3, // Refund
                _ => 0.2,
            };
        }
    }
    features.data[1] = pc_risk;

    // x2: Inter-arrival time interval / Sequence delta (Field 7 Transmission Date/Time or Field 11 STAN)
    let mut delta_t = 0.05;
    if let Some(f7) = msg.get_field(7) {
        if let Ok(s) = std::str::from_utf8(f7) {
            if s.len() >= 10 {
                if let Ok(sec) = s[8..10].parse::<f32>() {
                    delta_t = (sec % 60.0) / 60.0;
                }
            }
        }
    } else if let Some(f11) = msg.get_field(11) {
        if let Ok(s) = std::str::from_utf8(f11) {
            if let Ok(stan) = s.parse::<f32>() {
                delta_t = (stan % 1000.0) / 1000.0;
            }
        }
    }
    features.data[2] = delta_t;

    // x3: Merchant Category Code (MCC) risk weight (Field 18)
    let mut mcc_risk = 0.2;
    if let Some(f18) = msg.get_field(18) {
        if let Ok(mcc) = std::str::from_utf8(f18) {
            if mcc == "6011" || mcc == "6012" { // Financial institutions/ATMs
                mcc_risk = 0.8;
            } else if mcc == "7995" { // Betting/Casino
                mcc_risk = 0.95;
            }
        }
    }
    features.data[3] = mcc_risk; 

    // x4: Cross-border / Foreign Currency indicator (Field 49)
    let mut is_foreign = 0.0;
    if let Some(f49) = msg.get_field(49) {
        if f49 != b"840" { // Assuming 840 (USD) is domestic for this instance
            is_foreign = 1.0;
        }
    }
    features.data[4] = is_foreign; 

    // x5: PAN entropy and card velocity score (Field 2 PAN or Field 11 STAN)
    let mut card_velocity_risk = 0.05;
    if let Some(f2) = msg.get_field(2) {
        let sum: u32 = f2.iter().map(|&b| b as u32).sum();
        card_velocity_risk = ((sum % 100) as f32) / 100.0;
    } else if let Some(f11) = msg.get_field(11) {
        let sum: u32 = f11.iter().map(|&b| b as u32).sum();
        card_velocity_risk = ((sum % 50) as f32) / 50.0;
    }
    features.data[5] = card_velocity_risk;

    // x6: POS Entry Mode risk (Field 22)
    let mut entry_risk = 0.0;
    if let Some(f22) = msg.get_field(22) {
        if f22.starts_with(b"01") { // Manual PAN entry
            entry_risk = 0.9;
        } else if f22.starts_with(b"90") { // Magnetic Stripe
            entry_risk = 0.7;
        } else if f22.starts_with(b"05") { // EMV Chip
            entry_risk = 0.1;
        }
    }
    features.data[6] = entry_risk;

    // x7: Cyclical time-of-day feature
    let hour = (timestamp % 86400) as f32 / 3600.0;
    features.data[7] = (std::f32::consts::PI * 2.0 * hour / 24.0).sin();

    features
}
