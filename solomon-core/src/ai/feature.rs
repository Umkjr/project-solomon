// solomon-core/src/ai/feature.rs
use crate::ai::linalg::Vector;
use crate::iso8583::Iso8583Message;

/// Extracts a normalized 8-dimensional feature vector from either an ISO 8583 binary payload or JSON payment message.
pub fn extract_features(payload: &[u8], timestamp: i64) -> Vector {
    let mut features = Vector::new(8);

    // 1. Try parsing as binary ISO 8583 message
    if let Ok(msg) = Iso8583Message::parse(payload) {
        // x0: Normalized Amount (Field 4)
        let mut amount: f32 = 0.0;
        if let Some(f4) = msg.get_field(4) {
            if let Ok(s) = std::str::from_utf8(f4) {
                amount = s.parse().unwrap_or(0.0);
            }
        }
        features.data[0] = (amount + 1.0).log10() / 6.0;

        // x1: Processing Code risk (Field 3)
        let mut pc_risk = 0.1;
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

        // x2: Inter-arrival time interval / Sequence delta (Field 7 or Field 11)
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

        // x3: MCC risk weight (Field 18)
        let mut mcc_risk = 0.2;
        if let Some(f18) = msg.get_field(18) {
            if let Ok(mcc) = std::str::from_utf8(f18) {
                if mcc == "6011" || mcc == "6012" {
                    mcc_risk = 0.8;
                } else if mcc == "7995" {
                    mcc_risk = 0.95;
                }
            }
        }
        features.data[3] = mcc_risk;

        // x4: Cross-border / Foreign Currency indicator (Field 49)
        let mut is_foreign = 0.0;
        if let Some(f49) = msg.get_field(49) {
            if f49 != b"840" && f49 != b"356" { // 840=USD, 356=INR
                is_foreign = 1.0;
            }
        }
        features.data[4] = is_foreign;

        // x5: PAN entropy and card velocity score (Field 2 or 11)
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
            if f22.starts_with(b"01") {
                entry_risk = 0.9;
            } else if f22.starts_with(b"90") {
                entry_risk = 0.7;
            } else if f22.starts_with(b"05") {
                entry_risk = 0.1;
            }
        }
        features.data[6] = entry_risk;

        // x7: Cyclical time-of-day
        let hour = (timestamp % 86400) as f32 / 3600.0;
        features.data[7] = (std::f32::consts::PI * 2.0 * hour / 24.0).sin();

        return features;
    }

    // 2. Try parsing as JSON payment payload
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
        // x0: Amount
        let amount = v.get("amount")
            .or_else(|| v.get("f4"))
            .and_then(|a| a.as_f64().or_else(|| a.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(0.0) as f32;
        features.data[0] = (amount + 1.0).log10() / 6.0;

        // x1: Processing Code / Tx Type
        let pc = v.get("processing_code")
            .or_else(|| v.get("f3"))
            .or_else(|| v.get("tx_type"))
            .and_then(|p| p.as_str())
            .unwrap_or("00");
        features.data[1] = if pc.starts_with("01") { 0.5 } else if pc.starts_with("20") { 0.3 } else { 0.1 };

        // x2: Sequence / STAN
        let stan = v.get("stan")
            .or_else(|| v.get("f11"))
            .and_then(|s| s.as_u64().or_else(|| s.as_str().and_then(|st| st.parse().ok())))
            .unwrap_or(0);
        features.data[2] = ((stan % 1000) as f32) / 1000.0;

        // x3: MCC
        let mcc = v.get("mcc")
            .or_else(|| v.get("f18"))
            .and_then(|m| m.as_str())
            .unwrap_or("5411");
        features.data[3] = if mcc == "6011" || mcc == "6012" { 0.8 } else if mcc == "7995" { 0.95 } else { 0.2 };

        // x4: Currency
        let curr = v.get("currency")
            .or_else(|| v.get("f49"))
            .and_then(|c| c.as_str())
            .unwrap_or("INR");
        features.data[4] = if curr != "INR" && curr != "356" && curr != "USD" && curr != "840" { 1.0 } else { 0.0 };

        // x5: PAN Hash / Entropy
        if let Some(pan) = v.get("pan").or_else(|| v.get("card_number")).and_then(|p| p.as_str()) {
            let sum: u32 = pan.bytes().map(|b| b as u32).sum();
            features.data[5] = ((sum % 100) as f32) / 100.0;
        } else {
            features.data[5] = 0.1;
        }

        // x6: POS Entry Mode
        let entry_mode = v.get("pos_entry_mode")
            .or_else(|| v.get("f22"))
            .and_then(|e| e.as_str())
            .unwrap_or("05");
        features.data[6] = if entry_mode.starts_with("01") { 0.9 } else if entry_mode.starts_with("90") { 0.7 } else { 0.1 };

        // x7: Cyclical time-of-day
        let hour = (timestamp % 86400) as f32 / 3600.0;
        features.data[7] = (std::f32::consts::PI * 2.0 * hour / 24.0).sin();

        return features;
    }

    // 3. Fallback: Raw binary entropy extraction (never emit all zeros)
    let len_norm = (payload.len() as f32 / 1024.0).min(1.0);
    features.data[0] = len_norm;
    if !payload.is_empty() {
        let sum: u32 = payload.iter().map(|&b| b as u32).sum();
        features.data[1] = ((sum % 100) as f32) / 100.0;
    }
    let hour = (timestamp % 86400) as f32 / 3600.0;
    features.data[7] = (std::f32::consts::PI * 2.0 * hour / 24.0).sin();

    features
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_features_json_payload() {
        let json_payload = br#"{"amount": 4999.0, "processing_code": "000000", "stan": 12345, "mcc": "5411", "currency": "INR"}"#;
        let features = extract_features(json_payload, 1700000000);
        assert!(features.data[0] > 0.0, "Amount feature should be positive");
        assert_eq!(features.data[1], 0.1, "Purchase processing code should be 0.1");
        assert_eq!(features.data[3], 0.2, "Standard grocery MCC should be 0.2");
        assert_eq!(features.data[4], 0.0, "Domestic INR currency should be 0.0");
    }
}
