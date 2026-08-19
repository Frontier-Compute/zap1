fn get_prefixes() {
    return ["5a415031"];
}

fn hex_char(byte) {
    if byte == 48 { return "0"; }
    if byte == 49 { return "1"; }
    if byte == 50 { return "2"; }
    if byte == 51 { return "3"; }
    if byte == 52 { return "4"; }
    if byte == 53 { return "5"; }
    if byte == 54 { return "6"; }
    if byte == 55 { return "7"; }
    if byte == 56 { return "8"; }
    if byte == 57 { return "9"; }
    if byte == 65 || byte == 97 { return "a"; }
    if byte == 66 || byte == 98 { return "b"; }
    if byte == 67 || byte == 99 { return "c"; }
    if byte == 68 || byte == 100 { return "d"; }
    if byte == 69 || byte == 101 { return "e"; }
    if byte == 70 || byte == 102 { return "f"; }
    return "?";
}

fn type_label(type_hex) {
    if type_hex == "01" { return "PROGRAM_ENTRY"; }
    if type_hex == "02" { return "OWNERSHIP_ATTEST"; }
    if type_hex == "03" { return "CONTRACT_ANCHOR"; }
    if type_hex == "04" { return "DEPLOYMENT"; }
    if type_hex == "05" { return "HOSTING_PAYMENT"; }
    if type_hex == "06" { return "SHIELD_RENEWAL"; }
    if type_hex == "07" { return "TRANSFER"; }
    if type_hex == "08" { return "EXIT"; }
    if type_hex == "09" { return "MERKLE_ROOT"; }
    if type_hex == "0a" { return "STAKING_DEPOSIT"; }
    if type_hex == "0b" { return "STAKING_WITHDRAW"; }
    if type_hex == "0c" { return "STAKING_REWARD"; }
    if type_hex == "0d" { return "GOVERNANCE_PROPOSAL"; }
    if type_hex == "0e" { return "GOVERNANCE_VOTE"; }
    if type_hex == "0f" { return "GOVERNANCE_RESULT"; }
    return "UNKNOWN";
}

fn process_memo() {
    let type_hex = hex_char(memo::read_u8(5)) + hex_char(memo::read_u8(6));
    let hash = memo::read_string(8, 64);
    let label = type_label(type_hex);
    let headers = ["Field", "Value"];
    let rows = [
        [cell_string("Protocol"), cell_string("ZAP1")],
        [cell_string("Type"), cell_string(type_hex)],
        [cell_string("Label"), cell_string(label)],
        [cell_string("Hash"), cell_string(hash)],
    ];

    if type_hex != "09" {
        let url = "https://api.frontiercompute.cash/verify/" + hash;
        url += "/proof.json";
        rows.push([cell_string("Proof"), cell_url(url)]);
    }

    return [section("ZAP1 Memo", headers, rows)];
}
