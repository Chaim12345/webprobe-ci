//! Known-answer tests for the Decoder hash menu. Sources: independent
//! implementations (Python hashlib, pycryptodome, pyskein, a pure-Python
//! Keccak sponge) computed 2026-11-22 for input "abc", plus Bouncy Castle's
//! own published digest tests (bc-java, the library Burp uses) for MD2, MD4,
//! RIPEMD-128/256/320, Tiger, Whirlpool, DSTU7564-256, GOST3411, Streebog,
//! Haraka, Keccak-288 and Kupyna-384/512.

use super::*;

/// Input "abc" -> expected lowercase hex digest.
const KAT_ABC: &[(&str, &str)] = &[
    ("BLAKE2B-160", "384264f676f39536840523f284921cdc68b6846b"),
    ("BLAKE2B-256", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
    ("BLAKE2B-384", "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"),
    ("BLAKE2B-512", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
    ("BLAKE2S-128", "aa4938119b1dc7b87cbad0ffd200d0ae"),
    ("BLAKE2S-160", "5ae3b99be29b01834c3b508521ede60438f8de17"),
    ("BLAKE2S-224", "0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55"),
    ("BLAKE2S-256", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
    ("BLAKE3-256", "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"),
    ("DSTU7564-256", "0bd1b36109f1318411a0517315aa46b8839df06622a278676f5487996c9cfc04"),
    ("KECCAK-224", "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8"),
    ("KECCAK-256", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    ("KECCAK-288", "20ff13d217d5789fa7fc9e0e9a2ee627363ec28171d0b6c52bbd2f240554dbc94289f4d6"),
    ("KECCAK-384", "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e"),
    ("KECCAK-512", "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96"),
    ("MD2", "da853b0d3f88d99b30283a69e6ded6bb"),
    ("MD4", "a448017aaf21d8525fc10ae87aa6729d"),
    ("MD5", "900150983cd24fb0d6963f7d28e17f72"),
    ("PARALLELHASH128-256", "be49aa97b745613c5fc87e7595e5c649c77c77d5435d2249a47299088c78f84c"),
    ("PARALLELHASH256-512", "fcb60dde6a68485f79f6a19b47351d71dc6c77114d0a19f263e77196e170110f6de7aceea4747172ca01f9d28c53351fd877fc6dceb6e9b0349b113fb333b105"),
    ("RIPEMD128", "c14a12199c66e4ba84636b0f69144c77"),
    ("RIPEMD160", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    ("RIPEMD256", "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65"),
    ("RIPEMD320", "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d"),
    ("SHA-1", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    ("SHA-224", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
    ("SHA-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("SHA3-224", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
    ("SHA3-256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    ("SHA3-384", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"),
    ("SHA3-512", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
    ("SHA-384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
    ("SHA-512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    ("SHA-512/224", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"),
    ("SHA-512/256", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
    ("SHAKE128-256", "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"),
    ("SHAKE256-512", "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"),
    ("SKEIN-1024-1024", "35a599a0f91abcdb4cb73c19b8cb8d947742d82c309137a7caed29e8e0a2ca7a9ff9a90c34c1908cc7e7fd99bb15032fb86e76df21b72628399b5f7c3cc209d7bb31c99cd4e19465622a049afbb87c03b5ce3888d17e6e667279ec0aa9b3e2712624c01b5f5bbe1a564220bdcf6990af0c2539019f313fdd7406cca3892a1f1f"),
    ("SKEIN-1024-384", "621f17e9e75b831b5f73b68b463113614e427629787f9949fff4de89988bf74c84c8d288f1353f50f95b02d2b93aca09"),
    ("SKEIN-1024-512", "6ba71f63553ba77ef62659c9eb3506209901fd83ed17a1c13ad3df00e3432e8c0fa6f4276593a4572d525c4ff2663dc01283edd0d2d505b9ed4a721a14dde3ff"),
    ("SKEIN-256-128", "fd90216b2b58a9ec050e88032c4f64ef"),
    ("SKEIN-256-160", "60acda5d3a6ad42741ac413f1f977e39e3a32e39"),
    ("SKEIN-256-224", "ac5c22879f46f05b9baf3ce3e43cff421eda42771a756779197535a2"),
    ("SKEIN-256-256", "258bdec343b9fde1639221a5ae0144a96e552e5288753c5fec76c05fc2fc1870"),
    ("SKEIN-512-128", "60f13d823e75630e6538315d1672291e"),
    ("SKEIN-512-160", "a603e7cd34c4338c4cb8ce6074020c78ad005b19"),
    ("SKEIN-512-224", "0c71f7dda7e1fb752544c93e821c2a0a1f991a694db5f60fd48de904"),
    ("SKEIN-512-256", "0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527"),
    ("SKEIN-512-384", "b4329745321c8f6b788a04526dad856b4a87f510ee496b743f61b048209fc3261c1ebbb8a35040a7ff58c34378c4536c"),
    ("SKEIN-512-512", "8f5dd9ec798152668e35129496b029a960c9a9b88662f7f9482f110b31f9f93893ecfb25c009baad9e46737197d5630379816a886aa05526d3a70df272d96e75"),
    ("SM3", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
    ("TIGER", "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"),
    ("TUPLEHASH128-256", "873195cadfea6bc6a71cdd903da87afb49fd232d71db817c3abcad48ad8a7898"),
    ("TUPLEHASH256-512", "ca7a87aba99f45aecff1ec6fe534e9d691ae31cb8a7aa5d48b26c563aae2099ef7265381acd2da55b679ab903b0c45e933a92d2a8fc65898f2d95ed7a415b650"),
    ("WHIRLPOOL", "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5"),
];

#[test]
fn known_answers_abc() {
    for (label, want) in KAT_ABC {
        let spec = by_label(label).unwrap_or_else(|| panic!("no menu entry {label}"));
        let got = digest_hex(spec, b"abc").unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(&got, want, "{label}");
    }
}

#[test]
fn menu_has_all_82_entries_in_measured_order() {
    let expected: [&str; 82] = [
        "BLAKE2B-160",
        "BLAKE2B-256",
        "BLAKE2B-384",
        "BLAKE2B-512",
        "BLAKE2S-128",
        "BLAKE2S-160",
        "BLAKE2S-224",
        "BLAKE2S-256",
        "BLAKE3-256",
        "DSTU7564-256",
        "DSTU7564-384",
        "DSTU7564-512",
        "GOST3411",
        "GOST3411-2012-256",
        "GOST3411-2012-512",
        "HARAKA-256",
        "HARAKA-512",
        "KECCAK-224",
        "KECCAK-256",
        "KECCAK-288",
        "KECCAK-384",
        "KECCAK-512",
        "MD2",
        "MD4",
        "MD5",
        "OID.1.0.10118.3.0.55",
        "OID.1.2.804.2.1.1.1.1.2.2.1",
        "OID.1.2.804.2.1.1.1.1.2.2.2",
        "OID.1.2.804.2.1.1.1.1.2.2.3",
        "OID.2.16.840.1.101.3.4.2.10",
        "OID.2.16.840.1.101.3.4.2.11",
        "OID.2.16.840.1.101.3.4.2.12",
        "OID.2.16.840.1.101.3.4.2.7",
        "OID.2.16.840.1.101.3.4.2.8",
        "OID.2.16.840.1.101.3.4.2.9",
        "PARALLELHASH128-256",
        "PARALLELHASH256-512",
        "RIPEMD128",
        "RIPEMD160",
        "RIPEMD256",
        "RIPEMD320",
        "SHA-1",
        "SHA-224",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA-512/224",
        "SHA-512/256",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "SHAKE128-256",
        "SHAKE256-512",
        "SKEIN-1024-1024",
        "SKEIN-1024-384",
        "SKEIN-1024-512",
        "SKEIN-256-128",
        "SKEIN-256-160",
        "SKEIN-256-224",
        "SKEIN-256-256",
        "SKEIN-512-128",
        "SKEIN-512-160",
        "SKEIN-512-224",
        "SKEIN-512-256",
        "SKEIN-512-384",
        "SKEIN-512-512",
        "SM3",
        "TIGER",
        "TUPLEHASH128-256",
        "TUPLEHASH256-512",
        "WHIRLPOOL",
        "1.0.10118.3.0.55",
        "1.2.804.2.1.1.1.1.2.2.1",
        "1.2.804.2.1.1.1.1.2.2.2",
        "1.2.804.2.1.1.1.1.2.2.3",
        "2.16.840.1.101.3.4.2.10",
        "2.16.840.1.101.3.4.2.11",
        "2.16.840.1.101.3.4.2.12",
        "2.16.840.1.101.3.4.2.7",
        "2.16.840.1.101.3.4.2.8",
        "2.16.840.1.101.3.4.2.9",
    ];
    assert_eq!(MENU.len(), 82);
    for (i, (spec, label)) in MENU.iter().zip(expected.iter()).enumerate() {
        assert_eq!(spec.label, *label, "menu position {}", i);
    }
}

#[test]
fn oid_aliases_match_named_entries() {
    for (alias, named) in [
        ("OID.1.0.10118.3.0.55", "WHIRLPOOL"),
        ("1.0.10118.3.0.55", "WHIRLPOOL"),
        ("OID.1.2.804.2.1.1.1.1.2.2.1", "DSTU7564-256"),
        ("1.2.804.2.1.1.1.1.2.2.1", "DSTU7564-256"),
        ("OID.1.2.804.2.1.1.1.1.2.2.2", "DSTU7564-384"),
        ("1.2.804.2.1.1.1.1.2.2.2", "DSTU7564-384"),
        ("OID.1.2.804.2.1.1.1.1.2.2.3", "DSTU7564-512"),
        ("1.2.804.2.1.1.1.1.2.2.3", "DSTU7564-512"),
        ("OID.2.16.840.1.101.3.4.2.7", "SHA3-224"),
        ("2.16.840.1.101.3.4.2.7", "SHA3-224"),
        ("OID.2.16.840.1.101.3.4.2.8", "SHA3-256"),
        ("2.16.840.1.101.3.4.2.8", "SHA3-256"),
        ("OID.2.16.840.1.101.3.4.2.9", "SHA3-384"),
        ("2.16.840.1.101.3.4.2.9", "SHA3-384"),
        ("OID.2.16.840.1.101.3.4.2.10", "SHA3-512"),
        ("2.16.840.1.101.3.4.2.10", "SHA3-512"),
        ("OID.2.16.840.1.101.3.4.2.11", "SHAKE128-256"),
        ("2.16.840.1.101.3.4.2.11", "SHAKE128-256"),
        ("OID.2.16.840.1.101.3.4.2.12", "SHAKE256-512"),
        ("2.16.840.1.101.3.4.2.12", "SHAKE256-512"),
    ] {
        assert_eq!(
            digest(by_label(alias).unwrap(), b"abc").unwrap(),
            digest(by_label(named).unwrap(), b"abc").unwrap(),
            "{alias} vs {named}"
        );
    }
}

#[test]
fn every_entry_hashes_empty_input() {
    // Haraka is fixed-length (BC parity): empty input must error, not panic.
    for spec in MENU {
        match spec.alg {
            Alg::Haraka256 | Alg::Haraka512 => assert!(digest(spec, b"").is_err()),
            _ => {
                let d = digest(spec, b"").unwrap_or_else(|e| panic!("{}: {e}", spec.label));
                assert!(!d.is_empty(), "{}", spec.label);
            }
        }
    }
}

/// BC GOST3411DigestTest (S-box D-A, the provider default): empty input.
#[test]
fn gost3411_bc_empty_vector() {
    let got = digest_hex(by_label("GOST3411").unwrap(), b"").unwrap();
    assert_eq!(
        got,
        "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0"
    );
}

/// BC GOST3411DigestTest message 2.
#[test]
fn gost3411_bc_message_vector() {
    let got = digest_hex(
        by_label("GOST3411").unwrap(),
        b"This is message, length=32 bytes",
    )
    .unwrap();
    assert_eq!(
        got,
        "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb"
    );
}

/// BC GOST3411_2012 tests: M1 = "0123456789" * 6 + "012" (63 bytes).
#[test]
fn streebog_bc_vectors() {
    let m1: Vec<u8> = (0..63).map(|i| b'0' + (i % 10) as u8).collect();
    assert_eq!(
        digest_hex(by_label("GOST3411-2012-256").unwrap(), &m1).unwrap(),
        "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"
    );
    assert_eq!(
        digest_hex(by_label("GOST3411-2012-512").unwrap(), &m1).unwrap(),
        "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48"
    );
}

/// DSTU 7564:2014 official vectors (sequential-byte inputs).
#[test]
fn kupyna_official_vectors() {
    let seq95: Vec<u8> = (0u8..95).collect();
    assert_eq!(
        digest_hex(by_label("DSTU7564-384").unwrap(), &seq95).unwrap(),
        concat!(
            "d9021692d84e5175735654846ba751e6d0ed0fac36dfbc0841287dcb0b5584c7",
            "5016c3decc2a6e47c50b2f3811e351b8"
        )
    );
    assert_eq!(
        digest_hex(by_label("DSTU7564-512").unwrap(), b"").unwrap(),
        concat!(
            "656b2f4cd71462388b64a37043ea55dbe445d452aecd46c3298343314ef04019",
            "bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538"
        )
    );
    assert_eq!(
        digest_hex(by_label("DSTU7564-256").unwrap(), b"").unwrap(),
        "cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6"
    );
}

/// BC KeccakDigestTest: Keccak-288 of the empty message.
#[test]
fn keccak288_bc_empty_vector() {
    assert_eq!(
        digest_hex(by_label("KECCAK-288").unwrap(), b"").unwrap(),
        "6753e3380c09e385d0339eb6b050a68f66cfd60a73476e6fd6adeb72f5edd7c6f04a5d01"
    );
}

/// Skein empty-message vectors from BC SkeinDigestTest (the other Skein
/// combinations are pinned against pyskein on "abc" in KAT_ABC).
#[test]
fn skein_bc_empty_vectors() {
    assert_eq!(
        digest_hex(by_label("SKEIN-256-256").unwrap(), b"").unwrap(),
        "c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba"
    );
    assert_eq!(
        digest_hex(by_label("SKEIN-512-512").unwrap(), b"").unwrap(),
        concat!(
            "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4",
            "1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"
        )
    );
    assert_eq!(
        digest_hex(by_label("SKEIN-1024-1024").unwrap(), b"").unwrap(),
        concat!(
            "0fff9563bb3279289227ac77d319b6fff8d7e9f09da1247b72a0a265cd6d2a62",
            "645ad547ed8193db48cff847c06494a03f55666d3b47eb4c20456c9373c86297",
            "d630d5578ebd34cb40991578f9f52b18003efa35d3da6553ff35db91b81ab890",
            "bec1b189b7f52cb2a783ebb7d823d725b0b4a71f6824e88f68f982eefc6d19c6"
        )
    );
}
