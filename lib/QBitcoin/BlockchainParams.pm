package QBitcoin::BlockchainParams;
use warnings;
use strict;
use feature 'state';

use QBitcoin::Const;

# Spending any of these BTC UTXOs stops the btc->qbt conversion: coinbase upgrades are
# not allowed starting from the spending btc transaction (in btc order, including its
# own outputs); burns in earlier transactions of the same block are still converted.
# Keys are "txid:vout" with txid in display (RPC) byte order; compiled to binary prevout keys.
sub _stop_utxo_set {
    return { map {
        my ($txid, $vout) = split /:/;
        scalar(reverse pack("H*", $txid)) . pack("V", $vout) => $_
    } @_ };
}

use constant MAINNET => {
    GENESIS_HASH       => pack("H*", ""),
    # BTC pubkeys of the three federation operators behind the deposit/pool address
    # (2-of-3, see QBT_LOCK_WITNESS_SCRIPT / QBT_LOCK_SCRIPT below); any order here,
    # the witnessScript sorts them (BIP67). Address: 3QBTC3wxgSPUbKLqjZjh6aGwM3yKHWhaLU
    QBT_LOCK_PUBKEYS   => [
        pack("H*", "024ee83659c56ad0663c324cbeaf4cf969ed2c8171af7b5f71afcef472321f22f7"),
        pack("H*", "032a20877b907de2a1a9ee1ce5043f1dd324605a24c64e41663ce8905ac45d2f1c"),
        pack("H*", "026463dbd08255e4c5930d889902cf0b02efba68c0de392c2cfe10e8e4f8e6bac6"),
    ],
    # Falcon-512 pubkeys of the three federation operators signing downgrade
    # (pin) transactions: the freeze-script IF branch is 2-of-3 of them (see
    # _freeze_if below); any order here, the script sorts them. Post-quantum by
    # chain policy - unlike the EC pool keys (Bitcoin dictates those), these are
    # inlined in a consensus script and public from genesis.
    QBT_FREEZE_PUBKEYS => [
        pack("H*",
            "099dfc7296b6951f0310958069658d1e2dab2b5a5c77ae72c96a384a149db447e81b202d1c40917b5fad050bae" .
            "45a27a861312295e3b80eeb20150468add4cd244bdc9d15f8e583531ecd6de8b5e09ddfbb3a01ea03ddc8bc4e5" .
            "12ec9ae02381cb18f4ad4a065514677902d91d484e093ab19017791fc991382a1581cae7aea8e18253350ec704" .
            "a49978324614706091e05720bc1e5e71444de76db22cf3053fccc92b24c20989ddc1b6091156e76b5238d62965" .
            "bd1533994e0096c943742c4c7ba74fe2c2911032049657023e4c9e415dee787c6cc217cb23473820fdb657ed8f" .
            "5c91d2f4a46da97c3e75204643bc83c079a1dcd5dc6e6e7562736baf0cd6d8bbefe6d16215ea3b2d865497ce60" .
            "f4e540b0a8223f8630aaa268a4f2c95168e16e4820bb8da2f24b424f4b3ccb2615a987d0e503908871221171e1" .
            "662ef2a4eb016f5b6b217bc7384b3a2564bdc4722870604d71841612cda748f3ba90e1af4c3c43aabc97163e9d" .
            "3d502085b5aa956523b0a0fc4308126021dded74651506df5c6d15ec4be36115d874c8b4c3caae21beadeaa51c" .
            "141a58e98959c164279055f9c467ef8f79925bfa8e89eb50d4c923dae19d39b8195264551b4249b3e353d1efa3" .
            "55fd97322d78aa5521f6cf17d93cb012a5114a3e5d71e9c673190118aea234064a41024940f8dc8f0c3b84b44a" .
            "d0a6cbade0e9f84ae47803167a2782edc87278d7135dc88d9f22f81485223ba6f44cb8a854fa7eb813c255a52e" .
            "8d7a7aa1adc0d28968acb7aeda282f4137a32621d699cde5b1f942a47ad514078a2a679f1806f6b710428d55e0" .
            "bbc092628ca6f9488b48e85a5cb4388f65a6be45bd22590772354649d927ea542b34d1d0ef473bb23acacb3e5a" .
            "a059093b3252da8e4dc5cac6c987da24d8437925aff0239ab69594988e1156bba6bb25033e0a20353340a09f01" .
            "002ad16f159be8cb077b09d892f10885b51c6121f9e7d7f0ac61660a5d730347f34c59165b17a32244da0d4215" .
            "25147975aa8bbc8f4915362ca28a8d1a75627a5808d85107626ac305ce8d1c01eba7b29854a61545a68c51c159" .
            "7a2238ce42aa51601fc8d35ac83c7dd4fb4bdf91161a39b315d511335d9087beda868d1ead316045786624b081" .
            "6dc1ea8aaee89735920e3dbd604a64422659aa2cc4e59d3ab87856d26a07a594754769d0a21a465427ba4d27b7" .
            "1578ed452a96af3818ee453be504aad8620357505b63e6030bb701e337683422c681469c4e01a8dfe13b"),
        pack("H*",
            "092d86e8112b495797a6a3c6b7060d84769806074c3c29f6fbbb98db3b98c224eb2443749b1a8bc4682b949055" .
            "da39491a57ba1d1b96b19f9a3c28d3f76c9fb95e762cba84293cbca867f13fc1d580942eb69ad7e0827acca9e7" .
            "ca9a2e6984a9ee4bc0b20a85c3af27fb39aa7b340f6afbbd88bcd817d2550040b600234480a93ccaa3204f9f2e" .
            "a221bab982c8184e40b7c2e7c137bde7b1d484021b3efeb508ecd862982a049894aa0189a19324c8b550829e87" .
            "9484a67b60ac42e456f86bc576305daae679352f14d65f95ae2492a81a0fcfa38abdf8325c073d8c026116c113" .
            "04e5236117c54e6d9232d21c983b1fe6025baac92ca7067c28922c91b150f7fb38c551a5a40ab104dbaf448927" .
            "659f5b69a454e9d840d83b629e6467fd4a505a6ed917934b42176d7da4d12871bbf286966087eca15ac5927a6f" .
            "192b7122dac2d9e02c7d9094c1e419b55c3a78bb0db006fe46458900febcd5b7e78395e02e9699f1415bcb305e" .
            "0d79f5828e7afeac14796f1e5774f4b20b461d7e8472967f5a68b1e24c6b3e1f5bbb4d0061c760ca4b79c8d80e" .
            "991eb9e5cba8dbd79436825091484a98a3860a3a324c8ba75c2766a9187867942022c2d632125c6171abd25f59" .
            "8ce214c44b9f60b529e926ca809fc542c65341b93282692a99a93b1d963aa5a85d2d099e6c642fe0340ca1af59" .
            "caabf44feeb7a6691ab02a89dee8c5a32419b62f97708ebe32cc63508768230dac12048a9daf16d0a5aba79170" .
            "907a82e390513179dc93dad050952a905c8907c1f2776df276beaf750922c2f20ad0fc69c549819aadf779f5b0" .
            "120c15089cc21755f8601e13aed1a2c71c38ac1e44e0376b0f12496a3052d84e40ba2a953bd48e7a1e37170244" .
            "de32604fb2afd193af528c37a95ea12d7c3205ee25dab959ab67b70ead7118ac043204ea6ec4a0230b976e4bd6" .
            "35215fe2e78b2973035a65c379b98e7044644389b16357b380201462688a155f9a71d10bcbf640f431cee12233" .
            "ae51afd82191bdd9b7483a9bc036a9300111efe27cc56056866f19a2afcb20aa06404ddb165861d972895abf84" .
            "987599e2c7bf8ac074d6e39e386be1d17bf887e6091cb906e79ce3771e6db3602fc00e624d7504e92c09e07564" .
            "6303c63014daf5fd56221c4656a5c3c8a2464a8a33bdeeb005166ac2cad1bd93dda96572073370b09367ac5e0a" .
            "548cf1817784daafc58ef73fa58ab27980496d6a6ea68af8c372a70e011900512816e2851e850bda1a78"),
        pack("H*",
            "098969b559cfe0ca3e81aaaa89991e31393738dd05ec0d9447c0bd008cacb27a1a70cfd543c624aa032e9e01aa" .
            "0a79ac936e4aae06ebfce5ebabf1112ac2542c74cd61e1cd904f03e4c3d86baaa2654dfe6a07a3d19275254757" .
            "575f2c88923a3fddd86a8238517a8d9d0f2ef1c8108fed597048d7186c0053d170f6d0251795703e2470ec4719" .
            "2466db122a818f744f1b8513e36fad77278d262a24a086b81a983320e575907212235a8012abac492843f173a7" .
            "6a84a482548f0ae86c396864d214ca860c5f25eaf3b76c85ba09e16673c776a55e3359bdce0f82c5ae7879ede2" .
            "7b2111e2196729a308e150b7abf597a20253806be1888a2330f392c54e2ed46b5741c49cb63952cb68e13f66e9" .
            "383a618966783e62ced40c2b9acb2baed5fa375c8c757c26946e00a875070a245e31fdf5e5181236382d82ed41" .
            "2db22ce4c9154511749909a0ff8cab9e547f5ab51d83030ca6d6dc2ee2b662c561a624642e51d7a0fc43e847f2" .
            "83a5d353ca0761f8489ce7bb96f200621b014955b2e87199d7931e028ff2b4a8186c7d1343336113afbd503b9e" .
            "64d9214d3153a3ea520dc637a1ce0e5a41468c77c2aa6eba5d8bfb23c1d65f327ef40669e2681dcb306293361c" .
            "1084995062bd3b1a4b33fc2a8579c978d106ea53af0107dab0ef9eb3a4d3086f5303229c5543124d86073d5ca4" .
            "3765327f6858aacd0916a4083a9bd5aa00bd1dbcf97506bb9dfeca79e3477281a8750afe22c6bd9129ca416444" .
            "2fae853827c94f70a852a7bc6e3d7a5c8e65bb9f58985662750a93f9b75152524329edb35e01ab51627924cc48" .
            "93590b496d5ec5a1186a4e9b69b521874a1f271e49c0b627ef21f4b8d6c5685d5aa46b4133eb49bf28a5d6206f" .
            "d736010f2394238993b67ad1c3237c2a9155d7abacd068fddab294cf3029b42a26b69adfb2445e057063b26d54" .
            "85628491d1a78a2510a6d38c6881f9fbcec2649d00e987028d718f3c3b790fe6d26efa845a2cd685a42d719166" .
            "da9238860b01e3ec0a6e9db3191fd45c13aa8d239f516a3275a087b1022b5d21a103bb066b47a612a3db81b771" .
            "857920482dc4b140dea3fc03b57b22d0737688dea8886e098d19fdbfa581e13fab0393789a3062afa67e1eb45b" .
            "37663c7771b8c25123ae1894fc3b69d0d079711f296d9cab97c15035dfc2497a312c586e6124519dc7d89ee6b9" .
            "16fa51619b0ae66050321087570070e825f88612ac0b9e86848d951a9c60a1f718102323c1d36134ec70"),
    ],
    ADDRESS_VER        => "\x80",
    DELEG_KEY_VER256   => "\x8d", # delegation WIF: privkey + hash256(delegate pubkey), post-quantum delegate key
    DELEG_KEY_VER160   => "\x8e", # delegation WIF: privkey + hash160(delegate pubkey), pre-quantum delegate key
    ADDR_MAGIC         => "\x13\x9d",
    PKH_MAGIC          => "\x27\x10", # base58 pubkeyhash strings start with "6n" (hash256) or "2C" (hash160)
    PRIVATE_KEY_RE     => qr/^(?:[5KL][1-9A-HJ-NP-Za-km-z]{50,51}|2[JK][1-9A-HJ-NP-Za-km-z]{1755})$/,
    ADDRESS_RE         => qr/^(?:bq[1-9A-HJ-NP-Za-km-z]{33}|3u[H-K][1-9A-HJ-NP-Za-km-z]{49})$/,
    GENESIS_TIME       => 1635933000, # must be divided by BLOCK_INTERVAL*FORCE_BLOCKS
    PORT               => 9555,
    RPC_PORT           => 9556,
    REST_PORT          => 9557, # Esplora REST API, https://github.com/blockstream/esplora/blob/master/API.md
    BTC_PORT           => 8333,
    SEED_PEER          => "seed.qbitcoin.net",
    GENESIS_COINBASE   => 0,
    GENESIS_REWARD     => 50 * 100000000, # 50 QBTC
    BTC_GENESIS        => scalar reverse(pack("H*", "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")),
    BTC_P2PKH_VER      => 0x00,
    BTC_P2SH_VER       => 0x05,
    BTC_BECH32_HRP     => "bc",
    UPGRADE_FINISHED   => 0,
    UPGRADE_STOP_UTXO  => _stop_utxo_set(
        # "txid:vout"
        "6c3efe515b5017c5020e1f20a2c5924fa09e6648cf3eb3858771d2cad7edec45:0", # 0.1 BTC to PK "\x02"x33
        "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098:0", # Coinbase P2PK 50 BTC, block 1
        "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5:0", # Coinbase P2PK 50 BTC, block 2
        "999e1c837c76a1b7fbb7e57baf87b309960f5ffefbf2a9b95dd890602272f644:0", # Coinbase P2PK 50 BTC, block 3
        "44794602bebb5d51996e3c9b6ba9bd72f62bc9308b4eeaf52ca670b0fb9598b4:0", # 1 BTC to P2PKH 1F96aqP38aRb8aVexSUGAh2kiCyjrgoqBh
        "277951bc92bc86ed75ae4baa2ac5e7d1f3ecd2c951819796ad7d04cda431f430:0", #  800 BTC to P2PK block  3307, Feb 2009
        # "6bf2fb101058394e3aa7f79c188cd1967ccf76ac1cebc33c3c7fc510272f98aa:0", # 3233 BTC to P2PK block 40758, Feb 2010
        # "42bd3ac3e78bdaf69c4c020a695cec9fcfc3f9777be531f2fa0aeb23d884db4c:1", #  875 BTC to P2PK block 62373, Jun 2010
    ),
    CHECKPOINTS        => {
        # height => pack('H*', "block_hash_hex"),
    },
};
use constant TESTNET => {
    GENESIS_HASH       => pack("H*", "9a23986048cffb3b5115365cd94fe58441703653e561e0ff89f00c68a424b342"),
    # Address: 2MtQBTCa85CFPFa45Tc19DmuYa3XhfSuD8D
    QBT_LOCK_PUBKEYS   => [
        pack("H*", "032dccf5c2c79a5298dd7e1f1aaf9db35f0b2082c4a7ed599a2fb5bfad5b4e3f36"),
        pack("H*", "03c7f19d0502dd1db33fb5298efbc16848d9c7431ee88fb0fb929205580395599a"),
        pack("H*", "03acebbd33221306e9263cb6d03f7ed33e4bccbc85dc5bef7e49882351650b4909"),
    ],
    QBT_FREEZE_PUBKEYS => [
        pack("H*",
            "09bdb85ee8f805c54de6c505c8af4a94ce2f29682de71b75809ae79567aab432d2fea163a90831d74f86a35a1a" .
            "b515a16fb79eb8e0c4dd59561c9972756b9e1653f98c06eda274b4ced2f76001b2834a1f250450c31664841810" .
            "e1dda7c1bd732e88e1b6fe95f0b419f08059cac5ae40c98a851f44f02ea0a93a49a2e1cba733162894ceeb6a93" .
            "ce4fd810c19e7060c85251957008162b479de70607ce756b3603455b11cea302e3553f8a09303d2fe347a826f8" .
            "c5dacc218584a678cd4044b2c8325982b94c1863d636603255f86b57024f273d2ded81d9c49e5a099de128ec92" .
            "a1f9a4c569dd5b24417023b2c45f028c25ea7be3d44ef87d45204a444dace0752f6f933bfe0dd135d39e5c6956" .
            "c5e45b21919e1f26ec2802871e7b3964689a7f85d6b5179a7a6ce0f3aad8e44990e2d145ae8e000b993ef67848" .
            "ad16edb8047851a09d9938c1c22d07a33d2b134ddb1102cee94b50ed6583ec108449d847a44019b525db78287d" .
            "557b11dc40b34e2db44b569503f5d9638aab5b0db834d4cc137100ec02d3eca8f41ab693882a48ab0ac585789e" .
            "223355c04de2c221fba50e2dda8a0d3321808c246716566afdda98f0c2a64be5208787552b8b1811a2552950ad" .
            "bed15a98ce5c66b80466115d265a68d58270e772494469e2671fb89d5dc0b610e37a8648c892edc47f0496eab5" .
            "c329671d066ed7272e5469358ab4ea6bdb8a912341fb56a0b54e88e62acb37345cdbc21ed646986ca13231a238" .
            "83099c01058efd3b657305ea5605055241b3146769529219f58b1ccb1301e408dd462e9212bf0414d2a607fe33" .
            "932169f3079c08bbbf67a64452e1a08555a2aaedacb7a06d44a344b164c6acfc4ad65cf94a266688aaaae92205" .
            "55687a2845498879a0ea8734a2544f4c959d32facf81125a9c48aeecbe16be923918900ca151b4a69ecbc59045" .
            "0c48f21414b7c40ec57f927b57fcdd9751e9b458689ed3bb11ad26a1690153d7d605196cb438233d380aa7f2cd" .
            "0bc58ae5922031c31ea52957f0b0ae65a43de1a0665eeb8a9e5370ba8d244edce23b971fe1bf2ca22247c8f55d" .
            "74247064c8bc39cdaad4bd5bf485b4afe0089d74452d5ec7ba13058235cf60de2264600de26596806169813a31" .
            "0ae0f9a52ef7947a562a29be260ac19c014e8dad7387e930ae7aa1469dca9d9ed829f2ae9a3c6b14a79920dc9b" .
            "b4e0abf35f13b8a618eb1864ab24632640556125a746c88da415c24649f15387128e30bf1ae9803566da"),
        pack("H*",
            "091a3a73d126ccf2ab318bc4eb6dd97a0a77f02ea9c1445d4b78440b2d7aa1a0b7c645d80f61e92044ea479302" .
            "f1b307833e031678e1d69cac7b9884a04787c34562c1b43d194346daf288ff5988018ef7180c07697704adf141" .
            "5cd7687173e43407c8bbfd950686e701b128a87b7985a601d68cb1e6126247d1b955d11924b2a243f445a2c443" .
            "fa4710d7af5e86794eb27213635b241d847aa56f2472405a822216ab3109e7291ba60f980bfa8c6f4208cd2ad3" .
            "20a2235768ec08d0d920a43a1f393f071814d8543a80581c4920bfb504c0378cdc0020dc8f4c62b48e4934121e" .
            "15f2c1d14944d8341d1a6315067685288892421b3e77be3e46164495537ef4357c4b036305854b1186be011911" .
            "d93282da25aa0b50ffe4ce2489c378dd92ef9b507c65bd080c907a5ce46dd49e8bda9b64a5075b592c8f56b89b" .
            "db43adbb9b3b232a71728a747a878f00f46f84c08216b508b3077f9ef835eaaa3429232669cdfe9451e3e34459" .
            "ff3b074bd90c4003414ea3368c49fba9ab27ff25ac3544342cc53241570a988a7530d15fe5c01bcb48b8d2920a" .
            "99978c004b226707bb23b52072cc0bca177ae5f0eddbcf3766be04b8defd131c3ac29c86022fbcbf04d620b061" .
            "163a59a9182c40988019c50ce78e1a921380a414781c5294de14a626ecd6560465e9291428c98ede1d1dbcca4b" .
            "e853ef511ed993f66b1769a96ac302cc583fc235a0395653913225245691deaa04bd357b12e777718c62e66281" .
            "aa5632d35e48983142fc1365e47f8bb8911579e3bcbf10b8fac1c95b4eb1b8db6b6e49a41d3a7ada64968828be" .
            "b904c96c5dd0b50be71f0aa2b5a124871c7093f8129543ade5526ce62013a512483ecfe898cd24125c53b8dfde" .
            "b73ac6d3e32d0c1465b98e2356dcc70b1979842c9ac7183299a8b3e5c54714931a33d8cf29d58481ad44af38ad" .
            "577294ca957cd012e2dc28c96e9e8233039a3d9cb91a28af1c69532895050426693e4d2b61076d5b4401fe53bf" .
            "93e49f204ad7d058bdbfa504950e2e5730a60573de253d82b14e83ad2ec380e5ad67ec4a1908e02c434d68c13a" .
            "c18071d761ce18ce4bc84210b86441c351a68a5e51190ee7e361411b8406d04a6ee82902d0b04eadaa481894b0" .
            "ffe4cb1b99c5834dc8bd061a0a917bab7c6325de083ce9ca457cfbc6e41c03a295b432fa87a43860b358785c8d" .
            "9ce59772638dfd1f806f178dd1206f189fdbdf1013335e4ba397176e29864e59c5aed976aa8ec5a105f5"),
        pack("H*",
            "098b44ee70a495ea46d483dbd016541ef251b4c95bfa55fdb0ab2717dcbd81ab9ae09c178b96342a476aff465d" .
            "15b0f1a6404ca654823c82f72faa652013c489041aaf8424a7a7b1a642e4fcc50f83207619209c49b15a65500a" .
            "6dee225e853965cf30ae7676d76c212163946272f35ee83739b789660c1c1714356b47e90f4f65eb5340d8bb44" .
            "e867636a1868101d4c779a615163459f79e9eb7365d5b4363d23f54120ddbb836ecca7e81b9bcdc84125384ffb" .
            "2aad4654e92768f4a70c67c48101272caebceab1db69da8966ccb8a35741e78ea0efc62fd7bab8d447c285084e" .
            "9aa17fa2800f45ac6472a50f09fc078d5b50054ab268b6c34270de872a651582498aaf217d83727e4e9482b9b9" .
            "34dde8d424180b998a6fb3958962906d5ce21b415bd7dbce6229a239592824330949cb857c92313e041c54fb4b" .
            "d14f18bed46f138f42e15a61bd46df4b8c131ac282ae877da7fb708a6323b9eab58318072af82024e9676b0f41" .
            "f4c6bd8297bab1e814d0ea57ac12877001e410b66076970e098d2b288dbb09e7de3c86199b65a013876691665a" .
            "a65fa23c88e76252360e19abc6635cde889aba81de1019387adc007aae1a5e31db522a937588ad7785c5dbb319" .
            "3958b49063574942db75e7a2db60b0b613b551852b808a16f362baa1c67d995451fd8ec97dd466c8ed5f7ab701" .
            "57616719aa3ee81fa2f71ffc2a18b3ed5eaa2ea11b0657fda9b15559f960a55f8af03720d863008a9d4570c27e" .
            "513dde8260af33b9e5d62b8ced1c1ac99c1a332a07030177287f520aafca04242661ca5b485bf804160174fc09" .
            "b9f586a5af722808246064358eda680a6bf05bea24e1efdeda6df49b117be9f262f1ac92aa28751dfe17772b5e" .
            "b2bcc6be94326f5a5ebc93e864ef4f46b5a056bc50cb4b549a709e0971459ce6a85c6659a0f480409b91185c60" .
            "02e280a94fbfc5d4e8c2aafb0b554fa96797eb1e8681b01869597c3e7d76d340f0b84184d2f320b6bfe6db708d" .
            "80c59d88ffbb8b1cfc1b810810de1e900828ea858ee82c3bedc10aee18370a92698b62d59cbce28aa596859489" .
            "28a2917109ee8e6ef00957df8dac815ce8cc24e42f480957d49dc8a8c4a3a3e00e474722bd8a6a51bf39b053f0" .
            "8769af7e12067155862712015e979f811f5046e8d1185ea94c8dabe16c0ecf3dca28332c415998e453c662c860" .
            "0f36c5039dd1e22e3de4973300043c7d5005ffa1ed204dcb61024477aeb28eb71581a44ad0d4757543ba"),
    ],
    ADDRESS_VER        => "\xef",
    DELEG_KEY_VER256   => "\xf0", # delegation WIF: privkey + hash256(delegate pubkey), post-quantum delegate key
    DELEG_KEY_VER160   => "\xf1", # delegation WIF: privkey + hash160(delegate pubkey), pre-quantum delegate key
    ADDR_MAGIC         => "\x04\x73\x89",
    PKH_MAGIC          => "\x3f\x00", # base58 pubkeyhash strings start with "AKX" (hash256) or "2vt" (hash160)
    PRIVATE_KEY_RE     => qr/^(?:[9c][1-9A-HJ-NP-Za-km-z]{50,51}|3[ST][1-9A-HJ-NP-Za-km-z]{1755})$/,
    ADDRESS_RE         => qr/^(?:btq[1-9A-HJ-NP-Za-km-z]{33}|3ua[234][1-9A-HJ-NP-Za-km-z]{49})$/,
    GENESIS_TIME       => 1784460000, # 2026-07-19 11:20:00
    PORT               => 19555,
    RPC_PORT           => 19556,
    REST_PORT          => 19557,
    BTC_PORT           => 48333,
    SEED_PEER          => "seed-testnet.qbitcoin.net",
    GENESIS_COINBASE   => 0,
    GENESIS_REWARD     => 50 * 100000000, # 50 QBTC
    BTC_GENESIS        => scalar reverse(pack("H*", "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043")),
    BTC_P2PKH_VER      => 0x6F,
    BTC_P2SH_VER       => 0xC4,
    BTC_BECH32_HRP     => "tb",
    UPGRADE_FINISHED   => 0,
    UPGRADE_STOP_UTXO  => _stop_utxo_set(),
    CHECKPOINTS        => {
        3000 => pack("H*", "20e0dfa02b4ab01b44bda94112f1cbeaabe3c1bf51a568263a39a70a47054d4e"),
    },
};
use constant REGTEST => {
    GENESIS_HASH       => pack("H*", ""),
    # Regtest 2-of-3 lock keys, address 2N43iTdZBtFPzs5PvKkkbw8noqiDMGWrmLQ.
    # Dev keys, intentionally derivable as sha256("QBTC:REGTEST:LOCK:{A,B,C}") so tests
    # can sign pool spends without storing secrets.
    QBT_LOCK_PUBKEYS   => [
        pack("H*", "0257b3c47b272acf97881d3c1f65c122dcbd1098c218dd7a9d612fce02b87c9599"),
        pack("H*", "02a9e30e791334d7cc4ababd3cb6e5795668f654d434e941aa96ee23442643ad07"),
        pack("H*", "03cd91e21e72efff1cbaf0c70837a791c163e7b508f775de47bd7a6bacef3a6c1f"),
    ],
    # Regtest freeze federation dev keys; the private halves live in
    # test/lib/QBitcoin/Test/FederationKeys.pm (mirrored in qbtc-downgrade-service)
    # so tests can sign downgrade pins.
    QBT_FREEZE_PUBKEYS => [
        pack("H*",
            "09963243d3f7cc36a09d4b49a9c767bbc29408202e608ccdf4313981912d3262796619c73064d34954878b9ee2" .
            "03c4f4e7ed35286fa40323c651be0498c4c2f52d0a6b18bed6d9749133c8ddc11648aeb9e7b5e0aa0bfafada1a" .
            "02b133bcc2dbfbe2f88e1552d57d22314b5c3612f4c80938b85c34a201a9401aaec8dc86d588b030e35fad7374" .
            "5c2ef592af72bb3d8d8706df9279a152d9cec09426352e86b4efda0624f018cb0754730af77ab2edd46f85a5a7" .
            "38603e2e7af29558adaf02a8429bc2222726aae3c19b115579addf114e0cb8154cd2a1300f9db99d57c5c991c1" .
            "929556924801ca4b0de625c85fc268a958023451b1484410b5db4c8f1c511b06be5ecf3f02290769efb858c97e" .
            "f7d6e85e9e727763b7a38c090df9022557539e185a41b4948302063c88aa1eb861707102e95f2c52209708990f" .
            "4c7495fdd3d00d7743fc01b7dcaad44b92c59ac045ba7caad74183ece962f907b447ac0d09251f958c06975af0" .
            "3d24e14502b661d955546f83a8fe193543ebeb03aa2731729c051142fc4ae88b872e6a390b108b36b196f533d5" .
            "9a1310aac2b7f287c343d6791916a4aca652daf0a3c481631172e9008fe2ac69e0c06d40106a7cf9182c61f708" .
            "5c5275a4c0ab152d8c85d30cf91d5e33d1dbc6810ce95df81b165f63d838167c4cc3bf8a09bbc31f2c2a66dcb7" .
            "2544b93a52ddd44408cb04aa0449135d704cd80c841f1c2685bd3220d8574ba2a026746041bb1a3d5b5a3f25dd" .
            "a54ed0e995d43193d02d8658903b1594c170f16ddcb6ae4892faacea20e46c845e5136647e7648e2a7650cdc68" .
            "c83b048f16e46c1854801da8d129d1aa57f42c5ab883060875b9bdaa2059c41f58819ae34d41e12a8e65f25217" .
            "e2872d9c60bbde0901e54ecb3a2a5c0d984587354abf64e07e89d8975b9ae0fe07bf1cd44578c0d1ded68b6308" .
            "d1212f630a2264e8daf5c1ea158809572ed2660c80f5c14dd7235d20370bc725861cdcffd8bb43bb475a67388b" .
            "284952b83b496c87b97dc6f3cb278a2f88e98b558e6c3800850fb4fd5a4a126d9189ecd31b1a79789339cc4544" .
            "72f8d4eb9fda620dfac4192d17560241e3fe63c28be5d1f82a21682f2a661366e9a1bd38f837a2cbfc3820e57b" .
            "9e224b10b9f3c3e49cd11b7886dac287d88891f037df1f8e94de3af8ef09bc7e85ba5791111459e999658dd3ec" .
            "7584dee7168ec5b4b0b7a565c64881e808a05bcdbb49c0f551d217151051d1614613a83f615749690a51"),
        pack("H*",
            "09b76647191265717220cc90a8c94e90f16c913f4a5315da4d8baed47b9625eae3d14cf465f9dcfb14d31a3752" .
            "c64b01e2474709abb24de6a155b4eb0b1a194b9dd6c8d9d94fd6803acd437a56eb3315b193aceae56d9edfa1ad" .
            "9378baf6b1f7f04e5f20953cf1976d2f563ab4070a2e64b6e8dab352ad375dd1bf46554a37449ead536b600f41" .
            "1220571bd50e0ef4f9a0cde340baec84d0708d2d88c9d19bd515a07ed96ed1e6ea433f81fbaa88e959b5b03e86" .
            "1e61f55e60a34a3002a93388f7047c2539af71c62aa903b75a28f2496ea1bb082680b101c89840b572b5810bee" .
            "235a68d274430a453a1e53aaac7b081430b7dd46b4063260759e28ec5b59bcb6d986ac49b45b04ce21f39265ed" .
            "317592674465ea019f6fc199bee001be89ad952cd3fab166ff47aa0789cc4f6b5d9e9585f81a1527281f0b996f" .
            "8f4d0ce1c344851a94087168ce416b65d817d79127153272817776235ba83e5fdbed09412461642a5d955b4145" .
            "ed80b40f7d61ad8526ad0b397b501716aa1699484ae2354196e1bc21b7d0bb29b6a3682ca8a0d57d6fedce63b7" .
            "97d764aa86d21d5f3c641818181de1c9916d98028b17608d352463b8d6c229e8b910ea9b62b65147f1889b467a" .
            "be8366186cc1943af5001d86c34c852b2900d01da1a203d8c7e3ac62acfd1391da7e3e005c844f5f6196748d08" .
            "46403f1c9ea7f39bccaaae1d74eb0519a748923258d8a0e95d3af956088d2b2291b08276dea8bde0ac9078c416" .
            "3d260b3ad4803772d07d0662e4db49c5b4f2cc0e226bd643a41a4b0473b9dbc6a0409e0a4ad8bbff24e870b490" .
            "290c40cbb2827393b01d2f47e45cf6a367b314b89d843946212c1add42de1c792726d974a8d7edb4322f326c4a" .
            "914e20b2d6901987aa944cc55a04b298e27a87a59358b7399a2306ec5f595442956dce9462e66734b588beb4fa" .
            "9fb3ca117c2e82ce267490a23eda9a671a27008ac6bde3aad012b51911b0a6ef6922fdc2f43d0b821c592383eb" .
            "e4711cf560610f1e225914a0572e2ae8a9a9a8207c8e1d858417422b12668ddd8a100f4c3b45be0083a258de75" .
            "41165b3d29cb011d69e70ddd67ae70bc59c12ade0ea6dd48d80f429d8af3b75c0722550117e6c3d3db4144403b" .
            "bbe7bb32f8cc9b37cb2d883a382a416954751af70b81ea55bbe25f819ac0a46b317f2b9b1e68b6768bc4351215" .
            "30a67e397bcd1d0e16971bbaef3e5f059cf147ac19b552fb08ad95ca32bdebd1a1aff33aae0fa99226bc"),
        pack("H*",
            "095d240177e157402ec8f0202eade86b193787fccf8272516200b7543fa9ee0c82a25dcc18fd937b0f06c51b88" .
            "cd198527eb9502b89a918d7d90f28fe1be2cfc5809c0f6a6ad476e9a53935eee829e0ee619f5ef8f26e2bc81f4" .
            "e33734620c74de8ea22c2ae170f0d6765255eac44caa428ddec5e12f8a8e78411c8068c0e7548ac289545c1e0c" .
            "c6f4825b11cc8862c418c221383b1045356da064743c7f157d80454e6ae8d322113db80ec650a31105b4a23f48" .
            "2cc35520da68cb76a82a9d8dac390952dd1b5475099b48726b58a7d2541c0e87619ee3a99527274656cbe81d02" .
            "8f3d9671fe8ae38b5615050407ae9516614bb4a1005eed3e77056a1d87b4b938c5c74abae1aa4163a52825bdad" .
            "90121ead21be4b48a085d7b2f09639115171b0de1f2550d3db45d5eb1ae09d1dba4c25667487bb1add86eb4f57" .
            "3357edd7d5ec2d40680d6b8bbb2fd29d02a907ba92ce946ec1b1ef6496acd4a6497240252a41abe92954a76b99" .
            "e25108db9b764d12c35d0753b50871201fcb5e4c1a1de35b044600742890d459938b0cfee0d380be7842f5f370" .
            "5782bff8c08a50cdb53f4998367190fdb6423ba7a4d10639faca9389ad9941b037c38864c407b2dc42e2aa6d0f" .
            "a990cb809adbad387482b985819b8d0225a567abbb8972a2ad0948a831ddf60ce9a1a1f8507acd4919bdd22122" .
            "2a83724682d44bc705b8a6c11b45e02f5088507779481d27a7f676c123421eae409ff6e2043a924df125e4226f" .
            "51322164dde52189695cd4e7254faba0ff73091c6a6abd6dc17717bd28849524a56f1ab496d6d4dc99fc42a46f" .
            "6458a7ae0b54b132152f0b4e86d0b55b4ddc7a866a544c4f697818e508ab15d9add4cfe8f2620d1721df5aac83" .
            "594674d75bc1294db17c301843d64d247ea086fb5908aae48fb1e54eca543923181e8df65866333824aac358ea" .
            "3633ca50fe348cce0b4691836b04c0a355daaa1cfa9567fe1a1379edc8386e5d67ba85d2b8d5e24833e915a98d" .
            "df97614051697369ec7b8996f2e4eb103045395304a87e0dce74f958a37899651115fee7b448394fa242527228" .
            "9914747f8436a1f22b3289ed070a3a0509ba1eb0a4f65f8a414756a1f475eb1111ba2a0097db7e6ef242b8f29b" .
            "a12730844e086169e6b33f7875595641b5acc9e7046d4f1b8cfc3ef6ec400b07bad724f501eb83ba8935b39c92" .
            "6d5d45aa4d497eb1dabe0a6cc910a4f2024bd7abc800411f19b82ea082d99eb30d1f6322b47db9dd09a6"),
    ],
    PORT               => 29555,
    RPC_PORT           => 29556,
    REST_PORT          => 29557,
    SEED_PEER          => "",
    BTC_P2PKH_VER      => 0x6F,
    BTC_P2SH_VER       => 0xC4,
    BTC_BECH32_HRP     => "bcrt",
    UPGRADE_FINISHED   => 0,
    UPGRADE_STOP_UTXO  => _stop_utxo_set(
        # block 9 coinbase, the first ever spent satoshi's coins; arbitrary value for regtest
        "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9:0",
    ),
    CHECKPOINTS        => {},
};
use constant COMMON_CONST => {
    UPGRADE_POW        => 1,
    UPGRADE_FEE        => 0.01, # 1%
    UPGRADE_MAX_BLOCKS => 1400000, # middle 2036
    UPGRADE_MAX_VALUE  => 10_500_000 * 100_000_000, # 10.5M BTC - stop conversion when upgraded reaches this
    DOWNGRADE_FEE      => 0.01,       # 1%, taken by the downgrade service; covers the BTC network fee, the rest is its income
    STATIC_REWARD      => 20_000_000, # 0.2 QBTC/block after upgrade finished
    REWARD_HALVING     => 10_000_000, # blocks, halving every ~ 3 years and emit 4M QBTC total as block rewards
    STAKE_MATURITY     => 12*3600,    # 12 hours
    # Trustless downgrade relative time-locks, encoded for OP_CSV as a number of
    # BLOCK_INTERVAL(=10s) units OR'd with the QBitcoin time-type flag (1<<27), so the
    # lock is by wall-clock time, not by block count (qbtc skips empty blocks). See CSV
    # handling in QBitcoin::Script.
    DOWNGRADE_FREEZE_CSV => int(DOWNGRADE_FREEZE_SEC/10) | (1<<27),
    DOWNGRADE_OUTPUT_CSV => int(DOWNGRADE_OUTPUT_SEC/10) | (1<<27),
};

use QBitcoin::Script::OpCodes qw(:OPCODES);
use QBitcoin::Script qw(op_pushdata);
use QBitcoin::Config;
use QBitcoin::Crypto qw(hash160 hash256 sha256 checksum32);
use Encode::Base58::GMP qw(encode_base58);

use constant COMMON_CONST;

BEGIN {
    no strict 'refs';
    foreach my $key (keys %{&MAINNET}) {
        *{$key} = sub () {
            $config->{regtest} ? REGTEST->{$key} // MAINNET->{$key} :
                $config->{testnet} ? TESTNET->{$key} : MAINNET->{$key}
        };
    }
};


# The BTC-side system address: btc->qbt upgrade deposits are recognized by an
# output paying QBT_LOCK_SCRIPT, and the same address holds the frozen BTC pool
# the downgrade service pays releases from. It is a P2SH-wrapped P2WSH 2-of-3
# multisig of the federation operators (QBT_LOCK_PUBKEYS):
#   witnessScript = OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG, BIP67 key order
#   redeemScript  = OP_0 <32: sha256(witnessScript)>       (P2WSH witness program)
#   scriptPubKey  = OP_HASH160 <20: hash160(redeemScript)> OP_EQUAL
# BIP141 requires the scriptSig of every spend of such an output to be exactly a
# single push of the redeemScript, so QBT_LOCK_SCRIPTSIG is a deterministic
# 35-byte constant located in the non-witness (txid-committed, SPV-provable) part
# of the spending transaction: it identifies pool spends (releases, fee bumps,
# transfers co-spending a pool input), which must not be counted as upgrade
# deposits even though they pay change back to QBT_LOCK_SCRIPT.
sub QBT_LOCK_WITNESS_SCRIPT() {
    state $qbt_lock_witness_script = do {
        my @pubkeys = @{&QBT_LOCK_PUBKEYS};
        @pubkeys == 3 && !grep(length($_) != 33, @pubkeys)
            or die "QBT_LOCK_PUBKEYS must be three 33-byte compressed pubkeys";
        OP_2 . join("", map { pack("C", 33) . $_ } sort @pubkeys) . OP_3 . OP_CHECKMULTISIG;
    };
}
sub QBT_LOCK_REDEEM_SCRIPT() { state $qbt_lock_redeem = "\x00\x20" . sha256(QBT_LOCK_WITNESS_SCRIPT) }
sub QBT_LOCK_SCRIPTSIG()     { state $qbt_lock_scriptsig = "\x22" . QBT_LOCK_REDEEM_SCRIPT }
sub QBT_LOCK_SCRIPT() {
    state $qbt_lock_script = OP_HASH160 . pack("C", 20) . hash160(QBT_LOCK_REDEEM_SCRIPT) . OP_EQUAL;
}
# Base58Check P2SH address of the lock script - the published deposit address.
sub QBT_LOCK_ADDR() {
    state $qbt_lock_addr = do {
        my $payload = pack("C", BTC_P2SH_VER) . hash160(QBT_LOCK_REDEEM_SCRIPT);
        "" . encode_base58("0x" . unpack("H*", $payload . checksum32($payload)), "bitcoin");
    };
}

# Build a "system-spend-or-user-reclaim" script used by both the freeze output and
# the downgrade-tx output. Data layout: [reclaim_id (hash_len bytes)][btc scriptPubKey].
#   OP_IF   <if_branch>
#   OP_ELSE <CSV> OP_CSV OP_DROP
#           OP_OUTPUTDATA <0> <hash_len> OP_SUBSTR     ; reclaim_id = data[0..hash_len-1]
#           OP_OVER <hash_op> OP_EQUALVERIFY OP_CHECKSIG
#   OP_ENDIF
# The IF branch constrains the system spend to a specific transaction type;
# otherwise, after the time-lock, the user reclaims their QBTC by proving ownership
# of reclaim_id.
sub _reclaim_script {
    my ($if_branch, $csv_value, $hash_len, $hash_op) = @_;
    return
        OP_IF . $if_branch . OP_ELSE .
        chr(4) . pack("V", $csv_value) . OP_CSV . OP_DROP .
        OP_OUTPUTDATA . chr(1) . chr(0) . chr(1) . chr($hash_len) . OP_SUBSTR .
        OP_OVER . $hash_op . OP_EQUALVERIFY . OP_CHECKSIG .
        OP_ENDIF;
}

# Freeze deposit script (one constant address). data = [hash256(user_pubkey)][btc
# scriptPubKey]. reclaim_id is always hash256(pubkey): a single script serves both
# EC and post-quantum reclaim keys (OP_CHECKSIG dispatches on the signature class,
# and the key store indexes pubkeys by both hash160 and hash256). The IF branch is
# spendable only by the downgrade federation - 2 of the 3 QBT_FREEZE_PUBKEYS
# (Falcon-512, inlined via OP_PUSHDATA2, sorted lexicographically) - and only in a
# TX_TYPE_DOWNGRADE: grief pinning (committing a freeze to a payment that never
# comes) requires compromising two operators, not one. Otherwise the user reclaims
# after DOWNGRADE_FREEZE_SEC. The scripthash is hash256, as for everything
# post-quantum. Note: qbtc's OP_CHECKMULTISIG pops no extra dummy element (the
# bitcoin bug is not reproduced), so the siglist is exactly [sig, sig, "\x01"].
sub _freeze_if() {
    state $freeze_if = do {
        my @pubkeys = @{&QBT_FREEZE_PUBKEYS};
        @pubkeys == 3 or die "QBT_FREEZE_PUBKEYS must be three pubkeys";
        OP_7 . OP_TX_TYPE . OP_EQUALVERIFY .
            OP_2 . join("", map { op_pushdata($_) } sort @pubkeys) . OP_3 . OP_CHECKMULTISIG;
    };
}
sub QBT_FREEZE_SCRIPT()     { state $qbt_freeze_script = _reclaim_script(_freeze_if(), DOWNGRADE_FREEZE_CSV, 32, OP_HASH256) }
sub QBT_FREEZE_SCRIPTHASH() { state $qbt_freeze_scripthash = hash256(QBT_FREEZE_SCRIPT) }

# Downgrade-tx output script. The IF branch is permissionless: any node may spend
# it in a TX_TYPE_BURN, no signature required. The burn's correctness (that the
# committed BTC payment really happened) is enforced by the SPV proof in
# validate_burn, not by a signature. Otherwise the user reclaims after
# DOWNGRADE_OUTPUT_SEC.
use constant _DOWNGRADE_IF => OP_6 . OP_TX_TYPE . OP_EQUALVERIFY . OP_1;
use constant QBT_DOWNGRADE_SCRIPT     => _reclaim_script(_DOWNGRADE_IF, DOWNGRADE_OUTPUT_CSV, 32, OP_HASH256);
use constant QBT_DOWNGRADE_SCRIPTHASH => hash256(QBT_DOWNGRADE_SCRIPT);

# Freeze/downgrade output scripthash -> [redeem_script, reclaim_id length].
# The user-reclaim (ELSE) branch reads its identity (hash160/hash256 of the user
# pubkey) from the leading bytes of the output data.
sub QBT_RECLAIM_SCRIPTS()   {
    state $reclaim_scripts = {
        QBT_FREEZE_SCRIPTHASH()    => [ QBT_FREEZE_SCRIPT,    32 ],
        QBT_DOWNGRADE_SCRIPTHASH() => [ QBT_DOWNGRADE_SCRIPT, 32 ],
    };
}

use Exporter 'import';
our @EXPORT = (
    keys %{&MAINNET},
    keys %{&COMMON_CONST},
    'QBT_LOCK_WITNESS_SCRIPT',
    'QBT_LOCK_REDEEM_SCRIPT',
    'QBT_LOCK_SCRIPTSIG',
    'QBT_LOCK_SCRIPT',
    'QBT_LOCK_ADDR',
    'QBT_FREEZE_SCRIPT',
    'QBT_FREEZE_SCRIPTHASH',
    'QBT_DOWNGRADE_SCRIPT',
    'QBT_DOWNGRADE_SCRIPTHASH',
    'QBT_RECLAIM_SCRIPTS',
);

1;
