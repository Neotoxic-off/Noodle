// severity: suspicious
rule CryptoWallet_Bitcoin {
    meta:
        description = "Bitcoin wallet software or Bitcoin-related strings"
    strings:
        $bw1 = "wallet.dat" ascii nocase
        $bw2 = "bitcoin" ascii nocase fullword
        $bw3 = "Bitcoin Core" ascii nocase
        $bw4 = "bitcoind" ascii nocase
        $bw5 = "bitcoin-cli" ascii nocase
        $bw6 = "BTC" ascii fullword
        $bw7 = "bc1" ascii fullword
        $bw8 = "xpub" ascii fullword
        $bw9 = "xprv" ascii fullword
        $bip  = "BIP39" ascii nocase
    condition:
        2 of them
}

// severity: suspicious
rule CryptoWallet_Ethereum {
    meta:
        description = "Ethereum wallet / Web3 interaction"
    strings:
        $eth1 = "ethereum" ascii nocase fullword
        $eth2 = "Ethereum" ascii
        $eth3 = "web3" ascii nocase fullword
        $eth4 = "MetaMask" ascii nocase
        $eth5 = "keystore" ascii nocase fullword
        $eth6 = "ETH" ascii fullword
        $eth7 = "geth" ascii nocase fullword
        $eth8 = "Infura" ascii nocase
        $eth9 = "0x" ascii fullword
        $abi  = "eth_sendTransaction" ascii nocase
    condition:
        2 of them
}

// severity: suspicious
rule CryptoWallet_Monero {
    meta:
        description = "Monero wallet or XMR mining references"
    strings:
        $xmr1 = "monero" ascii nocase fullword
        $xmr2 = "Monero" ascii
        $xmr3 = "XMR" ascii fullword
        $xmr4 = "xmrig" ascii nocase
        $xmr5 = "monerod" ascii nocase
        $xmr6 = "monero-wallet" ascii nocase
        $xmr7 = "pool.minexmr" ascii nocase
        $xmr8 = "stratum+tcp" ascii nocase
        $xmr9 = "CryptoNight" ascii nocase
    condition:
        2 of them
}

// severity: dangerous
rule CryptoWallet_Clipper {
    meta:
        description = "Crypto address clipboard hijacker (clipper malware)"
    strings:
        $cl1 = "GetClipboardData" ascii
        $cl2 = "SetClipboardData" ascii
        $cl3 = "OpenClipboard" ascii
        $cl4 = "EmptyClipboard" ascii
        $btc_regex = "^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$" ascii nocase
        $eth_regex = "^0x[a-fA-F0-9]{40}$" ascii nocase
        $btc_addr  = "1Bitcoin" ascii nocase
        $xmr_addr  = "xmrig" ascii nocase
        $replace   = "replace_address" ascii nocase
    condition:
        ($cl1 and $cl2 and $cl3 and $cl4) and any of ($btc_regex, $eth_regex, $btc_addr, $xmr_addr, $replace)
}

// severity: dangerous
rule CryptoWallet_Stealer {
    meta:
        description = "Crypto wallet stealer — targets wallet files and seed phrases"
    strings:
        $ws1 = "wallet.dat" ascii nocase
        $ws2 = "seed phrase" ascii nocase
        $ws3 = "mnemonic" ascii nocase
        $ws4 = "private key" ascii nocase
        $ws5 = "keystore" ascii nocase fullword
        $ws6 = "electrum" ascii nocase
        $ws7 = "exodus" ascii nocase
        $ws8 = "Atomic Wallet" ascii nocase
        $ws9 = "Metamask" ascii nocase
        $ws10 = "TronLink" ascii nocase
        $ws11 = "phantom" ascii nocase
    condition:
        3 of them
}
