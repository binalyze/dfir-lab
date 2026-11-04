import "pe"

rule Compromised_certificate_7818933f8f85b4619a2b35fba83d0a {

    meta:

        date = "2026-10-23"
        description = "Detects PE files signed under the compromised eMudhra code-signing CA EM OV CS CA - G3B, revoked after its weak private key was exposed. Any file signed under it is likely forged."
        author = "Binalyze DFIR Lab"
        reference = "https://unit42.paloaltonetworks.com/emudhra-certificate-compromise/"
        reference = "https://blog.talosintelligence.com/compromised-intermediate-certificates/"
        verdict = "dangerous"
        mitre = "T1553.002"
        platform = "windows"
        search_context = "filesystem"

    condition:

        uint16(0) == 0x5A4D
        and for any i in (0 .. pe.number_of_signatures - 1) : (
                pe.signatures[i].issuer contains "EM OV CS CA - G3B" or
                for any j in (0 .. pe.signatures[i].number_of_certificates - 1) : (
                    pe.signatures[i].certificates[j].subject contains "EM OV CS CA - G3B" and
                    pe.signatures[i].certificates[j].serial == "78:18:93:3f:8f:85:b4:61:9a:2b:35:fb:a8:3d:0a"
                )
        )

}

rule Compromised_certificate_544b7f922c31ae220a4a922916f6e6 {

    meta:

        date = "2026-10-23"
        description = "Detects PE files signed under the compromised eMudhra code-signing CA EM OV CS CA - G3C, revoked after its weak private key was exposed. Any file signed under it is likely forged."
        author = "Binalyze DFIR Lab"
        reference = "https://unit42.paloaltonetworks.com/emudhra-certificate-compromise/"
        reference = "https://blog.talosintelligence.com/compromised-intermediate-certificates/"
        verdict = "dangerous"
        mitre = "T1553.002"
        platform = "windows"
        search_context = "filesystem"

    condition:

        uint16(0) == 0x5A4D
        and for any i in (0 .. pe.number_of_signatures - 1) : (
                pe.signatures[i].issuer contains "EM OV CS CA - G3C" or
                for any j in (0 .. pe.signatures[i].number_of_certificates - 1) : (
                    pe.signatures[i].certificates[j].subject contains "EM OV CS CA - G3C" and
                    pe.signatures[i].certificates[j].serial == "54:4b:7f:92:2c:31:ae:22:0a:4a:92:29:16:f6:e6"
                )
        )

}

rule Compromised_certificate_c7c41efe92d825f05eae841a4a82c1 {

    meta:

        date = "2026-10-26"
        description = "Detects PE files signed under the compromised eMudhra TLS CA EM EV TLS CA - G3B, revoked after its weak private key was exposed. A TLS CA should never sign code, so any signed file is forged."
        author = "Binalyze DFIR Lab"
        reference = "https://blog.talosintelligence.com/compromised-intermediate-certificates/"
        verdict = "dangerous"
        mitre = "T1553.002"
        platform = "windows"
        search_context = "filesystem"

    condition:

        uint16(0) == 0x5A4D
        and for any i in (0 .. pe.number_of_signatures - 1) : (
                pe.signatures[i].issuer contains "EM EV TLS CA - G3B" or
                for any j in (0 .. pe.signatures[i].number_of_certificates - 1) : (
                    pe.signatures[i].certificates[j].subject contains "EM EV TLS CA - G3B" and
                    pe.signatures[i].certificates[j].serial == "c7:c4:1e:fe:92:d8:25:f0:5e:ae:84:1a:4a:82:c1"
                )
        )

}

rule Compromised_certificate_6cada367fb1c100088120ea202d568 {

    meta:

        date = "2026-10-26"
        description = "Detects PE files signed under the compromised eMudhra TLS CA EM OV TLS CA - G3B, revoked after its weak private key was exposed. A TLS CA should never sign code, so any signed file is forged."
        author = "Binalyze DFIR Lab"
        reference = "https://blog.talosintelligence.com/compromised-intermediate-certificates/"
        verdict = "dangerous"
        mitre = "T1553.002"
        platform = "windows"
        search_context = "filesystem"

    condition:

        uint16(0) == 0x5A4D
        and for any i in (0 .. pe.number_of_signatures - 1) : (
                pe.signatures[i].issuer contains "EM OV TLS CA - G3B" or
                for any j in (0 .. pe.signatures[i].number_of_certificates - 1) : (
                    pe.signatures[i].certificates[j].subject contains "EM OV TLS CA - G3B" and
                    pe.signatures[i].certificates[j].serial == "6c:ad:a3:67:fb:1c:10:00:88:12:0e:a2:02:d5:68"
                )
        )

}

rule Compromised_certificate_a4aee678f23362b4c0e460b772f214 {

    meta:

        date = "2026-10-26"
        description = "Detects PE files signed under the compromised eMudhra TLS CA EM DV TLS CA - G3B, revoked after its weak private key was exposed. A TLS CA should never sign code, so any signed file is forged. Seen signing mimikatz."
        author = "Binalyze DFIR Lab"
        hash = "2b2e6e0db7c296a612408772b23a47704c665f5bdba5fb58096a78bff5cbd958"
        reference = "https://blog.talosintelligence.com/compromised-intermediate-certificates/"
        verdict = "dangerous"
        mitre = "T1553.002"
        platform = "windows"
        search_context = "filesystem"

    condition:

        uint16(0) == 0x5A4D
        and for any i in (0 .. pe.number_of_signatures - 1) : (
                pe.signatures[i].issuer contains "EM DV TLS CA - G3B" or
                for any j in (0 .. pe.signatures[i].number_of_certificates - 1) : (
                    pe.signatures[i].certificates[j].subject contains "EM DV TLS CA - G3B" and
                    pe.signatures[i].certificates[j].serial == "a4:ae:e6:78:f2:33:62:b4:c0:e4:60:b7:72:f2:14"
                )
        )

}

rule Compromised_certificate_8009928a64107601af05fa2f19f109 {

    meta:

        date = "2026-10-26"
        description = "Detects PE files signed under the compromised eMudhra TLS CA EM EV TLS CA - G3C, revoked after its weak private key was exposed. A TLS CA should never sign code, so any signed file is forged."
        author = "Binalyze DFIR Lab"
        reference = "https://blog.talosintelligence.com/compromised-intermediate-certificates/"
        verdict = "dangerous"
        mitre = "T1553.002"
        platform = "windows"
        search_context = "filesystem"

    condition:

        uint16(0) == 0x5A4D
        and for any i in (0 .. pe.number_of_signatures - 1) : (
                pe.signatures[i].issuer contains "EM EV TLS CA - G3C" or
                for any j in (0 .. pe.signatures[i].number_of_certificates - 1) : (
                    pe.signatures[i].certificates[j].subject contains "EM EV TLS CA - G3C" and
                    pe.signatures[i].certificates[j].serial == "80:09:92:8a:64:10:76:01:af:05:fa:2f:19:f1:09"
                )
        )

}

rule Compromised_certificate_296926c227a3a1526392b19482a504 {

    meta:

        date = "2026-10-26"
        description = "Detects PE files signed under the compromised eMudhra TLS CA EM OV TLS CA - G3C, revoked after its weak private key was exposed. A TLS CA should never sign code, so any signed file is forged."
        author = "Binalyze DFIR Lab"
        reference = "https://blog.talosintelligence.com/compromised-intermediate-certificates/"
        verdict = "dangerous"
        mitre = "T1553.002"
        platform = "windows"
        search_context = "filesystem"

    condition:

        uint16(0) == 0x5A4D
        and for any i in (0 .. pe.number_of_signatures - 1) : (
                pe.signatures[i].issuer contains "EM OV TLS CA - G3C" or
                for any j in (0 .. pe.signatures[i].number_of_certificates - 1) : (
                    pe.signatures[i].certificates[j].subject contains "EM OV TLS CA - G3C" and
                    pe.signatures[i].certificates[j].serial == "29:69:26:c2:27:a3:a1:52:63:92:b1:94:82:a5:04"
                )
        )

}

rule Compromised_certificate_588b2e3c2bb8cda13e1a1209254321 {

    meta:

        date = "2026-10-26"
        description = "Detects PE files signed under the compromised eMudhra TLS CA EM DV TLS CA - G3C, revoked after its weak private key was exposed. A TLS CA should never sign code, so any signed file is forged."
        author = "Binalyze DFIR Lab"
        reference = "https://blog.talosintelligence.com/compromised-intermediate-certificates/"
        verdict = "dangerous"
        mitre = "T1553.002"
        platform = "windows"
        search_context = "filesystem"

    condition:

        uint16(0) == 0x5A4D
        and for any i in (0 .. pe.number_of_signatures - 1) : (
                pe.signatures[i].issuer contains "EM DV TLS CA - G3C" or
                for any j in (0 .. pe.signatures[i].number_of_certificates - 1) : (
                    pe.signatures[i].certificates[j].subject contains "EM DV TLS CA - G3C" and
                    pe.signatures[i].certificates[j].serial == "58:8b:2e:3c:2b:b8:cd:a1:3e:1a:12:09:25:43:21"
                )
        )

}
