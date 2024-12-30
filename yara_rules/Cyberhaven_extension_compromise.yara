rule Cyberhaven_compromise_extension_pattern {

    meta:

        date = "2024-12-30"
        description = "Detects suspicious messages seen in compromised extensions as part of wider campaign targetting Chrome extensions."
        author = "SecureAnnex, Binalyze DFIR Lab"
        hash = "1f5675c4fd1265ef85cd80ef3f75a7c0"
        reference = "https://secureannex.com/blog/cyberhaven-extension-compromise/"
        reference = "https://www.cyberhaven.com/blog/cyberhavens-chrome-extension-security-incident-and-what-were-doing-about-it"
        verdict = "dangerous"
        mitre = "T1176, T1539, T1649"
        platform = "windows"
        search_context = "filesystem"

    strings:

        $msg1 = "action:" wide ascii

        $rtext1 = "-rtext" nocase wide ascii
        $rtext2 = "_rtext" nocase wide ascii

        $rjson1 = "-rjson" nocase wide ascii
        $rjson2 = "_rjson" nocase wide ascii

        $errors1 = "-check-errors" nocase wide ascii
        $errors2 = "_check-errors" nocase wide ascii

        $listener1 = "-completions" nocase wide ascii
        $listener2 = "-redirect" nocase wide ascii
        $listener3 = "-validate" nocase wide ascii

    condition:

        filesize < 1MB and ($msg1 or 2 of ($listener*)) and
        any of ($rtext*) and any of ($rjson*) and any of ($errors*)

}