rule JetBrains_CVE_2024_27198_CVE_2024_27199 {

    meta:

        date = "2024-03-05"
        description = "Identifies exploitation attempts related to JetBrains TeamCity Multiple Authentication Bypass Vulnerabilities CVE-2024-27198 and CVE-2024-27199."
        author = "Ahmet Payaslioglu - Binalyze DFIR Lab"
        reference = "https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/"
        verdict = "suspicious"
        mitre = "T1190"
        platform = "windows, linux"
        search_context = "filesystem"

    strings:

        $a1 = /;\S*\.jsp\?\S*jsp=/ ascii

    condition:

        $a1

}
