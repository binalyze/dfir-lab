rule PHP2Shell_Request_Driven_PHP_Webshell {

    meta:

        date            = "2026-10-22"
        author          = "Binalyze DFIR Lab"
        description     = "Hunts for PHP files that pass HTTP request input to code or command execution functions, a common webshell pattern. Use on web roots and upload directories of hosts exposed to PHP2Shell (CVE-2026-109618, CVE-2026-109619) to find attacker access that survives patching; matches require manual review."
        reference       = "https://binalyze.ai/blog/investigating-php2shell-after-patching/"
        hash            = ""
        verdict         = "suspicious"
        mitre           = "T1505.003"
        platform        = "linux, windows"
        search_context  = "filesystem"

    strings:

        // PHP open tag
        $php   = "<?" ascii

        // request-controlled input
        $input = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ ascii

        // code or command execution sinks
        $exec  = /\b(eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(/ ascii nocase

    condition:

        filesize < 5MB
        and $php and $input and $exec

}
