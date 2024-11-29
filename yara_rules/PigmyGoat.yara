import "elf"

rule PigmyGoat_VMProtect_variant {

    meta:

        date = "2024-11-28"
        description = "Pygmy Goat is a native x86-32 ELF shared object that was discovered on Sophos XG firewall devices, providing backdoor access to the device."
        author = "Binalyze DFIR Lab"
        hash = "3f28196675dc8cb20cf5b5f80ea29310"
        reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/pygmy-goat/ncsc-mar-pygmy-goat.pdf"
        verdict = "dangerous"
        mitre = ""
        platform = "linux"
        search_context = "filesystem"

    condition:

        uint32(0) == 0x464C457F
        and for any i in (0 .. elf.number_of_sections): (
            elf.sections[i].name == ".sophos0"
        )

}