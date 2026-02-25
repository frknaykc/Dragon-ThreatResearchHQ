import "elf"

rule ELF_entrypoint_at_least_64_FF
{
    meta:
        description = "ELF file with only 0xFF at entry point - RTU firmware wiper"
        date = "2026-02-02"
        author = "Nicklas Keijser - Truesec"
        reference = "https://www.truesec.com/hub/blog/detecting-russian-threats-to-critical-energy-infrastructure"

    condition:
        uint32(0) == 0x464c457f and
        for all i in (0..63) :
            (uint8(elf.entry_point + i) == 0xFF)
}
