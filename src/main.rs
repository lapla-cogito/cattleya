mod obfus;

#[derive(clap::Parser, Debug)]
#[command(
    author = "lapla",
    about = "A CLI application to obfuscate a ELF file",
    version = "v0.1.0"
)]
struct Args {
    #[arg(short, long, help = "input file name")]
    input: String,
    #[arg(short, long, help = "output file name", default_value = "obfuscated")]
    output: String,
    #[arg(
        short,
        long,
        help = "change architecture class in the ELF",
        default_value = "false"
    )]
    class: bool,
    #[arg(
        short,
        long,
        help = "change endian in the ELF",
        default_value = "false"
    )]
    endian: bool,
    #[arg(
        short,
        long,
        help = "nullify section header in the ELF",
        default_value = "false"
    )]
    sechdr: bool,
    #[arg(long, help = "nullify symbols in the ELF", default_value = "false")]
    symbol: bool,
    #[arg(
        long,
        help = "nullify comment section in the ELF",
        default_value = "false"
    )]
    comment: bool,
    #[arg(long, help = "nullify section in the ELF", default_value = "")]
    section: String,
}

fn main() -> std::io::Result<()> {
    use clap::Parser;
    let args = Args::parse();
    let loader = obfus::Obfuscator::open(&args.input, &args.output);
    let mut obfuscator = loader.unwrap();

    match obfuscator.is_elf() && obfuscator.is_64bit() {
        true => {
            println!("start obfuscating {}...", args.input);

            if args.class {
                obfuscator.change_class();
            }
            if args.endian {
                obfuscator.change_endian();
            }
            if args.sechdr {
                obfuscator.nullify_sec_hdr();
            }
            if args.symbol {
                obfuscator.nullify_section(".strtab");
            }
            if args.comment {
                obfuscator.nullify_section(".comment");
            }
            if !args.section.is_empty() {
                obfuscator.nullify_section(&args.section);
            }

            println!("obfuscation done!");
            Ok(())
        }
        false => {
            panic!("not a valid ELF file: {}", args.input);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::obfus::{self, Obfuscator};
    use memmap2::Mmap;
    use std::process::Command;

    #[test]
    fn not_elf() {
        let file = std::fs::File::open("src/main.rs").unwrap();
        assert!(unsafe { Mmap::map(&file).unwrap()[0..4] != obfus::HEADER_MAGIC });
    }

    #[test]
    fn change_class_64bit() {
        let loader = Obfuscator::open("bin/test_64bit", "bin/res_64bit");
        let mut obfuscator = loader.unwrap();
        assert_eq!(obfuscator.output[4], 2);
        obfuscator.change_class();
        assert_eq!(obfuscator.output[4], 1);
    }

    #[test]
    fn change_endian() {
        let loader = Obfuscator::open("bin/test_64bit", "bin/res_endian");
        let mut obfuscator = loader.unwrap();
        assert_eq!(obfuscator.output[5], 1);
        obfuscator.change_endian();
        assert_eq!(obfuscator.output[5], 2);
    }

    #[test]
    fn null_sec_hdr() {
        let loader = Obfuscator::open("bin/test_64bit", "bin/res_sechdr");
        let mut obfuscator = loader.unwrap();
        obfuscator.nullify_sec_hdr();
        let output = Command::new("readelf")
            .args(["-S", "bin/res_sechdr"])
            .output()
            .expect("failed to execute readelf");

        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "readelf: Error: no .dynamic section in the dynamic segment\n"
        );
    }

    #[test]
    fn null_symbol_name() {
        let loader = Obfuscator::open("bin/test_64bit", "bin/res_symbol");
        let mut obfuscator = loader.unwrap();
        obfuscator.nullify_section(".strtab");
        let output = Command::new("readelf")
            .args(["-x29", "bin/res_symbol"])
            .output()
            .expect("failed to execute readelf");

        assert_eq!(
            String::from_utf8(output.stdout)
                .unwrap()
                .trim()
                .split('\n')
                .collect::<Vec<&str>>()[1],
            "  0x00000000 00000000 00000000 00000000 00000000 ................"
        );
    }

    #[test]
    fn null_comment() {
        let loader = Obfuscator::open("bin/test_64bit", "bin/res_comment");
        let mut obfuscator = loader.unwrap();
        obfuscator.nullify_section(".comment");
        let output = Command::new("readelf")
            .args(["-x27", "bin/res_comment"])
            .output()
            .expect("failed to execute readelf");

        assert_eq!(
            String::from_utf8(output.stdout)
                .unwrap()
                .trim()
                .split('\n')
                .collect::<Vec<&str>>()[1],
            "  0x00000000 00000000 00000000 00000000 00000000 ................"
        );
    }
}
