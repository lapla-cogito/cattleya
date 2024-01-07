use clap::Parser;
use obfus::Obfuscator;

mod obfus;

#[derive(Parser, Debug)]
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
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let loader = Obfuscator::open(&args.input, &args.output);
    let mut obfuscator = loader.unwrap();

    match obfuscator.is_elf() {
        true => {
            println!("start obfuscating {}...", args.input);

            if args.class == true {
                obfuscator.change_class();
            }
            if args.endian == true {
                obfuscator.change_endian();
            }
            if args.sechdr == true {
                obfuscator.null_sec_hdr();
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
    use crate::obfus::Obfuscator;
    use std::process::Command;

    #[test]
    fn not_elf() {
        let loader = Obfuscator::open("src/main.rs", "bin/res_not_elf");
        let obfuscator = loader.unwrap();
        assert_eq!(obfuscator.is_elf(), false);
    }

    #[test]
    fn change_class_64bit() {
        let loader = Obfuscator::open("bin/test_64bit", "bin/res_64bit");
        let mut obfuscator = loader.unwrap();
        obfuscator.change_class();
        assert_eq!(obfuscator.output[4], 1);
    }

    #[test]
    fn change_class_32bit() {
        let loader = Obfuscator::open("bin/test_32bit", "bin/res_32bit");
        let mut obfuscator = loader.unwrap();
        obfuscator.change_class();
        assert_eq!(obfuscator.output[4], 2);
    }

    #[test]
    fn change_endian() {
        let loader = Obfuscator::open("bin/test_64bit", "bin/res_endian");
        let mut obfuscator = loader.unwrap();
        obfuscator.change_endian();
        assert_eq!(obfuscator.output[5], 2);
    }

    #[test]
    fn null_sec_hdr() {
        let loader = Obfuscator::open("bin/test_64bit", "bin/res_sechdr");
        let mut obfuscator = loader.unwrap();
        obfuscator.null_sec_hdr();
        let output = Command::new("readelf")
            .args(["-S", "bin/res_sechdr"])
            .output()
            .expect("failed to execute readelf");

        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "readelf: Error: no .dynamic section in the dynamic segment\n"
        );
    }
}
