use clap::Parser;
use obfus::Obfuscator;
use std::io::Error;

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
