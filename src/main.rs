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
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let loader = Obfuscator::open(&args.input, &args.output);
    let mut obfuscator = loader.unwrap();

    match obfuscator.is_elf() {
        true => {
            println!("start obfuscating {}...", args.input);
            obfuscator.change_class();
            obfuscator.change_endian();
            obfuscator.null_sec_hdr();
            println!("obfuscation done!");
            Ok(())
        }
        false => {
            eprintln!("not a valid ELF file: {}", args.input);
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "not a valid ELF file",
            ));
        }
    }
}
