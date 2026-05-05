mod dwarf;
mod error;
mod obfus;
mod util;

pub use error::{Error, Result};

#[derive(clap::Parser, Debug)]
#[command(
    author = "lapla",
    about = "A CLI application to obfuscate ELF file(s)",
    version = "v0.1.0"
)]
struct Args {
    #[arg(short, long, help = "input file name", default_value = "")]
    input: String,
    #[arg(short, long, help = "output file name", default_value = "")]
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
    #[arg(short, long, help = "recursive", default_value = "")]
    recursive: String,
    #[arg(short, long, help = "perform GOT overwrite", default_value = "false")]
    got: bool,
    #[arg(
        long,
        help = "GOT overwrite target library function name",
        default_value = ""
    )]
    got_l: String,
    #[arg(long, help = "GOT overwrite target function name", default_value = "")]
    got_f: String,
    #[arg(
        long,
        help = "encrypt function name with the given key",
        default_value = "false"
    )]
    encrypt: bool,
    #[arg(long, help = "encryption target function name", default_value = "")]
    encrypt_f: String,
    #[arg(long, help = "encryption key", default_value = "")]
    encrypt_key: String,
    #[arg(
        long,
        help = "swap two symbol names in the .symtab",
        default_value = "false"
    )]
    swap_symbol: bool,
    #[arg(long, help = "first symbol name to swap", default_value = "")]
    swap_symbol_a: String,
    #[arg(long, help = "second symbol name to swap", default_value = "")]
    swap_symbol_b: String,
}

fn main() -> Result<()> {
    use clap::Parser as _;
    let args = Args::parse();

    if args.recursive.is_empty() {
        if args.input.is_empty() {
            return Err(Error::InvalidOption("input file name is required"));
        }

        let output_path = if !args.output.is_empty() {
            &args.output
        } else {
            "obfuscated"
        };

        exec_obfus(&args.input, output_path, &args).unwrap();
    } else {
        if !args.input.is_empty() {
            return Err(Error::InvalidOption(
                "both input file name and recursive option are not allowed",
            ));
        }
        if !args.output.is_empty() {
            eprintln!("output file name will be ignored");
        }

        let entries = util::RecursiveDir::new(&args.recursive)
            .unwrap()
            .filter_map(|e| Some(e.ok()?.path()))
            .collect::<Vec<_>>();

        for entry in entries.iter() {
            let output_path = format!("obfuscated_dir/{}", entry.to_str().unwrap());
            let dir = output_path.rsplitn(2, '/').collect::<Vec<&str>>()[1];

            std::fs::create_dir_all(dir).unwrap();
            std::fs::File::create(&output_path).unwrap();

            match exec_obfus(entry.to_str().unwrap(), &output_path, &args) {
                Ok(_) => println!("obfuscation done!"),
                Err(e) => {
                    eprintln!("error while obfuscation of {output_path}: {e}");
                    std::fs::remove_file(&output_path).unwrap();
                    continue;
                }
            }
        }
    }

    Ok(())
}

fn exec_obfus(input_path: &str, output_path: &str, args: &Args) -> Result<()> {
    let loader = obfus::Obfuscator::open(input_path, output_path);
    let mut obfuscator = loader?;

    println!("start obfuscating {input_path}...");

    if args.class {
        match obfuscator.change_class() {
            Ok(_) => println!("change class metadata success"),
            Err(e) => eprintln!("failed to change class metadata: {e:?}"),
        }
    }
    if args.endian {
        match obfuscator.change_endian() {
            Ok(_) => println!("change endian metadata success"),
            Err(e) => eprintln!("failed to change class metadata: {e:?}"),
        }
    }
    if args.sechdr {
        match obfuscator.nullify_sec_hdr() {
            Ok(_) => println!("nullify section headers success"),
            Err(e) => eprintln!("failed to nullify section header: {e:?}"),
        }
    }
    if args.symbol {
        match obfuscator.nullify_section(".strtab") {
            Ok(_) => println!("nullify symbol table success"),
            Err(e) => eprintln!("failed to nullify symbol table: {e:?}"),
        }
    }
    if args.comment {
        match obfuscator.nullify_section(".comment") {
            Ok(_) => println!("nullify comment section success"),
            Err(e) => eprintln!("failed to nullify comment section: {e:?}"),
        }
    }
    if !args.section.is_empty() {
        match obfuscator.nullify_section(&args.section) {
            Ok(_) => println!("nullify section {:?} success", &args.section),
            Err(e) => eprintln!("failed to nullify section: {e:?}"),
        }
    }
    if args.got {
        if args.got_l.is_empty() || args.got_f.is_empty() {
            return Err(Error::InvalidOption(
                "both library and function names are required",
            ));
        }

        match obfuscator.got_overwrite(&args.got_l, &args.got_f) {
            Ok(_) => println!("GOT overwrite success"),
            Err(e) => eprintln!("failed to GOT overwrite: {e:?}"),
        }
    }
    if args.swap_symbol {
        if args.swap_symbol_a.is_empty() || args.swap_symbol_b.is_empty() {
            return Err(Error::InvalidOption(
                "two symbol names are required for swap-symbol",
            ));
        }

        match obfuscator.swap_symbol_names(&args.swap_symbol_a, &args.swap_symbol_b) {
            Ok(_) => println!(
                "swap symbol names {:?} <-> {:?} success",
                &args.swap_symbol_a, &args.swap_symbol_b
            ),
            Err(e) => eprintln!("failed to swap symbol names: {e:?}"),
        }
    }
    if args.encrypt {
        if args.encrypt_f.is_empty() || args.encrypt_key.is_empty() {
            return Err(Error::InvalidOption(
                "target function name and encryption key is required",
            ));
        }

        match obfuscator.encrypt_function_name(&args.encrypt_f, &args.encrypt_key) {
            Ok(_) => println!("encrypt function name success"),
            Err(e) => eprintln!("failed to encrypt function name: {e:?}"),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn not_elf() {
        let loader = crate::obfus::Obfuscator::open("src/main.rs", "foo");
        assert!(matches!(loader, Err(crate::Error::InvalidMagic)));
    }

    #[test]
    fn change_class_64bit() {
        let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_class");
        let mut obfuscator = loader.unwrap();
        assert_eq!(obfuscator.output[4], 2);
        obfuscator.change_class().unwrap();
        assert_eq!(obfuscator.output[4], 1);
    }

    #[test]
    fn change_endian() {
        let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_endian");
        let mut obfuscator = loader.unwrap();
        assert_eq!(obfuscator.output[5], 1);
        obfuscator.change_endian().unwrap();
        assert_eq!(obfuscator.output[5], 2);
    }

    #[test]
    fn null_sec_hdr() {
        let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_sechdr");
        let mut obfuscator = loader.unwrap();
        obfuscator.nullify_sec_hdr().unwrap();
        let output = std::process::Command::new("readelf")
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
        let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_symbol");
        let mut obfuscator = loader.unwrap();
        obfuscator.nullify_section(".strtab").unwrap();
        let output = std::process::Command::new("readelf")
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
        let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_comment");
        let mut obfuscator = loader.unwrap();
        obfuscator.nullify_section(".comment").unwrap();
        let output = std::process::Command::new("readelf")
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

    #[test]
    fn recursive_option() {
        std::process::Command::new("cargo")
            .args(["run", "--", "-r", "bin/recursive", "--symbol"])
            .output()
            .expect("failed to execute cargo");

        let entries = crate::util::RecursiveDir::new("obfuscated_dir/bin/recursive")
            .unwrap()
            .filter_map(|e| Some(e.ok()?.path()))
            .collect::<Vec<_>>();

        for entry in entries.iter() {
            let output = std::process::Command::new("readelf")
                .args(["-x29", entry.to_str().unwrap()])
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

    #[test]
    fn got_overwrite() {
        {
            let loader = crate::obfus::Obfuscator::open("bin/got", "bin/res_got");
            let mut obfuscator = loader.unwrap();
            obfuscator.got_overwrite("system", "secret").unwrap();
        }
        {
            let metadata = std::fs::metadata("bin/res_got").unwrap();
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions("bin/res_got", permissions).unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        let output = std::process::Command::new("./bin/res_got")
            .output()
            .expect("failed to execute res_got");

        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "secret function called\n"
        );
    }

    #[test]
    fn encrypt_function_name() {
        {
            let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_encrypt");
            let mut obfuscator = loader.unwrap();
            obfuscator.encrypt_function_name("fac", "foo").unwrap();
        }

        let output = std::process::Command::new("nm")
            .args(["bin/test_64bit"])
            .output()
            .expect("failed to execute nm");
        assert!(output.stdout.windows(3).any(|w| w == b"fac"));

        let output = std::process::Command::new("nm")
            .args(["bin/res_encrypt"])
            .output()
            .expect("failed to execute nm");
        assert!(!output.stdout.windows(3).any(|w| w == b"fac"));
    }

    #[test]
    fn swap_symbol_names() {
        let nm_orig = std::process::Command::new("nm")
            .args(["bin/test_64bit"])
            .output()
            .expect("failed to execute nm");
        let orig = String::from_utf8(nm_orig.stdout).unwrap();
        let orig_fac_addr = orig
            .lines()
            .find(|l| l.ends_with(" T fac"))
            .map(|l| l.split_whitespace().next().unwrap().to_string())
            .expect("fac symbol expected in baseline");
        let orig_fib_addr = orig
            .lines()
            .find(|l| l.ends_with(" T fib"))
            .map(|l| l.split_whitespace().next().unwrap().to_string())
            .expect("fib symbol expected in baseline");
        assert_ne!(orig_fac_addr, orig_fib_addr);

        {
            let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_swap_symbol");
            let mut obfuscator = loader.unwrap();
            obfuscator.swap_symbol_names("fac", "fib").unwrap();
        }

        // After swapping, `nm` must still print both names exactly once, but the addresses associated with them must be flipped.
        let nm_swapped = std::process::Command::new("nm")
            .args(["bin/res_swap_symbol"])
            .output()
            .expect("failed to execute nm");
        let swapped = String::from_utf8(nm_swapped.stdout).unwrap();

        let new_fac_addr = swapped
            .lines()
            .find(|l| l.ends_with(" T fac"))
            .map(|l| l.split_whitespace().next().unwrap().to_string())
            .expect("fac symbol expected after swap");
        let new_fib_addr = swapped
            .lines()
            .find(|l| l.ends_with(" T fib"))
            .map(|l| l.split_whitespace().next().unwrap().to_string())
            .expect("fib symbol expected after swap");

        assert_eq!(new_fac_addr, orig_fib_addr);
        assert_eq!(new_fib_addr, orig_fac_addr);
    }

    #[test]
    fn swap_symbol_names_unknown() {
        let loader =
            crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_swap_symbol_unknown");
        let mut obfuscator = loader.unwrap();
        let result = obfuscator.swap_symbol_names("fac", "this_symbol_does_not_exist");
        assert!(matches!(result, Err(crate::Error::NotFound(_))));
    }

    #[test]
    fn swap_symbol_names_same() {
        let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_swap_symbol_same");
        let mut obfuscator = loader.unwrap();
        let result = obfuscator.swap_symbol_names("fac", "fac");
        assert!(matches!(result, Err(crate::Error::InvalidOption(_))));
    }

    /// Building a fresh `-g` binary and checking that `addr2line` (which reads
    /// DWARF, not `.symtab`) reports the *swapped* names too. This verifies
    /// that the in-place swap of inline `DW_FORM_string` bytes inside
    /// `.debug_info` keeps symbol-table and DWARF views consistent.
    #[test]
    fn swap_symbol_names_dwarf_consistency() {
        if std::process::Command::new("gcc")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: gcc not available");
            return;
        }
        if std::process::Command::new("addr2line")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: addr2line not available");
            return;
        }

        let dbg_src = "bin/main.c";
        let dbg_bin = "bin/test_64bit_dbg";
        let out_bin = "bin/res_swap_symbol_dwarf";

        let status = std::process::Command::new("gcc")
            .args(["-g", "-no-pie", dbg_src, "-o", dbg_bin])
            .status()
            .expect("failed to invoke gcc");
        assert!(status.success(), "gcc failed to build {dbg_bin}");

        let sec = std::process::Command::new("readelf")
            .args(["-S", dbg_bin])
            .output()
            .expect("failed to execute readelf");
        let sec_out = String::from_utf8_lossy(&sec.stdout);
        assert!(
            sec_out.contains(".debug_info"),
            "baseline binary lacks .debug_info; toolchain may have stripped it"
        );

        {
            let loader = crate::obfus::Obfuscator::open(dbg_bin, out_bin);
            let mut obfuscator = loader.unwrap();
            obfuscator.swap_symbol_names("fac", "fib").unwrap();
        }

        let nm = std::process::Command::new("nm")
            .args([out_bin])
            .output()
            .expect("failed to execute nm");
        let nm_out = String::from_utf8(nm.stdout).unwrap();
        let addr_of = |name: &str| -> String {
            nm_out
                .lines()
                .find(|l| l.ends_with(&format!(" T {name}")))
                .map(|l| l.split_whitespace().next().unwrap().to_string())
                .unwrap_or_else(|| panic!("symbol {name} not found in nm output"))
        };
        let fac_addr = addr_of("fac");
        let fib_addr = addr_of("fib");

        let addr2line = |addr: &str| -> String {
            let out = std::process::Command::new("addr2line")
                .args(["-f", "-e", out_bin, addr])
                .output()
                .expect("failed to execute addr2line");
            String::from_utf8(out.stdout)
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .trim()
                .to_string()
        };

        assert_eq!(addr2line(&fac_addr), "fac");
        assert_eq!(addr2line(&fib_addr), "fib");
    }

    #[test]
    fn swap_symbol_names_dwarf_different_length() {
        if std::process::Command::new("gcc")
            .arg("--version")
            .output()
            .is_err()
            || std::process::Command::new("addr2line")
                .arg("--version")
                .output()
                .is_err()
        {
            eprintln!("skipping: gcc/addr2line not available");
            return;
        }

        let dbg_src = "bin/dwarf_diff_len.c";
        let dbg_bin = "bin/test_64bit_dbg_difflen";
        let out_bin = "bin/res_swap_symbol_difflen";

        let status = std::process::Command::new("gcc")
            .args(["-g", "-no-pie", dbg_src, "-o", dbg_bin])
            .status()
            .expect("failed to invoke gcc");
        assert!(status.success());

        {
            let loader = crate::obfus::Obfuscator::open(dbg_bin, out_bin);
            let mut obfuscator = loader.unwrap();
            obfuscator
                .swap_symbol_names("factorial_function", "fib")
                .unwrap();
        }

        let nm = std::process::Command::new("nm")
            .args([out_bin])
            .output()
            .expect("failed to execute nm");
        let nm_out = String::from_utf8(nm.stdout).unwrap();
        let addr_of = |name: &str| -> String {
            nm_out
                .lines()
                .find(|l| l.ends_with(&format!(" T {name}")))
                .map(|l| l.split_whitespace().next().unwrap().to_string())
                .unwrap_or_else(|| panic!("symbol {name} not found in nm output"))
        };
        let fac_addr = addr_of("factorial_function");
        let fib_addr = addr_of("fib");

        let addr2line = |addr: &str| -> String {
            let out = std::process::Command::new("addr2line")
                .args(["-f", "-e", out_bin, addr])
                .output()
                .expect("failed to execute addr2line");
            String::from_utf8(out.stdout)
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .trim()
                .to_string()
        };

        assert_eq!(addr2line(&fac_addr), "factorial_function");
        assert_eq!(addr2line(&fib_addr), "fib");
    }
}
