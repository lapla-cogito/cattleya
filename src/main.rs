mod error;
mod obfus;
mod util;

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
}

fn main() -> crate::error::Result<()> {
    use clap::Parser as _;
    let args = Args::parse();

    if args.recursive.is_empty() {
        if args.input.is_empty() {
            return Err(crate::error::Error::InvalidOption(
                "input file name is required",
            ));
        }

        let output_path = if !args.output.is_empty() {
            &args.output
        } else {
            "obfuscated"
        };

        exec_obfus(&args.input, output_path, &args).unwrap();
    } else {
        if !args.input.is_empty() {
            return Err(crate::error::Error::InvalidOption(
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
                    eprintln!("error while obfuscation: {}", e);
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}

fn exec_obfus(input_path: &str, output_path: &str, args: &Args) -> crate::error::Result<()> {
    let loader = obfus::Obfuscator::open(input_path, output_path);
    let mut obfuscator = loader.unwrap();

    match obfuscator.is_elf() {
        true => {
            println!("start obfuscating {}...", input_path);

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
                obfuscator.nullify_section(".strtab")?;
            }
            if args.comment {
                obfuscator.nullify_section(".comment")?;
            }
            if !args.section.is_empty() {
                obfuscator.nullify_section(&args.section)?;
            }
            if args.got {
                if args.got_l.is_empty() || args.got_f.is_empty() {
                    return Err(crate::error::Error::InvalidOption(
                        "both library and function names are required",
                    ));
                }

                obfuscator.got_overwrite(&args.got_l, &args.got_f)?;
            }
            if args.encrypt {
                if args.encrypt_f.is_empty() || args.encrypt_key.is_empty() {
                    return Err(crate::error::Error::InvalidOption(
                        "target function name and encryption key is required",
                    ));
                }

                obfuscator.encrypt_function_name(&args.encrypt_f, &args.encrypt_key)?;
            }

            Ok(())
        }
        false => Err(crate::error::Error::InvalidMagic),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn not_elf() {
        let file = std::fs::File::open("src/main.rs").unwrap();
        assert!(unsafe { memmap2::Mmap::map(&file).unwrap()[0..4] != crate::obfus::HEADER_MAGIC });
    }

    #[test]
    fn change_class_64bit() {
        let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_64bit");
        let mut obfuscator = loader.unwrap();
        assert_eq!(obfuscator.output[4], 2);
        obfuscator.change_class();
        assert_eq!(obfuscator.output[4], 1);
    }

    #[test]
    fn change_endian() {
        let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_endian");
        let mut obfuscator = loader.unwrap();
        assert_eq!(obfuscator.output[5], 1);
        obfuscator.change_endian();
        assert_eq!(obfuscator.output[5], 2);
    }

    #[test]
    fn null_sec_hdr() {
        let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_sechdr");
        let mut obfuscator = loader.unwrap();
        obfuscator.nullify_sec_hdr();
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
        let loader = crate::obfus::Obfuscator::open("bin/test_64bit", "bin/res_encrypt");
        let mut obfuscator = loader.unwrap();
        obfuscator.encrypt_function_name("fac", "foo").unwrap();

        let output = std::process::Command::new("readelf")
            .args(["-s", "bin/test_64bit"])
            .output()
            .expect("failed to execute readelf");
        assert!(String::from_utf8(output.stdout).is_ok());

        let output = std::process::Command::new("readelf")
            .args(["-s", "bin/res_encrypt"])
            .output()
            .expect("failed to execute readelf");
        assert!(String::from_utf8(output.stdout).is_err());
    }
}
