use std::io::Result;
use std::path::Path;

use asn1rs::converter::Converter;
use asn1rs::gen::rust::RustCodeGenerator;

fn load_files(
    dir: &Path,
    converter: &mut Converter
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            load_files(&path, converter)?;
        } else {
            match path.as_os_str().to_os_string().into_string() {
                Ok(path) if path.ends_with(".asn1") => {
                    println!("cargo:rerun-if-changed={}", &path);

                    if let Err(e) = converter.load_file(&path) {
                        panic!("Couldn't load {}: {:?}", &path, e);
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

pub fn main() {
    let mut converter = Converter::default();

    load_files(Path::new("./src/asn1"), &mut converter)
        .expect("Error loading ASN.1 files");

    let generated = Path::new("src/generated");

    if !generated.is_dir() {
        std::fs::create_dir(generated).expect("Could not create directory");
    }

    if let Err(e) =
        converter.to_rust(generated, |gen: &mut RustCodeGenerator| {
            gen.add_global_derive("serde::Deserialize");
            gen.add_global_derive("serde::Serialize");
        })
    {
        panic!("Error generating rust: {:?}", e);
    }
}
