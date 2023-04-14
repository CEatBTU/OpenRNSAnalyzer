extern crate r2api;
extern crate r2pipe;
extern crate serde_json;
extern crate serde_yaml;

extern crate pest;
#[macro_use]
extern crate pest_derive;

extern crate tera;

extern crate num_bigint;
extern crate num_traits;

extern crate clap;

extern crate indicatif;

extern crate env_logger;
extern crate log;

#[macro_use]
extern crate serde_derive;

pub mod common;
pub mod dataflow;
pub mod esil;
pub mod esilnew;
pub mod r2contrib;
pub mod r2structs;
pub mod registers;
pub mod util;

use std::collections::{BTreeMap, HashMap};

use std::convert::TryInto;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::io::prelude::Read;
use std::iter::FromIterator;
use std::path::Path;
use std::time::Instant;

use clap::{App, Arg, SubCommand};
use common::Addr;
use indicatif::{ProgressBar, ProgressStyle};
use r2api::api_trait::R2Api;
use r2api::structs::LSymbolType;
use r2pipe::r2::R2;
use tera::Context;
use tera::Tera;

use log::{info, trace};

use dataflow::DataflowArch;
use r2contrib::{FunctionWithBBs, R2ApiContrib};
use util::find_path;

fn main() {
    let matches = App::new("open-rns-analyzer")
        .subcommand(SubCommand::with_name("print-regs"))
        .subcommand(SubCommand::with_name("dot-regs"))
        .subcommand(SubCommand::with_name("dot-bbs"))
        .subcommand(SubCommand::with_name("dot-minimal-bbs"))
        .subcommand(
            SubCommand::with_name("calculate-dataflow")
                .arg(
                    Arg::with_name("output-yaml")
                        .short("-y")
                        .long("--output-yaml"),
                )
                .arg(Arg::with_name("no-html").short("-d").long("--no-html"))
                .arg(
                    Arg::with_name("only")
                        .value_name("FUNCTION")
                        .short("-f")
                        .long("--only")
                        .multiple(true),
                )
                .arg(
                    Arg::with_name("key-indicators")
                        .short("-k")
                        .long("--key-indicators"),
                )
                .arg(
                    Arg::with_name("footer-file")
                        .value_name("FOOTER-FILE")
                        .short("-F")
                        .long("--footer-file"),
                )
                .arg(
                    Arg::with_name("no-ud-chains")
                        .short("-u")
                        .long("--no-ud-chains"),
                ),
        )
        .arg(
            Arg::with_name("input")
                .value_name("INPUT-FILE")
                .short("-i")
                .long("--input")
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .value_name("OUTPUT-DIR")
                .short("-o")
                .long("--output-dir")
                .default_value("."),
        )
        .arg(
            Arg::with_name("fixup-file")
                .value_name("FIXUP-FILE")
                .short("-f")
                .long("--fixup-file"),
        )
        .get_matches();

    env_logger::init();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"));

    let output_dir = Path::new(matches.value_of("output").unwrap());
    if !output_dir.is_dir() {
        fs::create_dir(output_dir)
            .expect(&format!("Could not create output dir: {:?}", output_dir)[..]);
    }

    let file = matches.value_of("input");
    let mut r2 = R2::new(file).unwrap();

    r2.init();
    // r2.analyze_and_autoname();
    // r2.analyze_all();

    let dfa = DataflowArch::new(&mut r2);

    if let Some(_) = matches.subcommand_matches("print-regs") {
        println!("{}", serde_yaml::to_string(&dfa.regs).unwrap());
        return;
    }

    if let Some(_) = matches.subcommand_matches("dot-regs") {
        println!("{}", &dfa.regs.output_dot());
        return;
    }

    let translation_table: Option<HashMap<Addr, Addr>>;
    if let Some(fu_file) = matches.value_of("fixup-file") {
        let fu_fh = File::open(fu_file);
        let fu_read = BufReader::new(fu_fh.expect("could not open fixup file"));

        translation_table = Some(
            fu_read
                .lines()
                .map(|x| {
                    let comp: Vec<String> = x
                        .expect("could not read from fixup file")
                        .split(" ")
                        .map(|y| y.to_string())
                        .collect();
                    (
                        Addr::from_str_radix(&comp[0], 16).unwrap(),
                        Addr::from_str_radix(&comp[1], 16).unwrap(),
                    )
                })
                .collect(),
        );
        trace!("Translation table: {:#x?}", translation_table);
    } else {
        translation_table = None
    }

    r2.symbols()
        .expect("Could not get symbols")
        .iter()
        .filter(|sym| -> bool {
            match sym.stype {
                Some(LSymbolType::Func) => true,
                Some(LSymbolType::Notype) => true,
                _ => false,
            }
        })
        .for_each(|i| -> () {
            let x = i.clone();
            info!("Found Symbol {:?}", x);
            if let Some(tt) = translation_table.clone() {
                if tt.contains_key(&x.vaddr.expect("Symbol without Vaddr")) {
                    r2.add_function(x.name.expect("Symbol without name"), tt[&x.vaddr.unwrap()]);
                } else {
                    r2.add_function(
                        x.name.expect("Symbol without name"),
                        x.vaddr.expect("Symbol without Vaddr"),
                    );
                }
            } else {
                r2.add_function(
                    x.name.expect("Symbol without name"),
                    x.vaddr.expect("Symbol without Vaddr"),
                );
            }
        });

    let funs: BTreeMap<String, FunctionWithBBs> =
        BTreeMap::from_iter(r2.fn_list().unwrap().into_iter().map(
            |function| -> (String, FunctionWithBBs) {
                let f = FunctionWithBBs::new(&mut r2, function);
                let name = f.function.name.as_ref().unwrap().clone();
                (name, f)
            },
        ));

    if let Some(_) = matches.subcommand_matches("dot-bbs") {
        for (name, fun) in funs {
            fs::write(output_dir.join(format!("{}.dot", name)), fun.dot_bbs())
                .expect("couldn't write file");
        }
        return;
    }

    if let Some(_) = matches.subcommand_matches("dot-min-bbs") {
        for (name, fun) in funs {
            fs::write(output_dir.join(format!("{}.dot", name)), fun.dot_bbs())
                .expect("couldn't write file");
        }
        return;
    }

    let footer;
    if let Some(footer_filename) = matches.value_of("footer-file") {
        let mut footer_file = File::open(footer_filename).expect("can't open footer file");
        let mut contents = String::new();
        footer_file.read_to_string(&mut contents).expect("can't read footer file");
        footer = Some(contents);
    } else {
        footer = None;
        
    }

    if let Some(matcher) = matches.subcommand_matches("calculate-dataflow") {
        #[derive(Serialize)]
        struct FunctionMeta {
            pub name: String,
            pub link: String,
            pub duration: String,
        }

        let mut meta = Vec::new();

        let total_funs = funs.len();

        let pb = ProgressBar::new(total_funs.try_into().unwrap());
        pb.set_style(ProgressStyle::default_bar()
                     .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                     .progress_chars("#>-"));

        let memory_map = r2.get_memory_map().unwrap();

        for (idx, (name, fun)) in funs.into_iter().enumerate() {
            let calculate = match matcher.value_of("only") {
                Some(fn_names) => fn_names.contains(&name),
                None => true,
            } && name.starts_with("x.");

            pb.set_message(&name);
            if calculate {
                let now = Instant::now();
                let dataflow = dfa.wl_algorithm(&fun);
                let duration = now.elapsed();

                if matcher.is_present("output-yaml") {
                    fs::write(
                        output_dir.join(format!("{}.df.yml", name)),
                        serde_yaml::to_string(&dataflow).unwrap(),
                    )
                    .expect("couldn't write file");
                }

                if !matcher.is_present("no-html") {
                    let filename = output_dir.join(format!("{}.df.html", name));

                    let conversions_origin = if !matcher.is_present("no-ud-chains") {
                        Some(dfa.backtrack(&fun, &dataflow))
                    } else {
                        None
                    };

                    let key_indicators = if matcher.is_present("key-indicators") {
                        Some(dfa.get_key_indicators(
                            &fun,
                            &dataflow,
                            conversions_origin.as_ref().unwrap(),
                        ))
                    } else {
                        None
                    };

                    fs::write(
                        &filename,
                        dfa.gen_cytoscape(
                            &fun,
                            &dataflow,
                            &file.unwrap().to_string(),
                            &memory_map,
                            conversions_origin,
                            key_indicators,
                            &footer
                        ),
                    )
                    .expect("couldn't write file");

                    meta.push(FunctionMeta {
                        name: name,
                        link: format!(
                            "{}",
                            filename
                                .file_name()
                                .clone()
                                .unwrap()
                                .to_str()
                                .as_ref()
                                .unwrap(),
                        ),
                        duration: format!("{:.2}ms", duration.as_millis()),
                    })
                }
            }
            pb.set_position(idx.try_into().unwrap());
        }

        if !matcher.is_present("no-html") {
            let template_path = find_path(
                "TEMPLATE_DIR".to_string(),
                "../../src/templates/".to_string(),
                "index.html".to_string(),
            )
            .expect("couldn't find template dir")
            .join("*");

            let tera = Tera::new(template_path.to_str().unwrap()).expect("cannot compile template");
            let mut ctx = Context::new();
            ctx.insert("functions", &meta);
            ctx.insert("name", &file.unwrap());

            if let Some(footer_content) = &footer {
                ctx.insert("footer", footer_content);
            } else {
                ctx.insert("footer", "");
            }

            fs::write(
                output_dir.join("index.html"),
                tera.render("index.html", &ctx).unwrap(),
            )
            .expect("couldn't write file");

            let js_deps_dir = find_path(
                "JS_DIR".to_string(),
                "../../js-deps/".to_string(),
                "cytoscape.js".to_string(),
            )
            .expect("couldn't find js-deps");
            fs::read_dir(&js_deps_dir)
                .expect("couldn't find js dependencies")
                .for_each(|i| {
                    let entry = i.unwrap().file_name();
                    fs::copy(js_deps_dir.join(&entry), output_dir.join(&entry))
                        .expect(format!("couldn't copy js dependency {:?}", entry).as_str());
                });
        }
    }
}
