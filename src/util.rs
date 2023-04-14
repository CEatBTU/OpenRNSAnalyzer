use std::env;
use std::path::Path;

pub fn find_path(env_var: String, bin_rel_path: String, test_file: String) -> Result<Box<Path>, ()> {

    let complete_path: Box<Path> = match env::var(env_var) {
        Ok(var) => Path::new(var.as_str()).into(),
        Err(_)  => Path::new(env::current_exe().expect("cannot find current exe").parent().unwrap()).join(bin_rel_path).into_boxed_path()
    };
    if !complete_path.join(test_file).exists() {
        Err(())
    } else {
        Ok(complete_path)
    }
}
