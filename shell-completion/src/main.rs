use clap::Parser;

mod options {
    include!("../../src/options.rs");
}

mod listen {
    include!("../../src/listen/options.rs");
}

mod search {
    include!("../../src/search/options.rs");
}

mod show {
    include!("../../src/show/options.rs");
}

#[derive(Debug, Parser)]
struct ShellCompletionOptions {
    shell: clap_complete::Shell
}

fn main() {
    use std::io;
    use clap::CommandFactory;
    
    let options = ShellCompletionOptions::parse();
    let mut cmd = options::Options::command();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    
    clap_complete::generate(options.shell, &mut cmd, "fi", &mut stdout);
}
