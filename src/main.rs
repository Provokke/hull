use hull::cli::{self, Command};
use hull::container;
use hull::image::{self, Store};
use hull::state::{self, Status};
use hull::util::{ago, format_size, now_secs, state_root};
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match cli::parse(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hull: {e}");
            exit(2);
        }
    };
    let root = state_root();
    let needs_root = !matches!(cmd, Command::Help);
    if needs_root && unsafe { libc::geteuid() } != 0 {
        eprintln!("hull: must be run as root");
        exit(1);
    }
    let res: Result<i32, String> = match cmd {
        Command::Help => {
            println!("{}", cli::USAGE);
            Ok(0)
        }
        Command::Run(o) => container::run(&root, &o),
        Command::Exec { id, cmd } => container::exec(&root, &id, &cmd),
        Command::Stop { id, timeout } => container::stop(&root, &id, timeout).map(|_| 0),
        Command::Rm { ids, force } => {
            let mut code = 0;
            for id in ids {
                match container::rm(&root, &id, force) {
                    Ok(full) => println!("{full}"),
                    Err(e) => {
                        eprintln!("hull: {e}");
                        code = 1;
                    }
                }
            }
            Ok(code)
        }
        Command::Logs { id } => state::resolve(&root, &id).and_then(|s| {
            let p = s.dir(&root).join("container.log");
            let data = std::fs::read(&p).unwrap_or_default();
            use std::io::Write;
            std::io::stdout()
                .write_all(&data)
                .map_err(|e| e.to_string())?;
            Ok(0)
        }),
        Command::Inspect { id } => state::resolve(&root, &id).map(|s| {
            println!("{}", serde_json::to_string_pretty(&s).unwrap());
            0
        }),
        Command::Ps { all } => {
            let now = now_secs();
            println!(
                "{:<12}  {:<10}  {:<24}  {:<10}  {:<12}  {:<8}  NAME",
                "CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "PID"
            );
            for s in state::list(&root) {
                let running = s.status == Status::Running;
                if !all && !running {
                    continue;
                }
                let mut c = s.cmd.join(" ");
                if c.len() > 24 {
                    c.truncate(21);
                    c.push_str("...");
                }
                println!(
                    "{:<12}  {:<10}  {:<24}  {:<10}  {:<12}  {:<8}  {}",
                    s.id,
                    s.image,
                    c,
                    ago(s.created_at, now),
                    s.display_status(),
                    s.pid
                        .filter(|_| running)
                        .map(|p| p.to_string())
                        .unwrap_or_default(),
                    s.name.unwrap_or_default()
                );
            }
            Ok(0)
        }
        Command::Images => {
            let store = Store::new(&root);
            println!("{:<16}  {:<19}  {:>8}  SOURCE", "NAME", "DIGEST", "SIZE");
            for (n, m) in store.list() {
                println!(
                    "{:<16}  {:<19}  {:>8}  {}",
                    n,
                    &m.digest[..19],
                    format_size(m.size),
                    m.source
                );
            }
            Ok(0)
        }
        Command::Pull { name, busybox_only } => {
            let store = Store::new(&root);
            image::pull(&store, &name, busybox_only, &root.join("tmp")).map(|d| {
                println!("{name} {d}");
                0
            })
        }
        Command::Import { path, name } => {
            let store = Store::new(&root);
            let name = name.unwrap_or_else(|| {
                let f = std::path::Path::new(&path)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| "image".into());
                f.split('.').next().unwrap_or("image").to_string()
            });
            store
                .import(
                    std::path::Path::new(&path),
                    &name,
                    &format!("import:{path}"),
                )
                .map(|d| {
                    println!("{name} {d}");
                    0
                })
                .map_err(|e| e.to_string())
        }
    };
    match res {
        Ok(c) => exit(c),
        Err(e) => {
            eprintln!("hull: {e}");
            exit(125);
        }
    }
}
