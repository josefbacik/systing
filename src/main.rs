use anyhow::bail;
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::FmtSubscriber;

mod cmds;

#[derive(Debug, Parser)]
struct Command {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Debug, Subcommand)]
enum SubCommand {
    #[clap(name = "profile-sched")]
    ProfileSched(ProfileSchedOpts),
    #[clap(name = "describe")]
    Describe(DescribeOpts),
}

#[derive(Debug, Args)]
pub struct DescribeOpts {
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long)]
    pid: u32,
}

#[derive(Debug, Args)]
pub struct ProfileSchedOpts {
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long, default_value = "0")]
    pid: u32,
    #[arg(short, long)]
    cgroup: Vec<String>,
    #[arg(short, long)]
    summary: bool,
    #[arg(short, long)]
    tui: bool,
    #[arg(short, long, default_value = "0")]
    duration: u64,
    #[arg(short, long, default_value = "1")]
    loops: u64,
    #[arg(short, long)]
    aggregate: bool,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}


fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(LevelFilter::TRACE)
        .with_timer(SystemTime)
        .finish();
    set_global_subscriber(subscriber).expect("Failed to set tracing subscriber");

    let opts = Command::parse();
    bump_memlock_rlimit()?;

    match opts.subcmd {
        SubCommand::ProfileSched(opts) => cmds::profile::profile_sched(opts),
        SubCommand::Describe(opts) => cmds::describe::describe(opts),
    }
}
