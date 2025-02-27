use anyhow::bail;
use anyhow::Result;
use clap::{Args, Parser, Subcommand};

pub mod perfetto;
pub mod symbolize;
mod cmds;

#[derive(Debug, Parser)]
struct Command {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Debug, Subcommand)]
enum SubCommand {
    #[clap(name = "profile")]
    ProfileSched(ProfileSchedOpts),
    #[clap(name = "describe")]
    Describe(DescribeOpts),
    #[clap(name = "system")]
    System(SystemOpts),
}

#[derive(Debug, Args)]
pub struct DescribeOpts {
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long)]
    pid: u32,
    #[arg(short, long)]
    raw_output: bool,
    #[arg(short, long, default_value = "0")]
    duration: u64,
    #[arg(short, long)]
    sw_event: bool,
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

#[derive(Debug, Args)]
pub struct SystemOpts {
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long, default_value = "0")]
    pid: u32,
    #[arg(short, long)]
    cgroup: Vec<String>,
    #[arg(short, long, default_value = "0")]
    duration: u64,
    #[arg(short, long)]
    no_stack_traces: bool,
    #[arg(short, long, default_value = "0")]
    ringbuf_size_mib: u32,
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
    let opts = Command::parse();
    bump_memlock_rlimit()?;

    match opts.subcmd {
        SubCommand::ProfileSched(opts) => cmds::profile::profile_sched(opts),
        SubCommand::Describe(opts) => cmds::describe::describe(opts),
        SubCommand::System(opts) => cmds::system::system(opts),
    }
}
