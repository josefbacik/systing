use perfetto_protos::process_tree::process_tree::Process;
use regex::Regex;

pub fn profetto_fill_process(process: &mut Process) {
    let pid = process.pid();
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid));
    if status.is_err() {
        return;
    }

    let r = Regex::new(r"PPid:\s+(\d+)").unwrap();
    for line in status.unwrap().lines() {
        if let Some(captures) = r.captures(line) {
            let ppid = captures.get(1).unwrap().as_str().parse::<i32>().unwrap();
            process.set_ppid(ppid);
            break;
        }
    }
}
