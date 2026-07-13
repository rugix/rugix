use std::time::Duration;

use rugix_tasks::check_canceled;
use rugix_tasks::shutdown_blocking;
use rugix_tasks::spawn;
use rugix_tasks::spawn_blocking;

/// Does some work indefinitely until the task is aborted.
pub fn work_indefinitely() {
    loop {
        check_canceled();
        eprintln!("doing some work...");
        std::thread::sleep(Duration::from_secs(10));
    }
}

pub fn main() {
    spawn_blocking(|| {
        spawn(async {
            // Let's race the indefinite blocking work against an asynchronous timeout.
            let blocking_task = spawn_blocking(work_indefinitely);
            tokio::select! {
                _ = blocking_task.join() => {
                    // This will never happen, because the work takes forever.
                    unreachable!("work done!")
                }
                _ = tokio::time::sleep(Duration::from_secs(15)) => {
                    eprintln!("timeout: aborting task");
                }
            }
        })
        .join_blocking();
        eprintln!("main task terminated, waiting on background tasks");
        // Dropping the runtime will wait for background tasks to finish.
        shutdown_blocking();
        eprintln!("all tasks have terminated");
    })
    .join_blocking();
}
