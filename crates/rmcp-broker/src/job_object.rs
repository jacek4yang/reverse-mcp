//! Job Object helpers (Windows): tree-bound kill for disposable workers.
//!
//! A disposable worker is assigned to a kill-on-close Job Object before it
//! can spawn anything, so terminating the job deterministically destroys the
//! worker AND anything it spawned (IDA/Hex-Rays helper processes). On
//! non-Windows these compile to process-group equivalents kept minimal for
//! now (the production path is Windows-first; issue #72 targets the same).

/// Assign a spawned child to a fresh kill-on-close Job Object. Returns the
/// raw job handle (owned; close via `terminate_job`), or None on non-Windows.
pub fn assign_child(child: &tokio::process::Child) -> Option<isize> {
    #[cfg(windows)]
    {
        let h = child.raw_handle()?;
        Some(crate::job_object::win::create_and_assign(h as isize))
    }
    #[cfg(not(windows))]
    {
        let _ = child;
        None
    }
}

/// Terminate everything in the job and close the handle. Idempotent.
pub fn terminate_job(job: isize) {
    #[cfg(windows)]
    {
        crate::job_object::win::terminate_and_close(job);
    }
    #[cfg(not(windows))]
    {
        let _ = job;
    }
}

#[cfg(windows)]
pub(crate) mod win {
    use std::ffi::c_void;

    #[allow(clippy::upper_case_acronyms)]
    type HANDLE = *mut c_void;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x100;
    // JobObjectExtendedLimitInformation = 9
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;

    #[repr(C)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[repr(C)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    unsafe extern "system" {
        fn CreateJobObjectW(attrs: *mut c_void, name: *const u16) -> HANDLE;
        fn SetInformationJobObject(
            job: HANDLE,
            cls: i32,
            info: *mut c_void,
            len: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: HANDLE, proc: HANDLE) -> i32;
        fn TerminateJobObject(job: HANDLE, exit_code: u32) -> i32;
        fn CloseHandle(h: HANDLE) -> i32;
    }

    /// Create a kill-on-close job with a hard memory ceiling (2 GiB: Hex-Rays
    /// region analysis on giant functions stays well below; runaway work dies
    /// instead of thrashing the machine) and put `proc_handle` in it.
    pub fn create_and_assign(proc_handle: isize) -> isize {
        unsafe {
            let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
            if job.is_null() {
                return 0;
            }
            let mut limits = JobObjectExtendedLimitInformation {
                basic_limit_information: JobObjectBasicLimitInformation {
                    per_process_user_time_limit: 0,
                    per_job_user_time_limit: 0,
                    limit_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                        | JOB_OBJECT_LIMIT_PROCESS_MEMORY,
                    minimum_working_set_size: 0,
                    maximum_working_set_size: 0,
                    active_process_limit: 0,
                    affinity: 0,
                    priority_class: 0,
                    process_memory_limit: 2 * 1024 * 1024 * 1024, // 2 GiB
                    job_memory_limit: 0,
                    peak_process_memory_used: 0,
                    peak_job_memory_used: 0,
                },
                io_info: IoCounters {
                    read_operation_count: 0,
                    write_operation_count: 0,
                    other_operation_count: 0,
                    read_transfer_count: 0,
                    write_transfer_count: 0,
                    other_transfer_count: 0,
                },
                process_memory_limit: 2 * 1024 * 1024 * 1024,
                job_memory_limit: 0,
                peak_process_memory_used: 0,
                peak_job_memory_used: 0,
            };
            SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                &mut limits as *mut _ as *mut c_void,
                std::mem::size_of::<JobObjectExtendedLimitInformation>() as u32,
            );
            AssignProcessToJobObject(job, proc_handle as HANDLE);
            job as isize
        }
    }

    pub fn terminate_and_close(job: isize) {
        unsafe {
            if job != 0 {
                TerminateJobObject(job as HANDLE, 1);
                CloseHandle(job as HANDLE);
            }
        }
    }
}
