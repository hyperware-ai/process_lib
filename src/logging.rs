use crate::{
    print_to_terminal,
    vfs::{create_drive, open_file, File},
    Address, Request,
};
pub use tracing::{debug, error, info, warn, Level};
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    fmt, layer::SubscriberExt, prelude::*, util::SubscriberInitExt, EnvFilter,
};

pub struct RemoteLogSettings {
    pub target: Address,
    pub level: Level,
}

pub struct RemoteWriter {
    pub target: Address,
}

pub struct RemoteWriterMaker {
    pub target: Address,
}

pub struct FileWriter {
    pub file: File,
    pub max_size: u64,
}

pub struct FileWriterMaker {
    pub file: File,
    pub max_size: u64,
}

pub struct TerminalWriter {
    pub level: u8,
}

pub struct TerminalWriterMaker {
    pub level: u8,
}

impl std::io::Write for RemoteWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let log = if let Ok(json_log) = serde_json::from_slice::<serde_json::Value>(buf) {
            serde_json::to_string(&json_log).unwrap()
        } else {
            let string = String::from_utf8(buf.to_vec())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            string
        };
        let body = serde_json::json!({"Log": log});
        let body = serde_json::to_vec(&body).unwrap();
        Request::to(&self.target).body(body).send().unwrap();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RemoteWriterMaker {
    type Writer = RemoteWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RemoteWriter {
            target: self.target.clone(),
        }
    }
}

impl std::io::Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // TODO: use non-blocking call instead? (.append() `send_and_await()`s)
        let metadata = self
            .file
            .metadata()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if metadata.len > self.max_size {
            // Get current contents
            let contents = self
                .file
                .read()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            // Take second half of file
            let half_len = contents.len() / 2;
            let new_contents = &contents[half_len..];

            // Truncate and write back second half
            self.file
                .write(new_contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }

        self.file
            .append(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FileWriterMaker {
    type Writer = FileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        FileWriter {
            file: File::new(self.file.path.clone(), self.file.timeout),
            max_size: self.max_size,
        }
    }
}

impl std::io::Write for TerminalWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let string = String::from_utf8(buf.to_vec())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        print_to_terminal(self.level, &format!("{string}"));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TerminalWriterMaker {
    type Writer = TerminalWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TerminalWriter { level: self.level }
    }
}

/// Initialize [`tracing`](https://docs.rs/tracing)-based logging for the given process at the given level.
///
/// To write to logs, import the re-exported [`debug!()`], [`info!()`],
/// [`warn!()`], [`error!()`] macros and use as usual.
/// Logs will be printed to terminal as appropriate depending on given level.
/// Logs will be logged into the logging file as appropriate depending on the given level.
///
/// If `max_log_file_size` is provided, the log file will be rotated when it reaches
/// the given size. The default size is 1MB.
///
/// The logging file lives in the node's `vfs/` directory, specifically at
/// `node/vfs/package:publisher.os/log/process.log`, where `node` is your node's home
/// directory, `package` is the package name, `publisher.os` is the publisher of the
/// package, and `process` is the process name of the process doing the logging.
pub fn init_logging(
    file_level: Level,
    terminal_level: Level,
    remote: Option<RemoteLogSettings>,
    terminal_levels_mapping: Option<(u8, u8, u8, u8)>,
    max_log_file_size: Option<u64>,
) -> anyhow::Result<()> {
    let our = crate::our();
    let log_dir_path = create_drive(our.package_id(), "log", None)?;
    let log_file_path = format!("{log_dir_path}/{}.log", our.process());
    let log_file = open_file(&log_file_path, true, None)?;

    let file_filter = EnvFilter::new(file_level.as_str());
    let error_filter = tracing_subscriber::filter::filter_fn(|metadata: &tracing::Metadata<'_>| {
        metadata.level() == &Level::ERROR
    });
    let warn_filter = tracing_subscriber::filter::filter_fn(|metadata: &tracing::Metadata<'_>| {
        metadata.level() == &Level::WARN
    });
    let info_filter = tracing_subscriber::filter::filter_fn(|metadata: &tracing::Metadata<'_>| {
        metadata.level() == &Level::INFO
    });
    let debug_filter = tracing_subscriber::filter::filter_fn(|metadata: &tracing::Metadata<'_>| {
        metadata.level() == &Level::DEBUG
    });
    let file_writer_maker = FileWriterMaker {
        file: log_file,
        max_size: max_log_file_size.unwrap_or(1024 * 1024),
    };
    let (error, warn, info, debug) = terminal_levels_mapping.unwrap_or_else(|| (0, 1, 2, 3));
    let error_terminal_writer_maker = TerminalWriterMaker { level: error };
    let warn_terminal_writer_maker = TerminalWriterMaker { level: warn };
    let info_terminal_writer_maker = TerminalWriterMaker { level: info };
    let debug_terminal_writer_maker = TerminalWriterMaker { level: debug };

    let sub = tracing_subscriber::registry()
        .with(ErrorLayer::default())
        .with(
            fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_writer(file_writer_maker)
                .with_ansi(false)
                .with_target(false)
                .json()
                .with_filter(file_filter),
        )
        .with(
            fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .without_time()
                .with_writer(error_terminal_writer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(error_filter),
        );

    // TODO: can we DRY?
    let Some(remote) = remote else {
        if terminal_level >= Level::DEBUG {
            sub.with(
                fmt::layer()
                    .without_time()
                    .with_writer(warn_terminal_writer_maker)
                    .with_ansi(true)
                    .with_level(true)
                    .with_target(true)
                    .fmt_fields(fmt::format::PrettyFields::new())
                    .with_filter(warn_filter),
            )
            .with(
                fmt::layer()
                    .without_time()
                    .with_writer(info_terminal_writer_maker)
                    .with_ansi(true)
                    .with_level(true)
                    .with_target(true)
                    .fmt_fields(fmt::format::PrettyFields::new())
                    .with_filter(info_filter),
            )
            .with(
                fmt::layer()
                    .without_time()
                    .with_writer(debug_terminal_writer_maker)
                    .with_ansi(true)
                    .with_level(true)
                    .with_target(true)
                    .fmt_fields(fmt::format::PrettyFields::new())
                    .with_filter(debug_filter),
            )
            .init();
        } else if terminal_level >= Level::INFO {
            sub.with(
                fmt::layer()
                    .without_time()
                    .with_writer(warn_terminal_writer_maker)
                    .with_ansi(true)
                    .with_level(true)
                    .with_target(true)
                    .fmt_fields(fmt::format::PrettyFields::new())
                    .with_filter(warn_filter),
            )
            .with(
                fmt::layer()
                    .without_time()
                    .with_writer(info_terminal_writer_maker)
                    .with_ansi(true)
                    .with_level(true)
                    .with_target(true)
                    .fmt_fields(fmt::format::PrettyFields::new())
                    .with_filter(info_filter),
            )
            .init();
        } else if terminal_level >= Level::WARN {
            sub.with(
                fmt::layer()
                    .without_time()
                    .with_writer(warn_terminal_writer_maker)
                    .with_ansi(true)
                    .with_level(true)
                    .with_target(true)
                    .fmt_fields(fmt::format::PrettyFields::new())
                    .with_filter(warn_filter),
            )
            .init();
        }

        return Ok(());
    };

    let remote_filter = EnvFilter::new(remote.level.as_str());
    let remote_writer_maker = RemoteWriterMaker {
        target: remote.target,
    };
    let sub = sub.with(
        fmt::layer()
            .with_file(true)
            .with_line_number(true)
            .with_writer(remote_writer_maker)
            .with_ansi(false)
            .with_target(false)
            .json()
            .with_filter(remote_filter),
    );
    if terminal_level >= Level::DEBUG {
        sub.with(
            fmt::layer()
                .without_time()
                .with_writer(warn_terminal_writer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(warn_filter),
        )
        .with(
            fmt::layer()
                .without_time()
                .with_writer(info_terminal_writer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(info_filter),
        )
        .with(
            fmt::layer()
                .without_time()
                .with_writer(debug_terminal_writer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(debug_filter),
        )
        .init();
    } else if terminal_level >= Level::INFO {
        sub.with(
            fmt::layer()
                .without_time()
                .with_writer(warn_terminal_writer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(warn_filter),
        )
        .with(
            fmt::layer()
                .without_time()
                .with_writer(info_terminal_writer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(info_filter),
        )
        .init();
    } else if terminal_level >= Level::WARN {
        sub.with(
            fmt::layer()
                .without_time()
                .with_writer(warn_terminal_writer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(warn_filter),
        )
        .init();
    }

    Ok(())
}
