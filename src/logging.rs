use std::io::BufWriter;

pub use tracing::{debug, error, info, warn, Level};
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    fmt, layer::SubscriberExt, prelude::*, util::SubscriberInitExt, EnvFilter,
};

use crate::{print_to_terminal, Address};

pub struct FilePrinter {
    pub our: Address,
}

pub struct FilePrinterMaker {
    pub our: Address,
}

pub struct TerminalPrinter {
    pub level: u8,
}

pub struct TerminalPrinterMaker {
    pub level: u8,
}

impl std::io::Write for FilePrinter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // TODO: change to use vfs?
        let log_file_name = format!("{}.log", self.our.process());
        let log_path =
            std::path::PathBuf::from(std::env::var("LOGDIR").unwrap()).join(log_file_name);
        let file = std::fs::File::options()
            .append(true)
            .create(true)
            .open(&log_path)
            .unwrap();
        let mut writer = BufWriter::new(file);
        writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FilePrinterMaker {
    type Writer = FilePrinter;

    fn make_writer(&'a self) -> Self::Writer {
        FilePrinter {
            our: self.our.clone(),
        }
    }
}

impl std::io::Write for TerminalPrinter {
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

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TerminalPrinterMaker {
    type Writer = TerminalPrinter;

    fn make_writer(&'a self) -> Self::Writer {
        TerminalPrinter { level: self.level }
    }
}

/// Initialize `tracing`-based logging for the given process at the given level.
///
/// To write to logs, import the re-exported `debug!`, `info!`, `warn!`, `error!`
/// macros and use as usual. Logs will be printed to terminal as appropriate depending
/// on given level. Logs will be logged into the logging file as appropriate depending
/// on the given level.
///
/// The logging file lives in the node's `vfs/` directory, specifically at
/// `node/vfs/package:publisher.os/log/process.log`, where `node` is your node's home
/// directory, `package` is the package name, `publisher.os` is the publisher of the
/// package, and `process` is the process name of the process doing the logging.
pub fn init_logging(our: &Address, file_level: Level, terminal_level: Level) {
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
    let file_printer_maker = FilePrinterMaker { our: our.clone() };
    let error_terminal_printer_maker = TerminalPrinterMaker { level: 0 };
    let warn_terminal_printer_maker = TerminalPrinterMaker { level: 1 };
    let info_terminal_printer_maker = TerminalPrinterMaker { level: 2 };
    let debug_terminal_printer_maker = TerminalPrinterMaker { level: 3 };

    let sub = tracing_subscriber::registry()
        .with(ErrorLayer::default())
        .with(
            fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_writer(file_printer_maker)
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
                .with_writer(error_terminal_printer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(error_filter),
        );

    // TODO: can we DRY?
    if terminal_level >= Level::DEBUG {
        sub.with(
            fmt::layer()
                .without_time()
                .with_writer(warn_terminal_printer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(warn_filter),
        )
        .with(
            fmt::layer()
                .without_time()
                .with_writer(info_terminal_printer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(info_filter),
        )
        .with(
            fmt::layer()
                .without_time()
                .with_writer(debug_terminal_printer_maker)
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
                .with_writer(warn_terminal_printer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(warn_filter),
        )
        .with(
            fmt::layer()
                .without_time()
                .with_writer(info_terminal_printer_maker)
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
                .with_writer(warn_terminal_printer_maker)
                .with_ansi(true)
                .with_level(true)
                .with_target(true)
                .fmt_fields(fmt::format::PrettyFields::new())
                .with_filter(warn_filter),
        )
        .init();
    }
}
