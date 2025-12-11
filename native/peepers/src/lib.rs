use rustler::{Env, ListIterator, NifResult, Term};
use std::collections::HashMap;
use std::time::Instant;

// ============================================================================
// Prometheus Export - optimized text format generation
// ============================================================================

// Value type that preserves integer vs float distinction
#[derive(Debug, Clone)]
enum MetricValue {
    Integer(i64),
    Float(f64),
}

// Telemetry metric type from Elixir
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TelemetryMetricType {
    Counter,
    Sum,
    LastValue,
    Distribution,
}

impl TelemetryMetricType {
    fn from_struct_name(name: &str) -> Option<Self> {
        if name.ends_with("Counter") {
            Some(Self::Counter)
        } else if name.ends_with("Sum") {
            Some(Self::Sum)
        } else if name.ends_with("LastValue") {
            Some(Self::LastValue)
        } else if name.ends_with("Distribution") {
            Some(Self::Distribution)
        } else {
            None
        }
    }
}

// Prometheus metric type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrometheusType {
    Counter,
    Gauge,
    Histogram,
}

impl PrometheusType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "counter" => Some(Self::Counter),
            "gauge" => Some(Self::Gauge),
            "histogram" => Some(Self::Histogram),
            _ => None,
        }
    }

    fn default_for_telemetry_type(telemetry_type: TelemetryMetricType) -> Self {
        match telemetry_type {
            TelemetryMetricType::Counter => Self::Counter,
            TelemetryMetricType::Sum => Self::Counter,
            TelemetryMetricType::LastValue => Self::Gauge,
            TelemetryMetricType::Distribution => Self::Histogram,
        }
    }
}

// Special bucket keys in histogram data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BucketKey {
    Sum,
    Infinity,
}

impl BucketKey {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "sum" => Some(Self::Sum),
            "infinity" => Some(Self::Infinity),
            _ => None, // Upper bounds are numeric strings, parsed as f64 separately
        }
    }
}

// Metric struct field names
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetricField {
    Struct,
    Name,
    Description,
    ReporterOptions,
}

impl MetricField {
    fn from_atom_str(s: &str) -> Option<Self> {
        match s {
            "__struct__" => Some(Self::Struct),
            "name" => Some(Self::Name),
            "description" => Some(Self::Description),
            "reporter_options" => Some(Self::ReporterOptions),
            _ => None,
        }
    }
}

// Helper: Escape label values for Prometheus format
fn escape_label_value(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
}

// Helper: Escape help text for Prometheus format
fn escape_help(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
}

// Helper: Format a metric name (join with underscore, remove invalid chars)
fn format_name(name_parts: &[String]) -> String {
    let joined = name_parts.join("_");
    let mut result = String::with_capacity(joined.len());

    // Skip non-letter prefix
    let mut chars = joined.chars();
    loop {
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() => {
                result.push(c);
                break;
            }
            Some(_) => continue,
            None => return result,
        }
    }

    // Keep only letters, digits, and underscores
    for ch in chars {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            result.push(ch);
        }
    }

    result
}

// Helper: Format labels as comma-separated key="value" pairs, writing directly to output
fn format_labels_into(tags: &HashMap<String, String>, output: &mut String) {
    if tags.is_empty() {
        return;
    }

    // Collect entries (not just keys) to avoid re-lookup
    let mut entries: Vec<(&String, &String)> = tags.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    for (i, (key, value)) in entries.iter().enumerate() {
        if i > 0 {
            output.push(',');
        }
        output.push_str(key);
        output.push_str("=\"");
        escape_label_value(value, output);
        output.push('"');
    }
}

// Helper: Format a value (preserving integer vs float distinction), writing directly to output
fn format_value_into(value: &MetricValue, output: &mut String, ryu_buffer: &mut ryu::Buffer, itoa_buffer: &mut itoa::Buffer) {
    match value {
        MetricValue::Integer(i) => {
            output.push_str(itoa_buffer.format(*i));
        }
        MetricValue::Float(f) => {
            if f.is_nan() {
                output.push('0');
            } else if f.is_infinite() {
                if f.is_sign_positive() {
                    output.push_str("+Inf");
                } else {
                    output.push_str("-Inf");
                }
            } else {
                // Use ryu for float formatting (same as Erlang)
                output.push_str(ryu_buffer.format(*f));
            }
        }
    }
}

// Format a standard metric (counter, sum, gauge) directly into output string
fn format_standard_metric_into(
    name: &str,
    description: &str,
    prom_type: PrometheusType,
    series_term: Term,
    output: &mut String,
    tags_buf: &mut HashMap<String, String>,
    ryu_buffer: &mut ryu::Buffer,
    itoa_buffer: &mut itoa::Buffer,
) -> NifResult<()> {
    // Help line
    output.push_str("# HELP ");
    output.push_str(name);
    output.push(' ');
    escape_help(description, output);
    output.push('\n');

    // Type line
    output.push_str("# TYPE ");
    output.push_str(name);
    output.push(' ');
    output.push_str(prom_type.as_str());
    output.push('\n');

    // Iterate and format samples directly
    let map_iter = rustler::types::MapIterator::new(series_term)
        .ok_or_else(|| rustler::Error::Term(Box::new("Series is not a map")))?;

    for (tags_term, value_term) in map_iter {
        tags_buf.clear();
        decode_tags_map_into(tags_term, tags_buf)?;

        // Match on term type to preserve integer vs float distinction
        use rustler::TermType;
        let value = match value_term.get_type() {
            TermType::Integer => {
                let i = value_term.decode::<i64>()
                    .map_err(|_| rustler::Error::Term(Box::new("Failed to decode integer value")))?;
                MetricValue::Integer(i)
            }
            TermType::Float => {
                let f = value_term.decode::<f64>()
                    .map_err(|_| rustler::Error::Term(Box::new("Failed to decode float value")))?;
                MetricValue::Float(f)
            }
            other => {
                return Err(rustler::Error::Term(Box::new(format!(
                    "Unsupported value type: {:?}",
                    other
                ))));
            }
        };

        output.push_str(name);
        if !tags_buf.is_empty() {
            output.push('{');
            format_labels_into(tags_buf, output);
            output.push('}');
        }
        output.push(' ');
        format_value_into(&value, output, ryu_buffer, itoa_buffer);
        output.push('\n');
    }

    Ok(())
}

// Format a distribution (histogram) metric directly into output string
fn format_distribution_metric_into(
    name: &str,
    description: &str,
    series_term: Term,
    output: &mut String,
    tags_buf: &mut HashMap<String, String>,
    buckets_buf: &mut HashMap<String, i64>,
    labels_str: &mut String,
    bucket_list: &mut Vec<(f64, i64)>,
    cumulative_buckets: &mut Vec<(f64, i64)>,
    ryu_buffer: &mut ryu::Buffer,
    itoa_buffer: &mut itoa::Buffer,
) -> NifResult<()> {
    // Help line
    output.push_str("# HELP ");
    output.push_str(name);
    output.push(' ');
    escape_help(description, output);
    output.push('\n');

    // Type line
    output.push_str("# TYPE ");
    output.push_str(name);
    output.push_str(" histogram\n");

    // Iterate over series directly
    let map_iter = rustler::types::MapIterator::new(series_term)
        .ok_or_else(|| rustler::Error::Term(Box::new("Series is not a map")))?;

    // Process each tag combination
    for (tags_term, buckets_term) in map_iter {
        tags_buf.clear();
        decode_tags_map_into(tags_term, tags_buf)?;
        let has_labels = !tags_buf.is_empty();

        buckets_buf.clear();
        decode_buckets_map_into(buckets_term, buckets_buf)?;

        // Clear and format labels
        labels_str.clear();
        if has_labels {
            format_labels_into(tags_buf, labels_str);
        }

        // Clear and reuse bucket_list
        bucket_list.clear();
        let mut sum_value: i64 = 0;
        let mut inf_value: i64 = 0;

        for (key, count) in buckets_buf.iter() {
            match BucketKey::from_str(key) {
                Some(BucketKey::Sum) => sum_value = *count,
                Some(BucketKey::Infinity) => inf_value = *count,
                None => {
                    // Parse the bucket upper bound (numeric keys)
                    if let Ok(upper_bound) = key.parse::<f64>() {
                        bucket_list.push((upper_bound, *count));
                    }
                }
            }
        }

        // Sort by upper bound using unstable sort (faster, order of equal elements doesn't matter)
        bucket_list.sort_unstable_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        // Calculate cumulative counts (clear and reuse cumulative_buckets)
        cumulative_buckets.clear();
        let mut cumulative: i64 = 0;
        for (bound, count) in bucket_list.iter() {
            cumulative += count;
            cumulative_buckets.push((*bound, cumulative));
        }

        // Output bucket lines
        for (upper_bound, cumul_count) in cumulative_buckets.iter() {
            output.push_str(name);
            output.push_str("_bucket{");
            if has_labels {
                output.push_str(labels_str);
                output.push_str(",le=\"");
            } else {
                output.push_str("le=\"");
            }
            format_value_into(&MetricValue::Float(*upper_bound), output, ryu_buffer, itoa_buffer);
            output.push_str("\"} ");
            output.push_str(itoa_buffer.format(*cumul_count));
            output.push('\n');
        }

        // +Inf bucket
        output.push_str(name);
        output.push_str("_bucket{");
        if has_labels {
            output.push_str(labels_str);
            output.push_str(",le=\"+Inf\"} ");
        } else {
            output.push_str("le=\"+Inf\"} ");
        }
        output.push_str(itoa_buffer.format(cumulative + inf_value));
        output.push('\n');

        // Sum line
        output.push_str(name);
        output.push_str("_sum");
        if has_labels {
            output.push('{');
            output.push_str(labels_str);
            output.push('}');
        }
        output.push(' ');
        output.push_str(itoa_buffer.format(sum_value));
        output.push('\n');

        // Count line
        output.push_str(name);
        output.push_str("_count");
        if has_labels {
            output.push('{');
            output.push_str(labels_str);
            output.push('}');
        }
        output.push(' ');
        output.push_str(itoa_buffer.format(cumulative + inf_value));
        output.push('\n');
    }

    Ok(())
}

#[rustler::nif(schedule = "DirtyCpu")]
#[allow(unused_variables)]
fn prometheus_export<'a>(env: Env<'a>, metrics_map: Term<'a>) -> NifResult<String> {
    let export_start = Instant::now();

    // Count total number of time series (metric+tag combinations) to pre-allocate capacity
    // metrics_map is a map of %{metric_spec => series_map}
    let count_start = Instant::now();
    let map_iter = rustler::types::MapIterator::new(metrics_map)
        .ok_or_else(|| rustler::Error::Term(Box::new("Failed to decode metrics map")))?;

    let mut total_series_count = 0;
    for (_metric_struct, series_term) in map_iter {
        if let Ok(series_size) = series_term.map_size() {
            total_series_count += series_size;
        }
    }
    eprintln!("[PERF] Counting series: {:?}", count_start.elapsed());

    // Allocate ~500 bytes per time series (not per metric)
    let mut output = String::with_capacity(total_series_count * 500);

    // Re-create the iterator since we consumed it above
    let map_iter = rustler::types::MapIterator::new(metrics_map)
        .ok_or_else(|| rustler::Error::Term(Box::new("Failed to decode metrics map")))?;

    // Pre-allocate reusable buffers for the metric loop
    let mut struct_name = String::with_capacity(64);
    let mut name_parts: Vec<String> = Vec::with_capacity(8);
    let mut description = String::with_capacity(128);

    // Pre-allocate reusable buffers for decoding (shared across all metrics)
    let mut tags_buf: HashMap<String, String> = HashMap::with_capacity(16);
    let mut buckets_buf: HashMap<String, i64> = HashMap::with_capacity(32);

    // Pre-allocate reusable buffers for histogram formatting
    let mut labels_str = String::with_capacity(128);
    let mut bucket_list: Vec<(f64, i64)> = Vec::with_capacity(32);
    let mut cumulative_buckets: Vec<(f64, i64)> = Vec::with_capacity(32);

    // Pre-allocate ryu buffer for float formatting
    let mut ryu_buffer = ryu::Buffer::new();

    // Pre-allocate itoa buffer for integer formatting
    let mut itoa_buffer = itoa::Buffer::new();

    let mut time_parsing_metrics = std::time::Duration::ZERO;
    let mut time_formatting = std::time::Duration::ZERO;

    for (metric_struct, series_term) in map_iter {
        let parse_start = Instant::now();
        // metric_struct is the key (e.g., %Telemetry.Metrics.Counter{...})
        // series_term is the value (e.g., %{tags => value})

        // Extract metric struct fields using map access
        let map_iter = rustler::types::MapIterator::new(metric_struct)
            .ok_or_else(|| rustler::Error::Term(Box::new("Metric struct is not a map")))?;

        // Clear and reuse buffers
        struct_name.clear();
        name_parts.clear();
        description.clear();
        let mut reporter_opts_term: Option<Term> = None;

        for (key, value) in map_iter {
            if let Ok(key_atom) = key.atom_to_string() {
                if let Some(field) = MetricField::from_atom_str(&key_atom) {
                    match field {
                        MetricField::Struct => {
                            if let Ok(struct_atom) = value.atom_to_string() {
                                struct_name = struct_atom;
                            }
                        }
                        MetricField::Name => {
                            // name is a list of atoms/strings
                            if let Ok(name_iter) = value.decode::<ListIterator>() {
                                for part_term in name_iter {
                                    if let Ok(s) = part_term.atom_to_string() {
                                        name_parts.push(s);
                                    } else if let Ok(s) = part_term.decode::<String>() {
                                        name_parts.push(s);
                                    }
                                }
                            }
                        }
                        MetricField::Description => {
                            if let Ok(desc) = value.decode::<String>() {
                                description = desc;
                            }
                        }
                        MetricField::ReporterOptions => {
                            reporter_opts_term = Some(value);
                        }
                    }
                }
            }
        }

        let metric_name = format_name(&name_parts);

        time_parsing_metrics += parse_start.elapsed();
        let format_start = Instant::now();

        // Determine the metric type from the struct name
        let telemetry_type = TelemetryMetricType::from_struct_name(&struct_name)
            .ok_or_else(|| {
                rustler::Error::Term(Box::new(format!(
                    "Unknown metric type: {}",
                    struct_name
                )))
            })?;

        match telemetry_type {
            TelemetryMetricType::Counter => {
                format_standard_metric_into(
                    &metric_name,
                    &description,
                    PrometheusType::Counter,
                    series_term,
                    &mut output,
                    &mut tags_buf,
                    &mut ryu_buffer,
                    &mut itoa_buffer,
                )?;
            }
            TelemetryMetricType::Sum => {
                // Sum metric - check reporter_options for prometheus_type override
                let prom_type = if let Some(opts) = reporter_opts_term {
                    extract_prometheus_type(opts)
                        .unwrap_or_else(|| PrometheusType::default_for_telemetry_type(telemetry_type))
                } else {
                    PrometheusType::default_for_telemetry_type(telemetry_type)
                };
                format_standard_metric_into(
                    &metric_name,
                    &description,
                    prom_type,
                    series_term,
                    &mut output,
                    &mut tags_buf,
                    &mut ryu_buffer,
                    &mut itoa_buffer,
                )?;
            }
            TelemetryMetricType::LastValue => {
                // LastValue metric - check reporter_options for prometheus_type override
                let prom_type = if let Some(opts) = reporter_opts_term {
                    extract_prometheus_type(opts)
                        .unwrap_or_else(|| PrometheusType::default_for_telemetry_type(telemetry_type))
                } else {
                    PrometheusType::default_for_telemetry_type(telemetry_type)
                };
                format_standard_metric_into(
                    &metric_name,
                    &description,
                    prom_type,
                    series_term,
                    &mut output,
                    &mut tags_buf,
                    &mut ryu_buffer,
                    &mut itoa_buffer,
                )?;
            }
            TelemetryMetricType::Distribution => {
                format_distribution_metric_into(
                    &metric_name,
                    &description,
                    series_term,
                    &mut output,
                    &mut tags_buf,
                    &mut buckets_buf,
                    &mut labels_str,
                    &mut bucket_list,
                    &mut cumulative_buckets,
                    &mut ryu_buffer,
                    &mut itoa_buffer,
                )?;
            }
        }

        time_formatting += format_start.elapsed();
    }

    eprintln!("[PERF] Parsing metric structs: {:?}", time_parsing_metrics);
    eprintln!("[PERF] Formatting output: {:?}", time_formatting);

    output.push_str("# EOF\n");

    eprintln!("[PERF] Total export time: {:?}", export_start.elapsed());
    eprintln!("[PERF] Output size: {} bytes ({:.2} MB)", output.len(), output.len() as f64 / 1024.0 / 1024.0);

    Ok(output)
}

// Helper: Decode a tags map into a provided HashMap (reuses allocation)
fn decode_tags_map_into(tags_term: Term, tags: &mut HashMap<String, String>) -> NifResult<()> {
    let map_iter = rustler::types::MapIterator::new(tags_term)
        .ok_or_else(|| rustler::Error::Term(Box::new("Tags is not a map")))?;

    for (key_term, value_term) in map_iter {
        let key = decode_term_to_string(key_term)?;
        let value = decode_term_to_string(value_term)?;
        tags.insert(key, value);
    }

    Ok(())
}

// Helper: Decode a buckets map into a provided HashMap (reuses allocation)
fn decode_buckets_map_into(buckets_term: Term, buckets: &mut HashMap<String, i64>) -> NifResult<()> {
    let map_iter = rustler::types::MapIterator::new(buckets_term)
        .ok_or_else(|| rustler::Error::Term(Box::new("Buckets is not a map")))?;

    for (key_term, value_term) in map_iter {
        let key = decode_term_to_string(key_term)?;
        let value: i64 = value_term
            .decode()
            .map_err(|_| rustler::Error::Term(Box::new("Failed to decode bucket count")))?;
        buckets.insert(key, value);
    }

    Ok(())
}

// Helper: Decode any term to a string (atom, string, integer, etc.)
fn decode_term_to_string(term: Term) -> NifResult<String> {
    use rustler::TermType;

    match term.get_type() {
        TermType::Atom => term
            .atom_to_string()
            .map_err(|_| rustler::Error::Term(Box::new("Failed to decode atom"))),
        TermType::Binary => term
            .decode::<String>()
            .map_err(|_| rustler::Error::Term(Box::new("Failed to decode binary to string"))),
        TermType::Integer => term
            .decode::<i64>()
            .map(|i| i.to_string())
            .map_err(|_| rustler::Error::Term(Box::new("Failed to decode integer"))),
        TermType::Float => term
            .decode::<f64>()
            .map(|f| f.to_string())
            .map_err(|_| rustler::Error::Term(Box::new("Failed to decode float"))),
        TermType::List => {
            // Get first element to determine list type
            if let Ok(list_iter) = term.decode::<ListIterator>() {
                let elements: Vec<Term> = list_iter.collect();

                if elements.is_empty() {
                    return Ok(String::new());
                }

                match elements[0].get_type() {
                    TermType::Atom => {
                        // List of atoms - join them with underscore
                        let strings: Result<Vec<String>, _> =
                            elements.iter().map(|elem| elem.atom_to_string()).collect();

                        strings.map(|strs| strs.join("_")).map_err(|_| {
                            rustler::Error::Term(Box::new("Failed to decode list of atoms"))
                        })
                    }
                    TermType::Integer => {
                        // List of integers - this is a charlist, convert ASCII values to string
                        let numbers: Result<Vec<i64>, _> =
                            elements.iter().map(|elem| elem.decode::<i64>()).collect();

                        numbers
                            .map(|nums| nums.iter().map(|&n| n as u8 as char).collect::<String>())
                            .map_err(|_| {
                                rustler::Error::Term(Box::new("Failed to decode charlist"))
                            })
                    }
                    other => Err(rustler::Error::Term(Box::new(format!(
                        "Unsupported list element type: {:?}",
                        other
                    )))),
                }
            } else {
                Err(rustler::Error::Term(Box::new("Failed to decode list")))
            }
        }
        _other => {
            // Fallback for unsupported types - return "unknown"
            // This prevents crashes on unexpected types (matching Peep's inspect() behavior)
            Ok(String::from("unknown"))
        }
    }
}

// Helper: Extract prometheus_type from reporter_options keyword list
fn extract_prometheus_type(opts_term: Term) -> Option<PrometheusType> {
    // reporter_options is a keyword list (list of tuples)
    if let Ok(list_iter) = opts_term.decode::<ListIterator>() {
        for item in list_iter {
            if let Ok(tuple) = rustler::types::tuple::get_tuple(item) {
                if tuple.len() == 2 {
                    if let Ok(key) = tuple[0].atom_to_string() {
                        if key == "prometheus_type" {
                            // Try to decode as atom first, then as string
                            if let Ok(val) = tuple[1].atom_to_string() {
                                return PrometheusType::from_str(&val);
                            } else if let Ok(val) = tuple[1].decode::<String>() {
                                return PrometheusType::from_str(&val);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// ============================================================================
// String Escaping NIFs - for use with Elixir Prometheus exporter
// ============================================================================

/// Escape a label value for Prometheus format.
/// Escapes: ", \, and newline
#[rustler::nif]
fn escape_label(value: String) -> String {
    let mut result = String::with_capacity(value.len() + 10);

    for ch in value.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            _ => result.push(ch),
        }
    }

    result
}

/// Escape help text for Prometheus format.
/// Escapes: \ and newline
#[rustler::nif]
fn escape_help(value: String) -> String {
    let mut result = String::with_capacity(value.len() + 10);

    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            _ => result.push(ch),
        }
    }

    result
}

rustler::init!("Elixir.Supavisor.Monitoring.Peepers", [prometheus_export, escape_label, escape_help]);
