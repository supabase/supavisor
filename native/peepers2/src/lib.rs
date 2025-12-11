use rustc_hash::FxHashMap;
use rustler::{Env, ListIterator, NifResult, Term};
use std::collections::HashMap;

// ============================================================================
// Struct that holds aggregated metrics (with lifetime)
// ============================================================================

struct AggregatedMetrics<'a> {
    // Store metric keys once, use indices to reference them
    metric_keys: Vec<MetricKey>,
    // Map from metric index to tag->value map
    counters: FxHashMap<usize, FxHashMap<TagsKey<'a>, i64>>,
    sums: FxHashMap<usize, FxHashMap<TagsKey<'a>, i64>>,
    last_values: FxHashMap<usize, FxHashMap<TagsKey<'a>, MetricValue>>,
    distributions: FxHashMap<usize, FxHashMap<TagsKey<'a>, FxHashMap<String, i64>>>,
}

// ============================================================================
// Key types for organizing metrics
// ============================================================================

// Unique key for a metric (based on its name and reporter options)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct MetricKey {
    name_parts: Vec<String>,
    formatted_name: String, // Pre-computed formatted name for Prometheus
    description: String,
    reporter_options: Vec<(String, String)>,
}

// Tags stored as a Term
// Uses Term's built-in equality and phash2 for hashing
#[derive(Debug, Clone, Eq, PartialEq)]
struct TagsKey<'a> {
    // The raw term representing the tags map
    term: Term<'a>,
}

impl<'a> TagsKey<'a> {
    // Create TagsKey from a term
    fn from_term(term: Term<'a>) -> Self {
        Self { term }
    }

    fn is_empty(&self) -> bool {
        // Check if the map is empty
        if let Some(iter) = rustler::types::MapIterator::new(self.term) {
            iter.count() == 0
        } else {
            true
        }
    }

    // Convert the term to a Prometheus label string
    fn to_prometheus_labels(&self) -> String {
        let mut tags: Vec<(String, String)> = Vec::new();

        if let Some(map_iter) = rustler::types::MapIterator::new(self.term) {
            for (key_term, value_term) in map_iter {
                if let Ok(key) = decode_tag_key(key_term) {
                    if let Ok(value) = decode_tag_value(value_term) {
                        tags.push((key, value));
                    }
                }
            }
        }

        tags.sort_unstable();

        let mut formatted = String::with_capacity(tags.len() * 20);
        for (i, (key, value)) in tags.iter().enumerate() {
            if i > 0 {
                formatted.push(',');
            }
            formatted.push_str(key);
            formatted.push_str("=\"");
            escape_label_value(value, &mut formatted);
            formatted.push('"');
        }

        formatted
    }
}

impl<'a> std::hash::Hash for TagsKey<'a> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Use Erlang's internal hash for faster hashing
        // Salt of 0 is fine since we only use this for HashMap lookups
        self.term.hash_internal(0).hash(state);
    }
}

// ============================================================================
// Value types and enums
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

// ============================================================================
// Helper functions for decoding Elixir terms
// ============================================================================

// Helper: Decode tag key (almost always an atom)
#[inline]
fn decode_tag_key(term: Term) -> NifResult<String> {
    // Tag keys are almost always atoms
    if let Ok(s) = term.atom_to_string() {
        return Ok(s);
    }
    // Fallback to string
    if let Ok(s) = term.decode::<String>() {
        return Ok(s);
    }
    Err(rustler::Error::Term(Box::new("Failed to decode tag key")))
}

// Helper: Decode tag value (usually string, sometimes atom, integer, or charlist)
#[inline]
fn decode_tag_value(term: Term) -> NifResult<String> {
    // Try string first - most common
    if let Ok(s) = term.decode::<String>() {
        return Ok(s);
    }

    // Try atom second
    if let Ok(s) = term.atom_to_string() {
        return Ok(s);
    }

    // Try integer
    if let Ok(i) = term.decode::<i64>() {
        let mut buffer = itoa::Buffer::new();
        return Ok(buffer.format(i).to_string());
    }

    // Try charlist (list of integers)
    if let Ok(list_iter) = term.decode::<ListIterator>() {
        let elements: Vec<Term> = list_iter.collect();
        if !elements.is_empty() {
            if let Ok(numbers) = elements
                .iter()
                .map(|elem| elem.decode::<i64>())
                .collect::<Result<Vec<_>, _>>()
            {
                return Ok(numbers.iter().map(|&n| n as u8 as char).collect::<String>());
            }
        }
    }

    // Fallback
    Ok(String::from("unknown"))
}

// Helper: Decode metric value (almost always integer or float)
#[inline]
fn decode_metric_value_i64(term: Term) -> NifResult<i64> {
    // Try integer first - most common for counters/sums
    if let Ok(i) = term.decode::<i64>() {
        return Ok(i);
    }

    // Try float and convert to integer
    if let Ok(f) = term.decode::<f64>() {
        return Ok(f as i64);
    }

    Err(rustler::Error::Term(Box::new(
        "Failed to decode metric value as i64",
    )))
}

// Helper: Decode any term to a string (atom, string, integer, etc.)
// Generic version for cases where we don't know the expected type
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
            .map(|i| {
                let mut buffer = itoa::Buffer::new();
                buffer.format(i).to_string()
            })
            .map_err(|_| rustler::Error::Term(Box::new("Failed to decode integer"))),
        TermType::Float => term
            .decode::<f64>()
            .map(|f| {
                let mut buffer = ryu::Buffer::new();
                buffer.format(f).to_string()
            })
            .map_err(|_| rustler::Error::Term(Box::new("Failed to decode float"))),
        TermType::List => {
            if let Ok(list_iter) = term.decode::<ListIterator>() {
                let elements: Vec<Term> = list_iter.collect();

                if elements.is_empty() {
                    return Ok(String::new());
                }

                match elements[0].get_type() {
                    TermType::Atom => {
                        let strings: Result<Vec<String>, _> =
                            elements.iter().map(|elem| elem.atom_to_string()).collect();

                        strings.map(|strs| strs.join("_")).map_err(|_| {
                            rustler::Error::Term(Box::new("Failed to decode list of atoms"))
                        })
                    }
                    TermType::Integer => {
                        let numbers: Result<Vec<i64>, _> =
                            elements.iter().map(|elem| elem.decode::<i64>()).collect();

                        numbers
                            .map(|nums| nums.iter().map(|&n| n as u8 as char).collect::<String>())
                            .map_err(|_| {
                                rustler::Error::Term(Box::new("Failed to decode charlist"))
                            })
                    }
                    _ => Ok(String::from("unknown")),
                }
            } else {
                Err(rustler::Error::Term(Box::new("Failed to decode list")))
            }
        }
        _ => Ok(String::from("unknown")),
    }
}

// Decode tags map
fn decode_tags_map(tags_term: Term) -> NifResult<FxHashMap<String, String>> {
    let mut tags = FxHashMap::default();
    let map_iter = rustler::types::MapIterator::new(tags_term)
        .ok_or_else(|| rustler::Error::Term(Box::new("Tags is not a map")))?;

    for (key_term, value_term) in map_iter {
        let key = decode_term_to_string(key_term)?;
        let value = decode_term_to_string(value_term)?;
        tags.insert(key, value);
    }

    Ok(tags)
}

// Decode reporter options (keyword list)
fn decode_reporter_options(opts_term: Term) -> NifResult<Vec<(String, String)>> {
    let mut options = Vec::new();

    if let Ok(list_iter) = opts_term.decode::<ListIterator>() {
        for item in list_iter {
            if let Ok(tuple) = rustler::types::tuple::get_tuple(item) {
                if tuple.len() == 2 {
                    if let Ok(key) = decode_term_to_string(tuple[0]) {
                        if let Ok(val) = decode_term_to_string(tuple[1]) {
                            options.push((key, val));
                        }
                    }
                }
            }
        }
    }

    options.sort();
    Ok(options)
}

// Parse metric struct to extract key information
// Note: Returns cloneable types to support caching
fn parse_metric_struct(metric_struct: Term) -> NifResult<(TelemetryMetricType, MetricKey)> {
    let map_iter = rustler::types::MapIterator::new(metric_struct)
        .ok_or_else(|| rustler::Error::Term(Box::new("Metric struct is not a map")))?;

    let mut struct_name = String::new();
    let mut name_parts = Vec::new();
    let mut description = String::new();
    let mut reporter_options = Vec::new();

    for (key, value) in map_iter {
        if let Ok(key_atom) = key.atom_to_string() {
            if let Some(field) = MetricField::from_atom_str(&key_atom) {
                match field {
                    MetricField::Struct => {
                        if let Ok(s) = value.atom_to_string() {
                            struct_name = s;
                        }
                    }
                    MetricField::Name => {
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
                        reporter_options = decode_reporter_options(value)?;
                    }
                }
            }
        }
    }

    let metric_type = TelemetryMetricType::from_struct_name(&struct_name).ok_or_else(|| {
        rustler::Error::Term(Box::new(format!("Unknown metric type: {}", struct_name)))
    })?;

    // Pre-compute the formatted name once during parsing
    let formatted_name = format_name(&name_parts);

    let metric_key = MetricKey {
        name_parts,
        formatted_name,
        description,
        reporter_options,
    };

    Ok((metric_type, metric_key))
}

// Decode buckets map for distributions
fn decode_buckets_map(buckets_term: Term) -> NifResult<FxHashMap<String, i64>> {
    let mut buckets = FxHashMap::default();
    let map_iter = rustler::types::MapIterator::new(buckets_term)
        .ok_or_else(|| rustler::Error::Term(Box::new("Buckets is not a map")))?;

    for (key_term, value_term) in map_iter {
        let key = decode_term_to_string(key_term)?;
        let value: i64 = value_term
            .decode()
            .map_err(|_| rustler::Error::Term(Box::new("Failed to decode bucket count")))?;
        buckets.insert(key, value);
    }

    Ok(buckets)
}

// ============================================================================
// NIF: Aggregate and export preprocessed metrics
// ============================================================================

#[rustler::nif(schedule = "DirtyCpu")]
fn aggregate_and_export<'a>(
    env: Env<'a>,
    preprocessed_data: Term<'a>,
    itm_map: Term<'a>,
) -> NifResult<String> {
    let start = std::time::Instant::now();

    let mut counters = FxHashMap::default();
    let mut sums = FxHashMap::default();
    let mut last_values = FxHashMap::default();
    let mut distributions = FxHashMap::default();

    // preprocessed_data is a list of {metric_type, metric_id, tags, value}
    let list_iter = preprocessed_data
        .decode::<ListIterator>()
        .map_err(|_| rustler::Error::Term(Box::new("Expected list of preprocessed metrics")))?;

    eprintln!("[PEEPERS2] Starting aggregation...");
    let decode_start = std::time::Instant::now();

    // Pre-allocate vectors to store unique MetricKeys (avoid cloning)
    let mut metric_keys: Vec<MetricKey> = Vec::new();
    // Cache: metric_id (as u64) -> index in metric_keys vec
    // Use FxHashMap for faster lookups
    let mut metric_cache: FxHashMap<u64, (TelemetryMetricType, usize)> = FxHashMap::default();

    // Convert itm_map to a FxHashMap once for O(1) lookups
    let itm_hashmap: FxHashMap<u64, Term> = {
        let map_iter = rustler::types::MapIterator::new(itm_map)
            .ok_or_else(|| rustler::Error::Term(Box::new("itm_map is not a map")))?;

        let mut hm = FxHashMap::default();
        for (k, v) in map_iter {
            if let Ok(id) = k.decode::<u64>() {
                hm.insert(id, v);
            }
        }
        hm
    };

    let mut item_count = 0;
    let mut time_tuple_decode = std::time::Duration::ZERO;
    let mut time_metric_lookup = std::time::Duration::ZERO;
    let mut time_tags_copy = std::time::Duration::ZERO;
    let mut time_value_decode = std::time::Duration::ZERO;
    let mut time_hashmap_insert = std::time::Duration::ZERO;

    for item in list_iter {
        item_count += 1;

        let t0 = std::time::Instant::now();
        let tuple = rustler::types::tuple::get_tuple(item)
            .map_err(|_| rustler::Error::Term(Box::new("Expected tuple")))?;

        if tuple.len() != 4 {
            return Err(rustler::Error::Term(Box::new("Expected 4-element tuple")));
        }

        let _metric_type_atom = tuple[0]
            .atom_to_string()
            .map_err(|_| rustler::Error::Term(Box::new("Expected metric type atom")))?;
        let metric_id_term = tuple[1];
        let tags_term = tuple[2];
        let value_term = tuple[3];

        // Decode metric_id as u64 to use as cache key
        let metric_id: u64 = metric_id_term
            .decode()
            .map_err(|_| rustler::Error::Term(Box::new("Failed to decode metric_id")))?;
        time_tuple_decode += t0.elapsed();

        let t1 = std::time::Instant::now();
        let (metric_type, metric_key_idx) = if let Some(&cached) = metric_cache.get(&metric_id) {
            cached
        } else {
            // Look up the metric struct in the itm_hashmap (O(1) lookup)
            let metric_struct = itm_hashmap
                .get(&metric_id)
                .ok_or_else(|| rustler::Error::Term(Box::new("metric_id not found in itm_map")))?;

            let (metric_type, metric_key) = parse_metric_struct(*metric_struct)?;
            let idx = metric_keys.len();
            metric_keys.push(metric_key);
            metric_cache.insert(metric_id, (metric_type, idx));
            (metric_type, idx)
        };
        time_metric_lookup += t1.elapsed();

        let t2 = std::time::Instant::now();
        // Create TagsKey directly from the term
        let tags_key = TagsKey::from_term(tags_term);
        time_tags_copy += t2.elapsed();

        let t3 = std::time::Instant::now();
        match metric_type {
            TelemetryMetricType::Counter => {
                let value = decode_metric_value_i64(value_term)?;
                time_value_decode += t3.elapsed();

                let t4 = std::time::Instant::now();
                counters
                    .entry(metric_key_idx)
                    .or_insert_with(FxHashMap::default)
                    .entry(tags_key)
                    .and_modify(|v| *v += value)
                    .or_insert(value);
                time_hashmap_insert += t4.elapsed();
            }
            TelemetryMetricType::Sum => {
                let value = decode_metric_value_i64(value_term)?;
                time_value_decode += t3.elapsed();

                let t4 = std::time::Instant::now();
                sums.entry(metric_key_idx)
                    .or_insert_with(FxHashMap::default)
                    .entry(tags_key)
                    .and_modify(|v| *v += value)
                    .or_insert(value);
                time_hashmap_insert += t4.elapsed();
            }
            TelemetryMetricType::LastValue => {
                use rustler::TermType;
                let value = match value_term.get_type() {
                    TermType::Integer => {
                        let i = value_term.decode::<i64>().map_err(|_| {
                            rustler::Error::Term(Box::new("Failed to decode integer value"))
                        })?;
                        MetricValue::Integer(i)
                    }
                    TermType::Float => {
                        let f = value_term.decode::<f64>().map_err(|_| {
                            rustler::Error::Term(Box::new("Failed to decode float value"))
                        })?;
                        MetricValue::Float(f)
                    }
                    _ => {
                        return Err(rustler::Error::Term(Box::new(
                            "Unsupported last value type",
                        )))
                    }
                };
                time_value_decode += t3.elapsed();

                let t4 = std::time::Instant::now();
                last_values
                    .entry(metric_key_idx)
                    .or_insert_with(FxHashMap::default)
                    .insert(tags_key, value);
                time_hashmap_insert += t4.elapsed();
            }
            TelemetryMetricType::Distribution => {
                // value is a map of bucket->count
                let buckets = decode_buckets_map(value_term)?;
                time_value_decode += t3.elapsed();

                let t4 = std::time::Instant::now();
                let dist_map = distributions
                    .entry(metric_key_idx)
                    .or_insert_with(FxHashMap::default);

                let bucket_map = dist_map.entry(tags_key).or_insert_with(FxHashMap::default);

                for (bucket, count) in buckets {
                    bucket_map
                        .entry(bucket)
                        .and_modify(|v| *v += count)
                        .or_insert(count);
                }
                time_hashmap_insert += t4.elapsed();
            }
        }
    }

    let aggregated = AggregatedMetrics {
        metric_keys,
        counters,
        sums,
        last_values,
        distributions,
    };

    eprintln!(
        "[PEEPERS2] Aggregation decode+process took: {:?}",
        decode_start.elapsed()
    );
    eprintln!("[PEEPERS2]   - Tuple decode: {:?}", time_tuple_decode);
    eprintln!("[PEEPERS2]   - Metric lookup: {:?}", time_metric_lookup);
    eprintln!("[PEEPERS2]   - Tags copy: {:?}", time_tags_copy);
    eprintln!("[PEEPERS2]   - Value decode: {:?}", time_value_decode);
    eprintln!("[PEEPERS2]   - HashMap insert: {:?}", time_hashmap_insert);
    eprintln!("[PEEPERS2] Total aggregation time: {:?}", start.elapsed());
    eprintln!(
        "[PEEPERS2] Processed {} items, cached {} unique metrics",
        item_count,
        metric_cache.len()
    );
    eprintln!("[PEEPERS2] Metrics aggregated - counters: {}, sums: {}, last_values: {}, distributions: {}",
        aggregated.counters.len(),
        aggregated.sums.len(),
        aggregated.last_values.len(),
        aggregated.distributions.len()
    );

    // Now export the aggregated metrics
    export_aggregated_metrics(aggregated)
}

// ============================================================================
// Prometheus export formatting helpers
// ============================================================================

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

// Helper: Get prometheus type from reporter options
fn get_prometheus_type(
    reporter_options: &[(String, String)],
    default: PrometheusType,
) -> PrometheusType {
    for (key, value) in reporter_options {
        if key == "prometheus_type" {
            if let Some(prom_type) = PrometheusType::from_str(value) {
                return prom_type;
            }
        }
    }
    default
}

// Helper: Format labels inline
fn format_labels_inline(tags: &HashMap<String, String>, output: &mut String) {
    if tags.is_empty() {
        return;
    }

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

// Helper: Format value inline
fn format_value_inline(
    value: &MetricValue,
    output: &mut String,
    ryu_buffer: &mut ryu::Buffer,
    itoa_buffer: &mut itoa::Buffer,
) {
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
                output.push_str(ryu_buffer.format(*f));
            }
        }
    }
}

// ============================================================================
// Export aggregated metrics to Prometheus format
// ============================================================================

fn export_aggregated_metrics(aggregated: AggregatedMetrics) -> NifResult<String> {
    let start = std::time::Instant::now();
    eprintln!("[PEEPERS2] Starting export...");

    let mut output = String::with_capacity(500_000);
    let mut ryu_buffer = ryu::Buffer::new();
    let mut itoa_buffer = itoa::Buffer::new();

    let counters_start = std::time::Instant::now();
    // Export counters
    for (metric_key_idx, series) in &aggregated.counters {
        let metric_key = &aggregated.metric_keys[*metric_key_idx];
        let metric_name = &metric_key.formatted_name;

        output.push_str("# HELP ");
        output.push_str(metric_name);
        output.push(' ');
        escape_help(&metric_key.description, &mut output);
        output.push('\n');

        output.push_str("# TYPE ");
        output.push_str(metric_name);
        output.push_str(" counter\n");

        for (tags_key, value) in series {
            output.push_str(metric_name);
            if !tags_key.is_empty() {
                output.push('{');
                output.push_str(&tags_key.to_prometheus_labels());
                output.push('}');
            }
            output.push(' ');
            output.push_str(itoa_buffer.format(*value));
            output.push('\n');
        }
    }
    eprintln!(
        "[PEEPERS2] Counters export took: {:?}",
        counters_start.elapsed()
    );

    let sums_start = std::time::Instant::now();
    // Export sums
    for (metric_key_idx, series) in &aggregated.sums {
        let metric_key = &aggregated.metric_keys[*metric_key_idx];
        let metric_name = &metric_key.formatted_name;
        let prom_type = get_prometheus_type(&metric_key.reporter_options, PrometheusType::Counter);

        output.push_str("# HELP ");
        output.push_str(metric_name);
        output.push(' ');
        escape_help(&metric_key.description, &mut output);
        output.push('\n');

        output.push_str("# TYPE ");
        output.push_str(metric_name);
        output.push(' ');
        output.push_str(prom_type.as_str());
        output.push('\n');

        for (tags_key, value) in series {
            output.push_str(metric_name);
            if !tags_key.is_empty() {
                output.push('{');
                output.push_str(&tags_key.to_prometheus_labels());
                output.push('}');
            }
            output.push(' ');
            output.push_str(itoa_buffer.format(*value));
            output.push('\n');
        }
    }
    eprintln!("[PEEPERS2] Sums export took: {:?}", sums_start.elapsed());

    let last_values_start = std::time::Instant::now();
    // Export last values
    for (metric_key_idx, series) in &aggregated.last_values {
        let metric_key = &aggregated.metric_keys[*metric_key_idx];
        let metric_name = &metric_key.formatted_name;
        let prom_type = get_prometheus_type(&metric_key.reporter_options, PrometheusType::Gauge);

        output.push_str("# HELP ");
        output.push_str(metric_name);
        output.push(' ');
        escape_help(&metric_key.description, &mut output);
        output.push('\n');

        output.push_str("# TYPE ");
        output.push_str(metric_name);
        output.push(' ');
        output.push_str(prom_type.as_str());
        output.push('\n');

        for (tags_key, value) in series {
            output.push_str(metric_name);
            if !tags_key.is_empty() {
                output.push('{');
                output.push_str(&tags_key.to_prometheus_labels());
                output.push('}');
            }
            output.push(' ');
            format_value_inline(value, &mut output, &mut ryu_buffer, &mut itoa_buffer);
            output.push('\n');
        }
    }
    eprintln!(
        "[PEEPERS2] Last values export took: {:?}",
        last_values_start.elapsed()
    );

    let distributions_start = std::time::Instant::now();
    // Export distributions
    for (metric_key_idx, series) in &aggregated.distributions {
        let metric_key = &aggregated.metric_keys[*metric_key_idx];
        let metric_name = &metric_key.formatted_name;

        output.push_str("# HELP ");
        output.push_str(metric_name);
        output.push(' ');
        escape_help(&metric_key.description, &mut output);
        output.push('\n');

        output.push_str("# TYPE ");
        output.push_str(metric_name);
        output.push_str(" histogram\n");

        for (tags_key, buckets) in series {
            let has_labels = !tags_key.is_empty();
            let labels_str = tags_key.to_prometheus_labels();

            // Parse buckets
            let mut bucket_list: Vec<(f64, i64)> = Vec::new();
            let mut sum_value: i64 = 0;
            let mut inf_value: i64 = 0;

            for (key, count) in buckets {
                match key.as_str() {
                    "sum" => sum_value = *count,
                    "infinity" => inf_value = *count,
                    _ => {
                        if let Ok(upper_bound) = key.parse::<f64>() {
                            bucket_list.push((upper_bound, *count));
                        }
                    }
                }
            }

            bucket_list.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

            // Calculate cumulative counts
            let mut cumulative: i64 = 0;
            let mut cumulative_buckets: Vec<(f64, i64)> = Vec::new();
            for (bound, count) in &bucket_list {
                cumulative += count;
                cumulative_buckets.push((*bound, cumulative));
            }

            // Output bucket lines
            for (upper_bound, cumul_count) in &cumulative_buckets {
                output.push_str(metric_name);
                output.push_str("_bucket{");
                if has_labels {
                    output.push_str(&labels_str);
                    output.push_str(",le=\"");
                } else {
                    output.push_str("le=\"");
                }
                output.push_str(ryu_buffer.format(*upper_bound));
                output.push_str("\"} ");
                output.push_str(itoa_buffer.format(*cumul_count));
                output.push('\n');
            }

            // +Inf bucket
            output.push_str(metric_name);
            output.push_str("_bucket{");
            if has_labels {
                output.push_str(&labels_str);
                output.push_str(",le=\"+Inf\"} ");
            } else {
                output.push_str("le=\"+Inf\"} ");
            }
            output.push_str(itoa_buffer.format(cumulative + inf_value));
            output.push('\n');

            // Sum line
            output.push_str(metric_name);
            output.push_str("_sum");
            if has_labels {
                output.push('{');
                output.push_str(&labels_str);
                output.push('}');
            }
            output.push(' ');
            output.push_str(itoa_buffer.format(sum_value));
            output.push('\n');

            // Count line
            output.push_str(metric_name);
            output.push_str("_count");
            if has_labels {
                output.push('{');
                output.push_str(&labels_str);
                output.push('}');
            }
            output.push(' ');
            output.push_str(itoa_buffer.format(cumulative + inf_value));
            output.push('\n');
        }
    }

    output.push_str("# EOF\n");

    eprintln!(
        "[PEEPERS2] Distributions export took: {:?}",
        distributions_start.elapsed()
    );
    eprintln!("[PEEPERS2] Total export time: {:?}", start.elapsed());
    eprintln!(
        "[PEEPERS2] Output size: {} bytes ({:.2} MB)",
        output.len(),
        output.len() as f64 / 1024.0 / 1024.0
    );

    Ok(output)
}

// ============================================================================
// Rustler initialization
// ============================================================================

rustler::init!("Elixir.Supavisor.Monitoring.Peepers2");
