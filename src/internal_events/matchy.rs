use metrics::counter;
use vector_lib::internal_event::{InternalEvent, error_stage, error_type};

#[derive(Debug)]
pub struct MatchyEventProcessed {
    pub matched: bool,
    pub match_count: usize,
}

impl InternalEvent for MatchyEventProcessed {
    fn emit(self) {
        if self.matched {
            counter!("matchy_events_matched_total").increment(1);
            counter!("matchy_matches_total").increment(self.match_count as u64);
        }
    }
}

#[derive(Debug)]
pub struct MatchyDatabaseQueried {
    pub database_id: String,
}

impl InternalEvent for MatchyDatabaseQueried {
    fn emit(self) {
        counter!(
            "matchy_database_queries_total",
            "database_id" => self.database_id,
        )
        .increment(1);
    }
}

#[derive(Debug)]
pub struct MatchyExtracted {
    pub extracted_type: String,
    pub count: usize,
}

impl InternalEvent for MatchyExtracted {
    fn emit(self) {
        counter!(
            "matchy_extractions_total",
            "type" => self.extracted_type,
        )
        .increment(self.count as u64);
    }
}

#[derive(Debug)]
pub struct MatchyLookupError {
    pub database_id: String,
    pub error: String,
}

impl InternalEvent for MatchyLookupError {
    fn emit(self) {
        warn!(
            message = "Matchy database lookup error.",
            database_id = %self.database_id,
            error = %self.error,
            error_type = error_type::REQUEST_FAILED,
            stage = error_stage::PROCESSING,
        );
        counter!(
            "component_errors_total",
            "error_type" => error_type::REQUEST_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
    }
}

#[derive(Debug)]
pub struct MatchyExtractorBuildError {
    pub error: String,
}

impl InternalEvent for MatchyExtractorBuildError {
    fn emit(self) {
        error!(
            message = "Failed to build thread-local extractor.",
            error = %self.error,
            error_type = error_type::CONFIGURATION_FAILED,
            stage = error_stage::PROCESSING,
        );
        counter!(
            "component_errors_total",
            "error_type" => error_type::CONFIGURATION_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
    }
}
