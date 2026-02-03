//! Trending model and related types
//!
//! Models for trending repositories functionality.
//! Design Reference: DR-12.1 (Trending Service)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Trending time window
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "trending_window", rename_all = "lowercase")]
pub enum TrendingWindow {
    #[serde(rename = "1h")]
    #[sqlx(rename = "1h")]
    OneHour,
    #[serde(rename = "24h")]
    #[sqlx(rename = "24h")]
    #[default]
    TwentyFourHours,
    #[serde(rename = "7d")]
    #[sqlx(rename = "7d")]
    SevenDays,
    #[serde(rename = "30d")]
    #[sqlx(rename = "30d")]
    ThirtyDays,
}

impl fmt::Display for TrendingWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OneHour => write!(f, "1h"),
            Self::TwentyFourHours => write!(f, "24h"),
            Self::SevenDays => write!(f, "7d"),
            Self::ThirtyDays => write!(f, "30d"),
        }
    }
}

impl FromStr for TrendingWindow {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1h" => Ok(Self::OneHour),
            "24h" => Ok(Self::TwentyFourHours),
            "7d" => Ok(Self::SevenDays),
            "30d" => Ok(Self::ThirtyDays),
            _ => Err(format!(
                "Invalid window: {s}. Valid values are: 1h, 24h, 7d, 30d"
            )),
        }
    }
}

impl TrendingWindow {
    /// Get the duration in hours for this window
    pub fn hours(&self) -> i64 {
        match self {
            Self::OneHour => 1,
            Self::TwentyFourHours => 24,
            Self::SevenDays => 24 * 7,
            Self::ThirtyDays => 24 * 30,
        }
    }
}

/// Query parameters for trending endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct TrendingQuery {
    /// Time window for trending calculation (default: 24h)
    #[serde(default)]
    pub window: Option<String>,
    /// Maximum number of results to return (default: 50)
    #[serde(default)]
    pub limit: Option<i32>,
}

/// Trending repository information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrendingRepo {
    pub repo_id: String,
    pub name: String,
    pub owner_id: String,
    pub owner_name: String,
    pub description: Option<String>,
    pub stars: i32,
    pub stars_delta: i32,
    pub weighted_score: f64,
    pub created_at: DateTime<Utc>,
}

/// Response for trending repositories endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrendingResponse {
    pub window: String,
    pub repos: Vec<TrendingRepo>,
    pub computed_at: Option<DateTime<Utc>>,
}
