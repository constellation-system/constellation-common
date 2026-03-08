use std::time::Duration;
use std::time::Instant;

use constellation_common::retry::next_retry;
use constellation_common::retry::next_retry_definite;

#[test]
fn test_next_retry_definite_none() {
    let now = Instant::now();
    let time = next_retry_definite(&None, &now);

    assert_eq!(time, now);
}

#[test]
fn test_next_retry_definite_some_less() {
    let now = Instant::now();
    let next = now + Duration::from_secs(1);
    let time = next_retry_definite(&Some(now), &next);

    assert_eq!(time, now);
}

#[test]
fn test_next_retry_definite_some_greater() {
    let now = Instant::now();
    let next = now + Duration::from_secs(1);
    let time = next_retry_definite(&Some(next), &now);

    assert_eq!(time, now);
}

#[test]
fn test_next_retry_none() {
    let time = next_retry(&None, &None);

    assert_eq!(time, None);
}

#[test]
fn test_next_retry_none_some() {
    let now = Instant::now();
    let time = next_retry(&None, &Some(now));

    assert_eq!(time, Some(now));
}

#[test]
fn test_next_retry_some_none() {
    let now = Instant::now();
    let time = next_retry(&Some(now), &None);

    assert_eq!(time, Some(now));
}

#[test]
fn test_next_retry_some_some_less() {
    let now = Instant::now();
    let next = now + Duration::from_secs(1);
    let time = next_retry(&Some(now), &Some(next));

    assert_eq!(time, Some(now));
}

#[test]
fn test_next_retry_some_some_greater() {
    let now = Instant::now();
    let next = now + Duration::from_secs(1);
    let time = next_retry(&Some(next), &Some(now));

    assert_eq!(time, Some(now));
}
