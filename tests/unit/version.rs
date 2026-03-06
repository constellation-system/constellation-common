use std::convert::TryFrom;

use asn1rs::syn::io::UperWriter;
use asn1rs::syn::Readable;
use asn1rs::syn::Writable;
use constellation_common::codec::DatagramCodec;
use constellation_common::codec::Decoder;
use constellation_common::codec::Encoder;
use constellation_common::config::Create;
use constellation_common::version::Version;
use constellation_common::version::VersionPERCodec;
use constellation_common::version::VersionRange;
use constellation_common::version::VersionRangeElem;
use constellation_common::version::VersionRangeElemMajor;
use constellation_common::version::VersionRangeElemMinor;
use constellation_common::version::VersionRangeElemSub;

#[test]
fn test_version_codec() {
    let version = Version::new(1, 2, 10);
    let mut codec = VersionPERCodec::create(()).unwrap();
    let mut buf = [0; VersionPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&version, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(version, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_version_read_write() {
    let expected = Version::new(1, 2, 3);
    let mut writer = UperWriter::with_capacity(4);

    expected.write(&mut writer).expect("Expected success");

    let mut reader = writer.as_reader();
    let actual = Version::read(&mut reader).expect("Expected success");

    assert_eq!(expected, actual);
}

#[test]
fn test_version_range_elem_major_read_write() {
    let expected = VersionRangeElem::major(1);
    let mut writer = UperWriter::with_capacity(2);

    expected.write(&mut writer).expect("Expected success");

    let mut reader = writer.as_reader();
    let actual = VersionRangeElem::read(&mut reader).expect("Expected success");

    assert_eq!(expected, actual);
}

#[test]
fn test_version_range_elem_minor_read_write() {
    let expected = VersionRangeElem::minor(1, 2);
    let mut writer = UperWriter::with_capacity(3);

    expected.write(&mut writer).expect("Expected success");

    let mut reader = writer.as_reader();
    let actual = VersionRangeElem::read(&mut reader).expect("Expected success");

    assert_eq!(expected, actual);
}

#[test]
fn test_version_range_elem_sub_read_write() {
    let expected = VersionRangeElem::sub(1, 2, 3);
    let mut writer = UperWriter::with_capacity(5);

    expected.write(&mut writer).expect("Expected success");

    let mut reader = writer.as_reader();
    let actual = VersionRangeElem::read(&mut reader).expect("Expected success");

    assert_eq!(expected, actual);
}

#[test]
fn test_version_eq() {
    let tests = [
        ((1, 0, 0), (1, 0, 0), true),
        ((1, 1, 0), (1, 0, 0), false),
        ((1, 0, 0), (1, 1, 0), false),
        ((1, 1, 0), (1, 1, 0), true),
        ((1, 1, 1), (1, 1, 0), false),
        ((1, 1, 0), (1, 1, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_eq_version_range_elem_major() {
    let tests = [
        ((1, 0, 0), 2, false),
        ((2, 0, 0), 2, true),
        ((3, 0, 0), 2, false),
        ((1, 1, 0), 2, false),
        ((2, 1, 0), 2, true),
        ((3, 1, 0), 2, false),
        ((1, 0, 1), 2, false),
        ((2, 0, 1), 2, true),
        ((3, 0, 1), 2, false),
        ((1, 1, 1), 2, false),
        ((2, 1, 1), 2, true),
        ((3, 1, 1), 2, false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemMajor::new(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElem::major(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_major_eq_version() {
    let tests = [
        (2, (1, 0, 0), false),
        (2, (2, 0, 0), true),
        (2, (3, 0, 0), false),
        (2, (1, 1, 0), false),
        (2, (2, 1, 0), true),
        (2, (3, 1, 0), false),
        (2, (1, 0, 1), false),
        (2, (2, 0, 1), true),
        (2, (3, 0, 1), false),
        (2, (1, 1, 1), false),
        (2, (2, 1, 1), true),
        (2, (3, 1, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMajor::new(*lhs);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::major(*lhs);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_eq_version_range_elem_minor() {
    let tests = [
        ((1, 0, 0), (2, 1), false),
        ((2, 0, 0), (2, 1), false),
        ((3, 0, 0), (2, 1), false),
        ((1, 1, 0), (2, 1), false),
        ((2, 1, 0), (2, 1), true),
        ((3, 1, 0), (2, 1), false),
        ((1, 1, 1), (2, 1), false),
        ((2, 1, 1), (2, 1), true),
        ((3, 1, 1), (2, 1), false),
        ((1, 2, 0), (2, 1), false),
        ((2, 2, 0), (2, 1), false),
        ((3, 2, 0), (2, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElem::minor(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_minor_eq_version() {
    let tests = [
        ((2, 1), (1, 0, 0), false),
        ((2, 1), (2, 0, 0), false),
        ((2, 1), (3, 0, 0), false),
        ((2, 1), (1, 1, 0), false),
        ((2, 1), (2, 1, 0), true),
        ((2, 1), (3, 1, 0), false),
        ((2, 1), (1, 1, 1), false),
        ((2, 1), (2, 1, 1), true),
        ((2, 1), (3, 1, 1), false),
        ((2, 1), (1, 2, 0), false),
        ((2, 1), (2, 2, 0), false),
        ((2, 1), (3, 2, 0), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::minor(lhs.0, lhs.1);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_eq_version_range_elem_sub() {
    let tests = [
        ((1, 0, 0), (2, 1, 1), false),
        ((2, 0, 0), (2, 1, 1), false),
        ((3, 0, 0), (2, 1, 1), false),
        ((1, 1, 1), (2, 1, 1), false),
        ((2, 1, 1), (2, 1, 1), true),
        ((3, 1, 1), (2, 1, 1), false),
        ((1, 1, 2), (2, 1, 1), false),
        ((2, 1, 2), (2, 1, 1), false),
        ((3, 1, 2), (2, 1, 1), false),
        ((1, 2, 0), (2, 1, 1), false),
        ((2, 2, 0), (2, 1, 1), false),
        ((3, 2, 0), (2, 1, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemSub::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElem::sub(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_sub_eq_version() {
    let tests = [
        ((2, 1, 1), (1, 0, 0), false),
        ((2, 1, 1), (2, 0, 0), false),
        ((2, 1, 1), (3, 0, 0), false),
        ((2, 1, 1), (1, 1, 1), false),
        ((2, 1, 1), (2, 1, 1), true),
        ((2, 1, 1), (3, 1, 1), false),
        ((2, 1, 1), (1, 1, 2), false),
        ((2, 1, 1), (2, 1, 2), false),
        ((2, 1, 1), (3, 1, 2), false),
        ((2, 1, 1), (1, 2, 0), false),
        ((2, 1, 1), (2, 2, 0), false),
        ((2, 1, 1), (3, 2, 0), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemSub::new(lhs.0, lhs.1, lhs.2);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::sub(lhs.0, lhs.1, lhs.2);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_major_eq() {
    let tests = [(0, 1, false), (1, 0, false), (1, 1, true)];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMajor::new(*lhs);
        let rhs = VersionRangeElemMajor::new(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_major_eq_version_range_elem_minor() {
    let tests = [
        (2, (1, 0), false),
        (2, (2, 0), true),
        (2, (3, 0), false),
        (2, (1, 1), false),
        (2, (2, 1), true),
        (2, (3, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMajor::new(*lhs);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::major(*lhs);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMajor::new(*lhs);
        let rhs = VersionRangeElem::minor(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_minor_eq_version_range_elem_major() {
    let tests = [
        ((1, 0), 2, false),
        ((2, 0), 2, true),
        ((3, 0), 2, false),
        ((1, 1), 2, false),
        ((2, 1), 2, true),
        ((3, 1), 2, false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = VersionRangeElemMajor::new(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = VersionRangeElem::major(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::minor(lhs.0, lhs.1);
        let rhs = VersionRangeElemMajor::new(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_eq_range_elem_minor() {
    let tests = [
        ((1, 0), (1, 0), true),
        ((1, 1), (1, 0), false),
        ((1, 0), (1, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_minor_eq_version_range_elem_sub() {
    let tests = [
        ((2, 1), (1, 0, 0), false),
        ((2, 1), (2, 0, 0), false),
        ((2, 1), (3, 0, 0), false),
        ((2, 1), (1, 1, 0), false),
        ((2, 1), (2, 1, 0), true),
        ((2, 1), (3, 1, 0), false),
        ((2, 1), (1, 1, 1), false),
        ((2, 1), (2, 1, 1), true),
        ((2, 1), (3, 1, 1), false),
        ((2, 1), (1, 2, 0), false),
        ((2, 1), (2, 2, 0), false),
        ((2, 1), (3, 2, 0), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = VersionRangeElemSub::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::minor(lhs.0, lhs.1);
        let rhs = VersionRangeElemSub::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = VersionRangeElem::sub(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_sub_eq_version_range_elem_minor() {
    let tests = [
        ((1, 0, 0), (2, 1), false),
        ((2, 0, 0), (2, 1), false),
        ((3, 0, 0), (2, 1), false),
        ((1, 1, 0), (2, 1), false),
        ((2, 1, 0), (2, 1), true),
        ((3, 1, 0), (2, 1), false),
        ((1, 1, 1), (2, 1), false),
        ((2, 1, 1), (2, 1), true),
        ((3, 1, 1), (2, 1), false),
        ((1, 2, 0), (2, 1), false),
        ((2, 2, 0), (2, 1), false),
        ((3, 2, 0), (2, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemSub::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::sub(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemSub::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElem::minor(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_sub_eq() {
    let tests = [
        ((1, 0, 0), (1, 0, 0), true),
        ((1, 1, 0), (1, 0, 0), false),
        ((1, 0, 0), (1, 1, 0), false),
        ((1, 1, 0), (1, 1, 0), true),
        ((1, 1, 1), (1, 1, 0), false),
        ((1, 1, 0), (1, 1, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemSub::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemSub::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_from_str() {
    let cases = &[
        (
            "1",
            VersionRangeElem::Major(VersionRangeElemMajor { major: 1 })
        ),
        (
            "1.*",
            VersionRangeElem::Major(VersionRangeElemMajor { major: 1 })
        ),
        (
            "1.*.*",
            VersionRangeElem::Major(VersionRangeElemMajor { major: 1 })
        ),
        (
            "1.2",
            VersionRangeElem::Minor(VersionRangeElemMinor {
                major: 1,
                minor: 2
            })
        ),
        (
            "1.2.*",
            VersionRangeElem::Minor(VersionRangeElemMinor {
                major: 1,
                minor: 2
            })
        ),
        (
            "1.2.3",
            VersionRangeElem::Sub(VersionRangeElemSub {
                major: 1,
                minor: 2,
                sub: 3
            })
        )
    ];

    for (str, expected) in cases.iter() {
        let actual =
            VersionRangeElem::try_from(*str).expect("Expected success");

        assert_eq!(expected, &actual);
    }
}

#[test]
fn test_version_range_from_str() {
    let cases =
        &[
            (
                "*",
                VersionRange {
                    lower: None,
                    upper: None
                }
            ),
            (
                "*-*",
                VersionRange {
                    lower: None,
                    upper: None
                }
            ),
            (
                ">=1",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: None
                }
            ),
            (
                ">=1.*",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: None
                }
            ),
            (
                ">=1.*.*",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: None
                }
            ),
            (
                ">=1.2",
                VersionRange {
                    lower: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    )),
                    upper: None
                }
            ),
            (
                ">=1.2.*",
                VersionRange {
                    lower: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    )),
                    upper: None
                }
            ),
            (
                ">=1.2.3",
                VersionRange {
                    lower: Some(VersionRangeElem::Sub(VersionRangeElemSub {
                        major: 1,
                        minor: 2,
                        sub: 3
                    })),
                    upper: None
                }
            ),
            (
                "1-*",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: None
                }
            ),
            (
                "1.*-*",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: None
                }
            ),
            (
                "1.*.*-*",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: None
                }
            ),
            (
                "1.2-*",
                VersionRange {
                    lower: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    )),
                    upper: None
                }
            ),
            (
                "1.2.*-*",
                VersionRange {
                    lower: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    )),
                    upper: None
                }
            ),
            (
                "1.2.3-*",
                VersionRange {
                    lower: Some(VersionRangeElem::Sub(VersionRangeElemSub {
                        major: 1,
                        minor: 2,
                        sub: 3
                    })),
                    upper: None
                }
            ),
            (
                "<=1",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    ))
                }
            ),
            (
                "<=1.*",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    ))
                }
            ),
            (
                "<=1.*.*",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    ))
                }
            ),
            (
                "<=1.2",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    ))
                }
            ),
            (
                "<=1.2.*",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    ))
                }
            ),
            (
                "<=1.2.3",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Sub(VersionRangeElemSub {
                        major: 1,
                        minor: 2,
                        sub: 3
                    }))
                }
            ),
            (
                "*-1",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    ))
                }
            ),
            (
                "*-1.*",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    ))
                }
            ),
            (
                "*-1.*.*",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    ))
                }
            ),
            (
                "*-1.2",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    ))
                }
            ),
            (
                "*-1.2.*",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    ))
                }
            ),
            (
                "*-1.2.3",
                VersionRange {
                    lower: None,
                    upper: Some(VersionRangeElem::Sub(VersionRangeElemSub {
                        major: 1,
                        minor: 2,
                        sub: 3
                    }))
                }
            ),
            (
                "1-2",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 2 }
                    ))
                }
            ),
            (
                "1.*-2",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 2 }
                    ))
                }
            ),
            (
                "1.*.*-2",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 2 }
                    ))
                }
            ),
            (
                "1-2.*",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 2 }
                    ))
                }
            ),
            (
                "1.*-2.*",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 2 }
                    ))
                }
            ),
            (
                "1.*.*-2.*",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 2 }
                    ))
                }
            ),
            (
                "1-2.*.*",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 2 }
                    ))
                }
            ),
            (
                "1.*-2.*.*",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 2 }
                    ))
                }
            ),
            (
                "1.*.*-2.*.*",
                VersionRange {
                    lower: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 1 }
                    )),
                    upper: Some(VersionRangeElem::Major(
                        VersionRangeElemMajor { major: 2 }
                    ))
                }
            ),
            (
                "1.2-2.3",
                VersionRange {
                    lower: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    )),
                    upper: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 2, minor: 3 }
                    ))
                }
            ),
            (
                "1.2.*-2.3",
                VersionRange {
                    lower: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    )),
                    upper: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 2, minor: 3 }
                    ))
                }
            ),
            (
                "1.2-2.3.*",
                VersionRange {
                    lower: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    )),
                    upper: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 2, minor: 3 }
                    ))
                }
            ),
            (
                "1.2.*-2.3.*",
                VersionRange {
                    lower: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 1, minor: 2 }
                    )),
                    upper: Some(VersionRangeElem::Minor(
                        VersionRangeElemMinor { major: 2, minor: 3 }
                    ))
                }
            ),
            (
                "1.2.3-2.3.4",
                VersionRange {
                    lower: Some(VersionRangeElem::Sub(VersionRangeElemSub {
                        major: 1,
                        minor: 2,
                        sub: 3
                    })),
                    upper: Some(VersionRangeElem::Sub(VersionRangeElemSub {
                        major: 2,
                        minor: 3,
                        sub: 4
                    }))
                }
            )
        ];

    for (str, expected) in cases.iter() {
        let actual = VersionRange::try_from(*str).expect("Expected success");

        assert_eq!(expected, &actual);
    }
}
