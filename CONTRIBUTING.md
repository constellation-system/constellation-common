# Constellation Contribution Guide

Contributions should be made in the form of merge requests on the
primary Git hosting platform against the `devel` branch or an active
feature-development branch.  All commits to the working branch in a
merge request *must* be cryptographically signed by the author using
the PGP signature feature.  Contributions should never be made
directly to these branches.

Contributions *must* be written entirely by a human, or with the
assistance of one of the following types of programs:
* Template or "macro" systems, or preprocessor languages
* Programs that translate a well-defined input language into an
  implementation of an equivalent, well-defined computational model
  (e.g. lex, yacc, BURS generators)
* Programs that translate a datatype definition, schema language, or
  interface definition language (IDL) into well-defined
  implementations of serialization/deserialization routines, remote
  procedure calls, validation procedures, concrete type definitions,
  and similar functionality
* Programs that translate raw data, tables, strings, or complex
  objects described in a structure language into equivalent
  definitions in a programming language
* Tools that generate "template" or "boilerplate" code from a model or
  design diagram
* Tools based on automated deduction, model-checking, and other
  formal methods
* Simple patches generated deterministically by a type-checker,
  linter, or static analyzer
* Automatic formatting or code-style tools
* Internationalization or localization assistance programs
* Programs that translate from one low-level encoding scheme to
  another (e.g. `dos2unix`)
* `diff`, `merge`, `git`, `patch`, `sed`, `awk`, and similar tools

*Contributions written in whole or in part by any sort of generative
AI, LLM, or similar method are forbidden.*

In general, if a tool is used that deterministically translates an
input language into code without interaction with a human, then the
input itself should be added to the codebase, and the tool should be
integrated into the build process.

## Quality Standards

1. Contributions should compile without warnings, and should pass any
   format checkers or linters without warnings.  Warning suppression
   annotations should not be added without explicit permission.
1. All tests must pass reliably for any contribution merged into the
   `devel` branch, without exception.  Tests should not be deleted or
   commented out without adequate justification.
1. Contributions should be documented, and any developer documentation
   generators must run without warnings.  Code present in
   documentation ("doc tests") must compile and run without error.
1. Contributions must be reviewed by a human knowledgable about the
   relevant portions of code prior to merging.

## Restrictions on Contributors

1. No contributions may be made by any individual or organization
   acting on behalf of any government entity *without explicit
   authorization from the project leads*.
1. No contributions may be made by any individual or on behalf of any
   organization engaged in the following activities:
   * Human rights crimes
   * Terrorism, political or extremist violence
   * Trafficking or distribution of illegal drugs, arms, and other
     contraband
   * Human trafficking, slavery, or exploitation
   * Racketeering, extortion, and other organized crime
   * Financial fraud, securities fraud, money laundering, pyramid
     schemes, Ponzi schemes, and other scams or financial crimes
   * Providing material support or financing for any of the activites
     on this list
1. Contributions containing malware, back-doors, or deliberate
   introduction of security vulnerabilities are forbidden.
1. Contributions written in whole or in part by any kind of large
   language model (LLM), generative AI, Markov chain generator, or
   other method based on extracting statistical properties and/or
   patterns from a large corpus of examples ("training") and
   subsequently reproducing them *are expressly forbidden*.
