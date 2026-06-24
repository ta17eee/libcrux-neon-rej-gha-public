# libcrux NEON rejection sampler GHA smoke

This public repository is a minimal GitHub Actions smoke target for the
libcrux NEON rejection-sampler runner investigation.

It intentionally does not contain libcrux source, tuning code, private notes,
or benchmark data. The only workflow checks whether a standard GitHub-hosted
`macos-14` runner can start for a public repository and records runner
diagnostics needed before heavier reproductions.

Public workflow logs and artifacts are public.
