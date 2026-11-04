# ADR 0001: PDF generation library

## Status
Accepted

## Context
Evidence/complaint-preparation reports must render HTML templates with Hindi (Devanagari) text, tables, and embedded screenshots. Requirements: deterministic output, no browser runtime, easy CI caching, licence permissive.

## Options
- WeasyPrint: HTML/CSS → PDF, good CSS paged-media support, Devanagari shaping via Pango. Heavier native deps (Pango, cairo).
- ReportLab: programmatic layout, lighter, but templates are code (not HTML), Hindi shaping requires extra work.

## Decision
WeasyPrint. HTML templates are easier to maintain/test and localise (en/hi i18n keys), and Devanagari renders correctly with embedded fonts. ReportLab rejected for template ergonomics.

## Consequences
- Docker image must include Pango/cairo/fontconfig + Noto fonts (multi-stage, non-root).
- PDF generation is on-demand (signed URL), not at scan time.
