# Shelf Price Checker

Barcode price comparison across grocery store websites, by area.

- `site/` – the website (static; Netlify publishes this folder)
- `supabase/functions/pc-check` – live price checks for one item
- `supabase/functions/pc-catalog` – reads one page of a store's full price list (used by the scheduled "Who's cheaper" comparison)
- `helper/` – optional Chrome helper extension

The database (tables, schedules, matching) lives in the Supabase project. Secrets such as `FIRECRAWL_API_KEY` are set in Supabase, never in this repository.
