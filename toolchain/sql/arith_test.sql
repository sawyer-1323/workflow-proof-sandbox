-- pgTAP sample suite for the toolchain check (T4). Synthetic.
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap;
SELECT plan(3);
SELECT is(2 + 3, 5, 'integer addition');
SELECT is(floor(-7::numeric / 2)::int, -4, 'floor division rounds toward negative infinity');
SELECT is(round(2.5::numeric), 3::numeric, 'numeric round() rounds half away from zero');
SELECT * FROM finish();
ROLLBACK;
