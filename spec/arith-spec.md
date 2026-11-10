# Arithmetic specification (synthetic)

This table is the independent oracle for the golden tests. The golden file
`test/golden/expected.json` encodes exactly these rows. The specification,
the golden file and the golden test are protected baselines: a pull request
that changes any of them, or the recorded hashes in
`test/golden/PROTECTED.sha256`, fails the `golden-guard` check.

| # | Operation | a | b | Expected |
|---|---|---|---|---|
| 1 | add | 2 | 3 | 5 |
| 2 | add | -7 | 4 | -3 |
| 3 | subtract | 10 | 15 | -5 |
| 4 | multiply | -6 | 7 | -42 |
| 5 | divideFloor | 7 | 2 | 3 |
| 6 | divideFloor | -7 | 2 | -4 |
| 7 | roundHalfEven | 5 | 2 | 2 |
| 8 | roundHalfEven | 7 | 2 | 4 |
| 9 | roundHalfEven | -5 | 2 | -2 |
| 10 | roundHalfEven | 10 | 4 | 2 |
| 11 | roundHalfEven | 11 | 4 | 3 |
| 12 | roundHalfEven | 1 | 3 | 0 |
